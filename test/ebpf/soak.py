#!/usr/bin/env python3
"""Capture correctness under concurrent load; production or instrumented build.

A capture-enabled nginx runs in a private network namespace and proxies to a
second, capture-free nginx in its own namespace over a veth pair. The backend
listens on three ports whose SYN-ACKs differ (receive buffer, address
family), so a fingerprint handed to the wrong connection is visible in the
response. Each phase drives concurrent clients, then checks:

  - every response carries its route's fingerprint
  - CAPTURED equals nginx's upstream connects; failure counters stay 0
  - map occupancy stays bounded while loaded
  - all three maps drain promptly after the load, without the sweeper
  - (at the end) nginx releases every map and link

Knobs: SOAK_SECONDS per phase (default 5), SOAK_CONCURRENCY clients (16).
"""
from contextlib import contextmanager
import ctypes as C
import http.client
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

from fixture import Tap, command, namespace
from nginx import Maps, resources, wait


STATS = ["EXPECT_FULL", "SECOND_KEY", "COLLISION", "CAPTURE_FULL", "CAPTURED",
         "EXPIRED", "REGISTER_FAILED", "ALLOC_FAILED", "HANDOFF_ERROR",
         "INVALID_RECORD", "EVICTED", "MISSED"]

# route suffix -> backend address; the ports' SYN-ACKs differ
BACKENDS = {"a": "192.0.2.2:23456", "b": "192.0.2.2:23457",
            "c": "[2001:db8:1::2]:23458"}


def upstream_connects():
    """TCP connects made in this namespace, less those it accepted: the load
    clients connect to nginx over loopback here, so what remains is nginx's
    upstream connects. (The backend's PassiveOpens is no reference: under
    impairment it also counts SYNs that reuse TIME_WAIT tuples.)"""
    lines = [l.split() for l in Path("/proc/self/net/snmp").read_text()
             .splitlines() if l.startswith("Tcp:")]
    tcp = dict(zip(lines[0][1:], map(int, lines[1][1:])))
    return tcp["ActiveOpens"] - tcp["PassiveOpens"]


def sysctl(name, value, prefix=()):
    command(*prefix, "sysctl", "-q", "-w", f"{name}={value}")


class Backend:
    """A capture-free nginx in its own network namespace, joined by a veth."""

    def __init__(self, binary):
        self.temp = tempfile.TemporaryDirectory(prefix="synack-soak-backend-")
        root = Path(self.temp.name)
        root.chmod(0o755)
        (root/"logs").mkdir()
        (root/"nginx.conf").write_text(f'''
daemon off;
master_process on;
user nobody nogroup;
worker_processes 2;
worker_rlimit_nofile 65536;
pid {root}/nginx.pid;
error_log {root}/error.log warn;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    keepalive_requests 1000000;
    server {{
        listen 23456 backlog=4096;
        listen 23457 backlog=4096 rcvbuf=8k;
        listen [::]:23458 backlog=4096 ipv6only=on;
        location / {{ return 200 "ok\\n"; }}
    }}
}}
''')
        # unshare(1) execs nginx in a new namespace: the master's pid names it.
        self.proc = subprocess.Popen(["unshare", "-n", binary, "-p", str(root),
                                      "-c", str(root/"nginx.conf")])
        self.prefix = ["nsenter", "-t", str(self.proc.pid), "-n"]
        try:
            # nginx has unshared, bound and written its pid file
            own = os.readlink("/proc/self/ns/net")
            wait(lambda: self.proc.poll() is None
                 and os.readlink(f"/proc/{self.proc.pid}/ns/net") != own
                 and (root/"nginx.pid").exists())
            command("ip", "link", "add", "soak0", "type", "veth", "peer", "name", "soak1")
            command("ip", "link", "set", "soak1", "netns", str(self.proc.pid))
            command("ip", "addr", "add", "192.0.2.1/24", "dev", "soak0")
            command("ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "soak0", "nodad")
            command("ip", "link", "set", "soak0", "up")
            command(*self.prefix, "ip", "link", "set", "lo", "up")
            command(*self.prefix, "ip", "addr", "add", "192.0.2.2/24", "dev", "soak1")
            command(*self.prefix, "ip", "-6", "addr", "add", "2001:db8:1::2/64",
                    "dev", "soak1", "nodad")
            command(*self.prefix, "ip", "link", "set", "soak1", "up")
            sysctl("net.core.somaxconn", 4096, self.prefix)
            sysctl("net.ipv4.tcp_max_syn_backlog", 4096, self.prefix)
            self.log = root/"error.log"
        except BaseException:
            self.close()
            raise

    @contextmanager
    def impaired(self, spec):
        """netem on the backend's egress: SYN-ACKs are lost, duplicated..."""
        command(*self.prefix, "tc", "qdisc", "add", "dev", "soak1", "root", "netem", *spec)
        try:
            yield
        finally:
            command(*self.prefix, "tc", "qdisc", "del", "dev", "soak1", "root")

    def close(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGQUIT)
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.temp.cleanup()


class Front:
    """The nginx under test: capture on (or off), IPv4/IPv6, fresh and
    keepalive upstream connections."""

    def __init__(self, binary, enabled=True, workers=4):
        self.binary = binary
        self.temp = tempfile.TemporaryDirectory(prefix="synack-soak-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        (self.root/"logs").mkdir()
        self.log = self.root/"error.log"
        self.enabled = enabled
        upstreams, locations = "", ""
        for name, address in BACKENDS.items():
            upstreams += f"upstream ka_{name} {{ server {address}; keepalive 32; }}\n"
            locations += f'''
        location /new/{name} {{ proxy_pass http://{address}/; }}
        location /ka/{name} {{ proxy_pass http://ka_{name}/;
            proxy_http_version 1.1; proxy_set_header Connection ""; }}'''
        (self.root/"nginx.conf").write_text(f'''
daemon off;
master_process on;
user nobody nogroup;
worker_processes {workers};
worker_rlimit_nofile 65536;
pid {self.root}/nginx.pid;
error_log {self.log} notice;
events {{ worker_connections 8192; }}
http {{
    access_log off;
    tcp_save_synack {"on" if enabled else "off"};
    keepalive_requests 1000000;
    add_header X-FP "[$upstream_ja4ts]" always;
    {upstreams}
    server {{
        listen 127.0.0.1:18080 backlog=4096;
        location /ready {{ return 200 "ready"; }}
        {locations}
    }}
}}
''')
        self.before_maps, self.before_links = resources(), resources("link")
        self.maps, self.map_ids, self.link_ids = None, set(), set()
        self.proc = subprocess.Popen([binary, "-p", str(self.root), "-c",
                                      str(self.root/"nginx.conf")])
        try:
            wait(self.ready)
            rows = {i: r for i, r in resources().items() if i not in self.before_maps}
            self.map_ids = set(rows)
            self.link_ids = set(resources("link")) - set(self.before_links)
            if enabled:
                self.maps = Maps(rows)
                assert len(self.link_ids) == 4, self.link_ids
            else:
                assert not rows and not self.link_ids
        except BaseException:
            self.close()
            raise

    def ready(self):
        if self.proc.poll() is not None:
            raise AssertionError(self.log.read_text() if self.log.exists() else "exited")
        try:
            return fetch("/ready")[0] == 200
        except OSError:
            return False

    def counters(self):
        return {name: self.maps.get("stats", i, C.c_uint64).value
                for i, name in enumerate(STATS)}

    def count(self, name, limit=1 << 20):
        """Entries in a map, walked with get_next_key (bounded)."""
        size = self.maps.rows[name]["bytes_key"]
        prev, key, n = None, (C.c_ubyte * size)(), 0
        while n < limit and self.maps.lib.bpf_map_get_next_key(
                self.maps.fds[name], prev, C.byref(key)) == 0:
            n += 1
            prev = C.byref((C.c_ubyte * size).from_buffer_copy(key))
        return n

    def occupancy(self):
        return {name: self.count(name) for name in ("conn", "expect", "capture")}

    def close(self):
        """Graceful stop; then every map and link nginx created is released."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGQUIT)
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                raise AssertionError("nginx did not shut down gracefully")
        if self.maps:
            self.maps.close()
            self.maps = None
        try:
            wait(lambda: not self.map_ids.intersection(resources()))
            wait(lambda: not self.link_ids.intersection(resources("link")))
        finally:
            self.temp.cleanup()


def fetch(path, conn=None):
    own = conn is None
    if own:
        conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=30)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        response.read()
        return response.status, response.getheader("X-FP")
    finally:
        if own:
            conn.close()


def client(args):
    """One load process: keepalive to the front, cycling its routes."""
    index, routes, expected, deadline = args
    done, errors, wrong = 0, [], []
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=30)
    i = index
    while time.monotonic() < deadline:
        route = routes[i % len(routes)]
        i += 1
        try:
            status, fp = fetch(route, conn)
        except (OSError, http.client.HTTPException) as e:
            errors.append(f"{route}: {e!r}")
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=30)
            continue
        done += 1
        if status != 200:
            errors.append(f"{route}: status {status}")
        elif fp != expected[route[-1]]:
            wrong.append(f"{route}: {fp} != {expected[route[-1]]}")
    conn.close()
    return done, errors[:5], len(errors), wrong[:5], len(wrong)


def calibrate():
    """Each backend's fingerprint, from single fresh connections."""
    expected = {}
    for name in BACKENDS:
        seen = {fetch(f"/new/{name}")[1] for _ in range(3)}
        assert len(seen) == 1 and seen != {"[]"}, (name, seen)
        expected[name] = seen.pop()
    assert len(set(expected.values())) == len(expected), \
        f"backend SYN-ACKs must differ to detect misattribution: {expected}"
    return expected


def load(front, routes, expected, seconds, concurrency):
    """Run the clients and sample map occupancy; return totals and peaks."""
    deadline = time.monotonic() + seconds
    peak, stop = {"conn": 0, "expect": 0, "capture": 0}, threading.Event()

    def sample():
        while not stop.is_set():
            for name, n in front.occupancy().items():
                peak[name] = max(peak[name], n)
            stop.wait(0.1)

    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(concurrency) as pool:
        pending = pool.map_async(client, [(i, routes, expected, deadline)
                                          for i in range(concurrency)])
        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        try:
            results = pending.get(timeout=seconds + 120)
        finally:
            stop.set()
            sampler.join()
    total = sum(r[0] for r in results)
    errors = [e for r in results for e in r[1]]
    n_errors = sum(r[2] for r in results)
    wrong = [w for r in results for w in r[3]]
    n_wrong = sum(r[4] for r in results)
    return total, errors, n_errors, wrong, n_wrong, peak


def phase(tap, front, backend, name, routes, expected, seconds, concurrency,
          impairment=None):
    with tap.case(name):
        before, opens = front.counters(), upstream_connects()
        start = time.monotonic()
        if impairment:
            with backend.impaired(impairment):
                total, errors, n_errors, wrong, n_wrong, peak = load(
                    front, routes, expected, seconds, concurrency)
        else:
            total, errors, n_errors, wrong, n_wrong, peak = load(
                front, routes, expected, seconds, concurrency)
        elapsed = time.monotonic() - start
        # Drain: handoff and BPF remove everything; the sweeper is not needed.
        drained = time.monotonic()
        wait(lambda: not any(front.occupancy().values()), timeout=5)
        drained = time.monotonic() - drained
        after, opens = front.counters(), upstream_connects() - opens
        delta = {k: after[k] - before[k] for k in STATS}
        tap.note(f"{total} requests in {elapsed:.1f}s ({total/elapsed:.0f}/s), "
                 f"{opens} upstream connections, {delta['CAPTURED']} captured; "
                 f"peak conn={peak['conn']} expect={peak['expect']} "
                 f"capture={peak['capture']}; drained in {drained:.2f}s")
        assert total > 0, "no requests completed"
        assert n_errors == 0, (n_errors, errors)
        assert n_wrong == 0, (n_wrong, wrong)
        assert delta["CAPTURED"] == opens, (delta["CAPTURED"], opens)
        failed = {k: v for k, v in delta.items() if k != "CAPTURED" and v}
        assert not failed, failed
        # Registrations live only through handshake + handoff, per client.
        bound = 2 * concurrency
        assert peak["conn"] <= bound and peak["capture"] <= bound, (peak, bound)
        assert peak["expect"] <= 2 * bound, (peak, bound)


def check_build(binary):
    out = subprocess.run([binary, "-V"], capture_output=True, text=True).stderr
    if "/ebpf" not in out:
        Tap.bail(f"{binary} lacks the ebpf addon (--add-module=.../ebpf)")


def setup(binary):
    """Private namespace and backend; shared with bench.py."""
    namespace()
    sysctl("net.ipv4.ip_local_port_range", "10000 65000")
    sysctl("net.ipv4.tcp_tw_reuse", 1)
    sysctl("net.core.somaxconn", 4096)
    return Backend(binary)


def main():
    if len(sys.argv) != 2:
        Tap.bail("usage: sudo python3 test/ebpf/soak.py /path/to/nginx")
    if os.geteuid():
        Tap.bail("soak.py must run as root")
    binary = os.path.abspath(sys.argv[1])
    check_build(binary)
    seconds = float(os.environ.get("SOAK_SECONDS", 5))
    concurrency = int(os.environ.get("SOAK_CONCURRENCY", 16))
    tap = Tap()
    try:
        backend = setup(binary)
    except Exception as e:
        Tap.bail(f"cannot set up the namespaces and backend: {e}")
    front = None
    try:
        with tap.case("topology up; per-backend fingerprints distinct", stop=True):
            front = Front(binary)
            expected = calibrate()
            tap.note(f"fingerprints: {expected}")
        fresh = [f"/new/{n}" for n in BACKENDS]
        reused = [f"/ka/{n}" for n in BACKENDS]
        phase(tap, front, backend, "fresh upstream connection per request",
              fresh, expected, seconds, concurrency)
        phase(tap, front, backend, "keepalive upstream connections",
              reused, expected, seconds, concurrency)
        phase(tap, front, backend, "fresh and keepalive mixed",
              fresh + reused, expected, seconds, concurrency)
        phase(tap, front, backend, "SYN-ACK loss and duplication (netem)",
              fresh, expected, seconds, concurrency,
              impairment=["loss", "3%", "duplicate", "5%"])
        with tap.case("no warnings or alerts in the error log"):
            text = front.log.read_text()
            bad = [l for l in text.splitlines()
                   if any(f"[{lvl}]" in l for lvl in ("warn", "error", "crit", "alert", "emerg"))]
            assert not bad, bad[:5]
    except Exception:
        pass    # a failed setup case was already reported
    finally:
        if front:
            with tap.case("shutdown releases every map and link"):
                front.close()
        backend.close()
    sys.exit(tap.done())


if __name__ == "__main__":
    main()
