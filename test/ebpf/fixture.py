#!/usr/bin/env python3
"""Shared privileged fixture for capture.py and nginx.py; not a test runner.

Private network namespaces, nftables tables, a remote backend namespace, a
libbpf loader for Netfilter BPF objects, and TAP output. All links/maps die
with the process. No bpffs pins, conntrack queries, cgroup enrollment, or host
network changes.
"""
import codecs
import ctypes as C
from contextlib import contextmanager
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import traceback


class Stop(Exception):
    """Raised after a failed case whose later cases cannot run meaningfully."""


class Tap:
    """Test Anything Protocol output, so `prove` can run the scripts:

        ok 1 - name
        not ok 2 - name
        # traceback lines
        1..2
    """

    def __init__(self):
        self.count = 0
        self.failed = 0

    def _point(self, ok, name):
        self.count += 1
        print(f"{'ok' if ok else 'not ok'} {self.count} - {name}", flush=True)

    @contextmanager
    def case(self, name, stop=False):
        """One test point. A failure is reported with its traceback; with
        stop=True it then raises Stop so the caller abandons dependent cases."""
        try:
            yield
        except Stop:
            raise
        except Exception as e:
            self.failed += 1
            self._point(False, name)
            for line in traceback.format_exc().rstrip().splitlines():
                print("# " + line, flush=True)
            if stop:
                raise Stop(name) from e
        else:
            self._point(True, name)

    def note(self, text):
        print("# " + text, flush=True)

    def done(self):
        """Print the plan and return the process exit status."""
        print(f"1..{self.count}", flush=True)
        return 1 if self.failed else 0

    @staticmethod
    def bail(reason):
        """The environment cannot run the suite: stop the whole harness."""
        print(f"Bail out! {reason}", flush=True)
        sys.exit(255)


SKELETON = Path(__file__).resolve().parents[2] / "ebpf" / "ngx_ebpf.skel.h"


def skeleton_object(skeleton=SKELETON):
    """Write the BPF object embedded in the committed skeleton to a temporary
    file and return its path, so tests load exactly what nginx embeds."""
    text = Path(skeleton).read_text()
    m = re.search(r'ngx_ebpf__elf_bytes\(size_t \*sz\)\s*\{\s*'
                  r'static const char data\[\][^=]*=\s*"(.*?)";', text, re.S)
    if not m:
        raise RuntimeError(f"no embedded object in {skeleton}")
    data = codecs.escape_decode(m.group(1).replace("\\\n", ""))[0]
    if data[:4] != b"\x7fELF":
        raise RuntimeError(f"embedded object in {skeleton} is not ELF")
    f = tempfile.NamedTemporaryFile(prefix="ngx_ebpf-", suffix=".bpf.o", delete=False)
    with f:
        f.write(data)
    return f.name


class Tuple(C.Structure):
    _fields_ = [("family", C.c_uint16), ("protocol", C.c_uint8),
                ("pad", C.c_uint8), ("src", C.c_ubyte * 16),
                ("dst", C.c_ubyte * 16), ("sport", C.c_uint16),
                ("dport", C.c_uint16), ("ack", C.c_uint32)]


class Attach(C.Structure):
    _fields_ = [("sz", C.c_size_t), ("pf", C.c_uint32),
                ("hooknum", C.c_uint32), ("priority", C.c_int32),
                ("flags", C.c_uint32)]


def command(*args, input=None):
    return subprocess.run(args, input=input, text=True, check=True,
                          stdout=subprocess.PIPE).stdout


def namespace():
    libc = C.CDLL(None, use_errno=True)
    if libc.unshare(0x40000000):  # CLONE_NEWNET
        raise OSError(C.get_errno(), "unshare(CLONE_NEWNET)")
    command("ip", "link", "set", "lo", "up")


@contextmanager
def rules(body):
    table = f"ja4ts_proof_{os.getpid()}"
    command("nft", "-f", "-", input=f"table inet {table} {{\n{body}\n}}\n")
    try:
        yield
    finally:
        command("nft", "delete", "table", "inet", table)


def backend():
    namespace()
    listeners = []
    for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        s = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((address, 23456))
        s.listen(16)
        listeners.append(s)
    print("ready", flush=True)
    while True:
        ready, _, _ = select.select(listeners, [], [])
        for listener in ready:
            conn, _ = listener.accept()
            conn.close()


@contextmanager
def remote_backend():
    # The child creates its own anonymous namespace. No named namespace or
    # mount is created in the host; veth names exist only in private namespaces.
    child = subprocess.Popen([sys.executable, __file__, "--backend"],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready", "backend startup failed"
        command("ip", "link", "add", "proof0", "type", "veth", "peer", "name", "proof1")
        command("ip", "link", "set", "proof1", "netns", str(child.pid))
        command("ip", "addr", "add", "192.0.2.1/24", "dev", "proof0")
        command("ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "proof0", "nodad")
        command("ip", "link", "set", "proof0", "up")
        prefix = ["nsenter", "-t", str(child.pid), "-n"]
        command(*prefix, "ip", "addr", "add", "192.0.2.2/24", "dev", "proof1")
        command(*prefix, "ip", "-6", "addr", "add", "2001:db8:1::2/64", "dev", "proof1", "nodad")
        command(*prefix, "ip", "link", "set", "proof1", "up")
        command("ip", "route", "add", "198.51.100.0/24", "via", "192.0.2.2")
        command("ip", "-6", "route", "add", "2001:db8:2::/64", "via", "2001:db8:1::2")
        yield
    finally:
        child.terminate()
        child.wait(timeout=5)
        child.stdout.close()


class Loader:
    """Open, load and attach an object: programs = (PREROUTING, POSTROUTING)."""

    def __init__(self, path, *, programs, map_name, capacities=None):
        self.lib = C.CDLL("libbpf.so.1", use_errno=True)
        signatures = {
            "bpf_object__open_file": (C.c_void_p, [C.c_char_p, C.c_void_p]),
            "libbpf_get_error": (C.c_long, [C.c_void_p]),
            "bpf_object__load": (C.c_int, [C.c_void_p]),
            "bpf_object__close": (None, [C.c_void_p]),
            "bpf_object__find_program_by_name": (C.c_void_p, [C.c_void_p, C.c_char_p]),
            "bpf_program__attach_netfilter": (C.c_void_p, [C.c_void_p, C.POINTER(Attach)]),
            "bpf_link__destroy": (C.c_int, [C.c_void_p]),
            "bpf_object__find_map_fd_by_name": (C.c_int, [C.c_void_p, C.c_char_p]),
            "bpf_object__find_map_by_name": (C.c_void_p, [C.c_void_p, C.c_char_p]),
            "bpf_map__set_max_entries": (C.c_int, [C.c_void_p, C.c_uint32]),
            "bpf_map_update_elem": (C.c_int, [C.c_int, C.c_void_p, C.c_void_p, C.c_uint64]),
            "bpf_map_lookup_elem": (C.c_int, [C.c_int, C.c_void_p, C.c_void_p]),
            "bpf_map_lookup_and_delete_elem": (C.c_int, [C.c_int, C.c_void_p, C.c_void_p]),
            "bpf_map_delete_elem": (C.c_int, [C.c_int, C.c_void_p]),
            "bpf_map_get_next_key": (C.c_int, [C.c_int, C.c_void_p, C.c_void_p]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.lib, name)
            fn.restype, fn.argtypes = result, args
        self.links = []
        self.obj = self.lib.bpf_object__open_file(os.fsencode(path), None)
        if not self.obj or self.lib.libbpf_get_error(self.obj):
            raise RuntimeError("BPF object open failed")
        try:
            for name, size in (capacities or {}).items():
                bpf_map = self.lib.bpf_object__find_map_by_name(self.obj, name)
                if not bpf_map or self.lib.bpf_map__set_max_entries(bpf_map, size):
                    raise RuntimeError(f"Cannot set test capacity for {name!r}")
            if self.lib.bpf_object__load(self.obj):
                raise RuntimeError("BPF load/verifier failed")
            # Attach all incoming hooks before any outgoing hook.
            for name, hook, priority in [(programs[0], 0, -2147483647),
                                         (programs[1], 4, 2147483646)]:
                prog = self.lib.bpf_object__find_program_by_name(self.obj, name)
                if not prog:
                    raise RuntimeError(f"Missing BPF program {name!r}")
                for family in (2, 10):
                    opts = Attach(C.sizeof(Attach), family, hook, priority, 0)
                    link = self.lib.bpf_program__attach_netfilter(prog, C.byref(opts))
                    if not link or self.lib.libbpf_get_error(link):
                        raise RuntimeError(f"Netfilter attachment failed: {name!r}/{family}")
                    self.links.append(link)
            self.fd = self.lib.bpf_object__find_map_fd_by_name(self.obj, map_name)
            if self.fd < 0:
                raise RuntimeError("registration map missing")
        except BaseException:
            self.close()
            raise

    def close(self):
        for link in reversed(self.links):
            self.lib.bpf_link__destroy(link)
        self.links.clear()
        if self.obj:
            self.lib.bpf_object__close(self.obj)
            self.obj = None


if __name__ == "__main__" and sys.argv[1:] == ["--backend"]:
    backend()  # re-executed by remote_backend() inside its own namespace
