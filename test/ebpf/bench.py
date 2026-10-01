#!/usr/bin/env python3
"""Capture overhead report: tcp_save_synack on vs off. Not a pass/fail test.

Uses soak.py's topology (capture-enabled nginx in a private namespace, backend
nginx behind a veth) and drives it with wrk. Rounds alternate on/off so drift
affects both; the report gives medians. With capture on, it also reads each
BPF program's run count and run time in a separate run, since
kernel.bpf_stats_enabled slows every program run (restored afterwards): the
hooks run on every packet in the namespace, not only on handshakes.

Absolute numbers depend on the machine. On VMs whose clocksource is not TSC
(e.g. hpet), the per-run BPF timing carries clock overhead: compare runs on
the same machine only.

Knobs: BENCH_SECONDS per run (10), BENCH_ROUNDS (3), BENCH_CONNECTIONS (32),
BENCH_THREADS wrk threads (2), BENCH_WORKERS nginx workers (2).
"""
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys

from soak import Front, calibrate, check_build, setup, sysctl
from fixture import command


ROUTES = {"fresh upstream connection": "/new/a", "keepalive upstream": "/ka/a"}
UNITS = {"us": 1e-3, "ms": 1.0, "s": 1e3}


def wrk(path, seconds, connections, threads):
    out = command("wrk", f"-t{threads}", f"-c{connections}", f"-d{seconds}s",
                  "--latency", f"http://127.0.0.1:18080{path}")
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1))
    requests = int(re.search(r"(\d+) requests in", out).group(1))
    latency = {p: float(v) * UNITS[u] for p, v, u in
               re.findall(r"^\s+(50|99)%\s+([\d.]+)(us|ms|s)$", out, re.M)}
    bad = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    errors = re.search(r"Socket errors: (.*)", out)
    if bad or errors:
        raise RuntimeError(f"wrk reported failures for {path}:\n{out}")
    return {"rps": rps, "requests": requests, "p50": latency["50"], "p99": latency["99"]}


def programs(ids=None):
    rows = json.loads(command(os.environ.get("BPFTOOL", "bpftool"), "-j", "prog", "show"))
    return {r["id"]: r for r in rows
            if r.get("name") in ("synack_in", "synack_out") and (ids is None or r["id"] in ids)}


def bpf_cost(before, after, requests):
    """Per-program ns/run and runs/request over one wrk run."""
    cost = {}
    for i, row in after.items():
        runs = row.get("run_cnt", 0) - before[i].get("run_cnt", 0)
        ns = row.get("run_time_ns", 0) - before[i].get("run_time_ns", 0)
        name = row["name"]
        prev = cost.get(name, (0, 0))
        cost[name] = (prev[0] + runs, prev[1] + ns)   # IPv4 + IPv6 links
    return {name: {"ns": ns / runs if runs else 0.0, "per_request": runs / requests}
            for name, (runs, ns) in cost.items()}


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: sudo python3 test/ebpf/bench.py /path/to/nginx")
    if os.geteuid():
        sys.exit("bench.py must run as root")
    binary = os.path.abspath(sys.argv[1])
    check_build(binary)
    subprocess.run(["wrk", "--version"], capture_output=True)  # FileNotFoundError: install wrk
    seconds = int(os.environ.get("BENCH_SECONDS", 10))
    rounds = int(os.environ.get("BENCH_ROUNDS", 3))
    connections = int(os.environ.get("BENCH_CONNECTIONS", 32))
    threads = int(os.environ.get("BENCH_THREADS", 2))
    workers = int(os.environ.get("BENCH_WORKERS", 2))

    stats_path = Path("/proc/sys/kernel/bpf_stats_enabled")
    stats_before = stats_path.read_text().strip()
    backend = setup(binary)
    results = {(route, mode): [] for route in ROUTES for mode in ("on", "off")}
    costs = {route: [] for route in ROUTES}
    try:
        sysctl("kernel.bpf_stats_enabled", 0)
        for r in range(rounds):
            # alternate which mode runs first, so drift does not favour one
            for mode in (("on", "off") if r % 2 == 0 else ("off", "on")):
                front = Front(binary, enabled=(mode == "on"), workers=workers)
                try:
                    if mode == "on":
                        calibrate()     # capture works before measuring it
                    for route, path in ROUTES.items():
                        wrk(path, 2, connections, threads)          # warm up
                        result = wrk(path, seconds, connections, threads)
                        results[(route, mode)].append(result)
                        if mode == "on":
                            # a separate run: bpf_stats itself slows every run
                            sysctl("kernel.bpf_stats_enabled", 1)
                            try:
                                before = programs()
                                timed = wrk(path, max(2, seconds // 2), connections, threads)
                                after = programs(set(before))
                            finally:
                                sysctl("kernel.bpf_stats_enabled", 0)
                            costs[route].append(bpf_cost(before, after, timed["requests"]))
                        print(f"round {r+1} {mode:3} {route:28} {result['rps']:10.0f} req/s "
                              f"p50 {result['p50']:.2f}ms p99 {result['p99']:.2f}ms",
                              file=sys.stderr, flush=True)
                finally:
                    front.close()
    finally:
        sysctl("kernel.bpf_stats_enabled", stats_before)
        backend.close()

    print(f"\ncapture overhead: {rounds} rounds x {seconds}s, wrk -t{threads} "
          f"-c{connections}, {workers} nginx workers, medians\n")
    print(f"{'':28} {'req/s off':>10} {'req/s on':>10} {'change':>8} "
          f"{'p50 off':>8} {'p50 on':>8} {'p99 off':>8} {'p99 on':>8}")
    for route in ROUTES:
        med = {m: {k: statistics.median(x[k] for x in results[(route, m)])
                   for k in ("rps", "p50", "p99")} for m in ("on", "off")}
        change = (med["on"]["rps"] / med["off"]["rps"] - 1) * 100
        print(f"{route:28} {med['off']['rps']:10.0f} {med['on']['rps']:10.0f} {change:+7.1f}% "
              f"{med['off']['p50']:7.2f}ms {med['on']['p50']:6.2f}ms "
              f"{med['off']['p99']:7.2f}ms {med['on']['p99']:6.2f}ms")
    print(f"\n{'BPF cost (capture on)':28} {'program':>10} {'ns/run':>8} {'runs/req':>9} {'ns/req':>8}")
    for route in ROUTES:
        for prog in ("synack_out", "synack_in"):
            ns = statistics.median(c[prog]["ns"] for c in costs[route])
            per = statistics.median(c[prog]["per_request"] for c in costs[route])
            print(f"{route:28} {prog:>10} {ns:8.0f} {per:9.1f} {ns*per:8.0f}")


if __name__ == "__main__":
    main()
