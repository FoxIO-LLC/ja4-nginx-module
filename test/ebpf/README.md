# SYN-ACK capture tests

Four privileged suites cover the `ebpf/` addon, and `bench.py` reports its
overhead. Missing dependencies, load/verifier failures, and assertion failures
are errors; there are no successful skips. Run them sequentially: `nginx.py`
and `soak.py` check system-wide BPF resource IDs for leaks.

Dependencies: root, kernel BTF, libbpf 1.3+, Python 3.9+, iproute2, util-linux
(`nsenter`), nftables and Test::Nginx; `wrk` for `bench.py`. No BPF compiler
is needed: the suites use the object embedded in the committed
`ebpf/ngx_ebpf.skel.h`. `nginx.py` also
needs `bpftool`, to list the maps and links nginx creates; set `BPFTOOL` to the
real executable when the distro wrapper expects a tools package matching the
running kernel. On Ubuntu 24.04, install `libbpf-dev libelf-dev iproute2
nftables linux-tools-generic wrk`.

## Build

Build Nginx with all three patches and both addons. `nginx.py` needs its own
instrumented build: add `--with-cc-opt=-DNGX_SYNACK_TEST=1`. The test define
enables raw-header inspection and fault injection without adding production
variables.
`nginx.py` checks `nginx -V` first and exits with the missing option if the
build doesn't qualify. Use a separate build for deployment; production does
not recognize the `NGX_SYNACK_TEST_*` environment variables.

```sh
sudo -E prove -v --exec python3 test/ebpf/capture.py
sudo -E env JA4TS_REQUIRE_CAPTURE_TESTS=1 \
    TEST_NGINX_BINARY=/path/to/nginx/objs/nginx \
    prove -v test/ja4ts-variables.t test/ja4ts-network.t
sudo -E prove -v --exec python3 test/ebpf/nginx.py :: /path/to/instrumented/nginx
sudo -E prove -v --exec python3 test/ebpf/soak.py :: /path/to/nginx/objs/nginx
sudo -E python3 test/ebpf/bench.py /path/to/nginx/objs/nginx
sh test/ebpf/build-matrix.sh /path/to/nginx-1.31.4.tar.gz /tmp/new-build-matrix
```

Preserve `PERL5LIB` with `sudo -E` if Test::Nginx was installed locally, and
include `/usr/sbin` in PATH. `nginx.py` also needs a `nobody:nogroup` account and permission to drop
privileges. Use a short, world-traversable build and servroot path: unix-socket
paths are limited to 108 bytes, and unprivileged workers must reach the binary.

`capture.py` and `nginx.py` print TAP, so `prove` runs them like the `.t` files
(they also run directly with `python3`). Each case is one `ok`/`not ok` line,
with the traceback as `#` diagnostics. A failed `capture.py` case does not stop
the others. In `nginx.py`, a failed `test_http` phase skips the later phases
that depend on it, but the shutdown check still runs. A wrong environment (not
root, or an nginx build without the addon or the instrumentation) ends in
`Bail out!`.

`fixture.py` is shared by `capture.py` and `nginx.py`, and is not a runner. It
provides private network namespaces, owned nftables tables, a remote backend in
its own namespace, and a libbpf loader. It never creates named namespaces or
pins, and links and maps are released by descriptor closure.

## Coverage

Each case belongs to the lowest layer that can observe it.

- **`capture.py`: the collector, driven directly.** It extracts the object
  embedded in the committed skeleton, exactly what nginx ships, loads it with
  test map capacities (1024 registrations and captures, 2048 expectations)
  and reports 33 TAP points: 32 cases plus the remote namespace setup:
  - crafted packets: payload exclusion, IPv4 options, IPv6 extension limits,
    fragments, jumbograms, ESP, bad TCP offsets, truncated IPv4 and IPv6 TCP
    headers, RST, and non-SYN-ACK flags
    (ACK, SYN, data, FIN, RST) on a registered key, over IPv4 and IPv6
  - SYN-data ACK misses, retransmitted SYNs keeping their key, terminal state,
    colliding ownership, and ACK wraparound
  - eviction from all three LRU maps when overfilled to twice their capacity,
    and a key whose owner is gone taken over by its next owner
  - real TCP to a backend in a separate namespace: IPv4, IPv6, an IPv4-mapped
    socket, untracked traffic, and DNAT/SNAT
  Nginx cannot produce these packets or map states. Run the **same object** on
  each target kernel to check CO-RE relocation. CI runs it on the runner's
  kernel and, in the `kernel-6-4` job, on Ubuntu's mainline 6.4.0 build (the
  oldest kernel with Netfilter BPF links) booted with virtme-ng under KVM.
- **`ja4ts-config.t`: directive parsing, without root.** It runs against the
  SYN-ACK patch both with and without the addon, and covers:
  - invalid values, and the main and `upstream` contexts
  - `$upstream_ja4ts` existing and empty with capture unset or off
  - `tcp_save_synack on` failing without the addon (skipped on ebpf builds)
  - rejection in `stream {}` (skipped without `--with-stream`)
  - `tcp_save_synack on` failing clearly without BPF privileges (runs on ebpf
    builds when not root)
- **`ja4ts-variables.t`: JA4TS behaviour through Nginx.** It has 144 assertions,
  over loopback IPv4, covering:
  - capture policy and inheritance
  - golden fingerprints for option layouts
  - plain and TLS upstreams, including a failed upstream TLS handshake
  - retries, refused connections and unix sockets
  - the log phase and early evaluation
  - keepalive reuse across enabled and disabled locations
  - `error_page` into a disabled location
- **`ja4ts-network.t`: network paths through Nginx.** It has 61 assertions
  covering:
  - IPv6
  - DNAT, SNAT, REDIRECT and their combinations to an upstream in nginx's own
    namespace, including IPv6 and a non-local address: deliberately not
    captured, and the request is unaffected (remote NAT is covered by
    `capture.py`)
  - NATed and direct connections in turn
  - later PREROUTING rewrites and untracked traffic
  Both files share `test/lib/Ja4tsCapture.pm`: the private namespace and the
  `--- synack`, `--- nat`, `--- prerouting` and `--- notrack` sections.
- **`nginx.py`: white-box lifecycle through Nginx.** It covers:
  - default-off and `-t`/`-s` resource behavior
  - no BPF resources leaked by a startup that fails without privileges
  - unprivileged workers
  - atomic handoff before response variables, checked in the maps
  - allocation failure, a full registration map evicting while capture keeps
    working, the eviction and miss counters (`NGX_SYNACK_TEST_EVICT`,
    `NGX_SYNACK_TEST_MISS`), and aborted-connect cleanup
  - worker replacement
  - reload policy and resource reuse
  - final map and link release
  - concurrent capture-enabled instances in one namespace, each at the next
    free hook priority, and a clear failure once all 64 are taken
  - binary upgrade (`USR2`): the new master captures beside the old one
- **`soak.py`: correctness under concurrent load.** Either build. A capture-enabled
  nginx proxies to a second nginx in another namespace; the backend's three
  ports answer with different SYN-ACKs, so a fingerprint handed to the wrong
  connection shows up in the response. Phases: a fresh upstream connection per
  request, keepalive, both mixed, and 3% loss plus 5% duplication (netem) on
  the backend's egress. Each phase checks:
  - every response carries its route's fingerprint
  - `CAPTURED` equals nginx's upstream connects, and the failure counters stay 0
  - map occupancy stays bounded by the client count
  - all three maps drain right after the load, without the sweeper
  Then nothing is logged at warn or above, and shutdown releases every map and
  link. `SOAK_SECONDS` (default 5) and `SOAK_CONCURRENCY` (16) set the load;
  raise them for long soak runs. Needs `tc` with `sch_netem`.
- **`bench.py`: overhead report, not a test.** The same topology driven by
  `wrk`, with capture on and off in alternating rounds. It reports median
  requests/s and p50/p99 latency for fresh and keepalive upstream connections,
  plus each BPF program's ns/run and runs/request from a separate run with
  `kernel.bpf_stats_enabled` (restored afterwards). Compare runs on the same
  machine only; on VMs whose clocksource is not TSC (e.g. hpet), clock reads are
  slow, both inside the programs and in the statistics. `BENCH_SECONDS`,
  `BENCH_ROUNDS`, `BENCH_CONNECTIONS`, `BENCH_THREADS` and `BENCH_WORKERS` set
  the run. Needs `wrk`.
- **`build-matrix.sh`: production builds.** It builds HTTP, HTTP plus stream,
  and capture-disabled trees from fresh sources.

## Boundaries

nginx does not use TCP Fast Open upstream, so a SYN-ACK acknowledging SYN data
does not match.
Earlier XDP/TC/OUTPUT/other-namespace rewrites cannot be recovered. Headers
outside the linear skb head are not read. There is no stream capture, no
retransmission-time/RST suffix. Each capture-enabled nginx in a network
namespace takes its own hook priorities (at most 64 at once) and its own maps;
during a binary upgrade the old and new masters capture side by side, and
nothing is handed over. Privileged CI errors instead of silently skipping
capture coverage.
When changing CO-RE accesses or packet reads, check that `capture.py` passes
unchanged in both CI kernel jobs. To reproduce the 6.4 run locally, follow the
job's steps: `virtme-ng`, the kernel's modules copied into `/lib/modules` (never
extract the package into `/`), and `vng --verbose`.
