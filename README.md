# JA4+ Nginx Module

An nginx module exposing JA4+ fingerprints as nginx variables for logging and request handling.

The module requires rebuilding nginx with [patches/nginx.patch](patches/nginx.patch), which captures TLS ClientHello information. JA4T additionally requires the [SYN capture patch](patches/nginx-tcp-save-syn.patch). JA4TS uses the independent [SYN-ACK capture patch](patches/nginx-tcp-save-synack.patch) and optional `ebpf` core addon.

## Supported fingerprints

| Fingerprint | Nginx variables | Output |
| --- | --- | --- |
| JA4 | `$http_ssl_ja4`, `$http_ssl_ja4_string` | TLS client fingerprint; `_string` exposes the unhashed components. |
| JA4one | `$http_ssl_ja4one` | TLS client fingerprint variant that excludes dynamic extensions from its extension count and hash. |
| JA4H | `$http_ssl_ja4h`, `$http_ssl_ja4h_string` | HTTP request fingerprint; `_string` exposes header names and cookie data before hashing. |
| JA4TS | `$upstream_ja4ts` | Upstream TCP SYN-ACK fingerprint of the final upstream attempt. Requires [SYN-ACK capture](#ja4ts). |
| JA4T | `$http_ssl_ja4t`, `$http_ssl_ja4t_string` | TCP SYN fingerprint; both variables return the same value. Requires [SYN capture](#ja4t). |

JA4 and JA4one require TLS and are empty on plain HTTP. JA4H works with both HTTP and HTTPS; JA4T and JA4TS are independent of TLS.

## Quick start

The root [Dockerfile](Dockerfile) and [Compose configuration](docker-compose.yaml) provide a development/reference environment. Make sure Docker Compose and OpenSSL are installed, and ports 80 and 443 are available.

From the repository root, generate the local test certificate and key (neither is committed), then start nginx:

```bash
mkdir -p nginx_utils/logs
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout nginx_utils/server.key -out nginx_utils/server.crt \
    -days 30 -subj "/CN=localhost"
docker compose up --build
```

In another terminal, request the fingerprint response:

```bash
curl -k https://localhost/
```

`-k` accepts the self-signed test certificate. The response uses [nginx_utils/nginx.conf](nginx_utils/nginx.conf); JA4T is empty until SYN capture is enabled. Stop the environment with `docker compose down`.

## Building with nginx

Install a C compiler, `make`, `patch`, and the OpenSSL, PCRE and zlib development libraries, then unpack the nginx source. See the [Dockerfile](Dockerfile) for a complete reference build and dependency versions.

Starting from this repository's root, apply the patches to the nginx source tree before configuring:

```bash
ja4_module_dir="$(pwd)"
cd /path/to/nginx-source
patch -p1 < "$ja4_module_dir/patches/nginx.patch"
# Optional: include this patch if you need JA4T.
patch -p1 < "$ja4_module_dir/patches/nginx-tcp-save-syn.patch"
./configure --add-module="$ja4_module_dir" \
    --with-http_ssl_module --with-http_v2_module
make
make install
```

Add your usual nginx configure options, such as `--prefix`, as needed. Without the SYN capture patch, the module still builds, but JA4T returns no value and the `tcp_save_syn` directive is unavailable.

## Configuration

Reference the variables in your nginx configuration, for example to log fingerprints. Define the log format inside `http` and select it in your server:

```nginx
http {
    log_format fingerprints '$remote_addr "$request" '
                            'ja4=$http_ssl_ja4 ja4one=$http_ssl_ja4one '
                            'ja4h=$http_ssl_ja4h ja4t=$http_ssl_ja4t';

    server {
        listen 443 ssl;
        tcp_save_syn on; # Requires the optional SYN capture patch.
        ssl_certificate /path/to/server.crt;
        ssl_certificate_key /path/to/server.key;
        access_log logs/access.log fingerprints;
    }
}
```

### JA4T

JA4T requires the optional SYN capture patch and a Linux kernel with `TCP_SAVE_SYN` support. Enable capture in the relevant `server` block, or at `http` or `stream` scope.

```nginx
tcp_save_syn on;
```

Capture defaults to off because saved SYN packets cost memory. A fingerprint such as `64240_2-4-8-1-3_1460_7` contains the TCP window size, option kinds, MSS and window scale.

`TCP_SAVE_SYN` applies to the listening socket. If server blocks share a listen address, enabling capture in either block saves SYNs for every connection on that socket. Use a dedicated address/port to isolate the cost.

JA4T is empty when nginx is built without `NGX_HAVE_TCP_SAVE_SYN`, capture is off, or no SYN is available (for example with SYN cookies, Unix sockets or QUIC). Behind a TCP proxy, it fingerprints the proxy's connection to nginx.

### JA4TS

JA4TS fingerprints the upstream server's SYN-ACK. It requires Linux 6.4+ with
kernel BTF and Netfilter BPF support, libbpf 1.3+, and an Nginx master running
as root or with `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`. libbpf details
about a failed load are logged at the `notice` level.
Workers inherit the capture descriptors and need no BPF administration privileges.
No conntrack, cgroup setup, interface list or separate collector is needed.

Install `libbpf-dev` (1.3+), `libelf-dev` and `pkg-config` in addition to the
regular build dependencies; no BPF compiler is needed to build nginx. From a source
tree with the JA4 patch applied:

```bash
patch -p1 < "$ja4_module_dir/patches/nginx-tcp-save-synack.patch"
./configure --add-module="$ja4_module_dir" \
    --add-module="$ja4_module_dir/ebpf" \
    --with-http_ssl_module
make
```

The `ebpf/` addon is the Nginx eBPF loader. `ngx_ebpf_module.c` loads and
attaches the BPF object, `ngx_ebpf_synack.c` registers, consumes and releases
each upstream connection's capture, and `ngx_ebpf.h` is shared with the
kernel-side sources in `ebpf/bpf/`. The compiled BPF programs are embedded in
the committed `ebpf/ngx_ebpf.skel.h`, a libbpf skeleton.
The object is CO-RE, so this one skeleton loads on every supported kernel.

After changing `ebpf/bpf/ngx_ebpf.bpf.c` or `ebpf/ngx_ebpf.h`, regenerate and
commit the skeleton with `sh ebpf/gen-skel.sh`. This needs clang with a BPF
backend (`clang-18` is preferred when present), `bpftool` (on Ubuntu also in the
matching `linux-tools` package) and kernel BTF. `BPF_CLANG`, `BPFTOOL` and
`BPF_BTF` override them. The skeleton records a hash
of its inputs; `sh ebpf/gen-skel.sh --check`, which CI runs, rejects a stale one.

The addon must be linked statically.
Builds with it add a module signature bit, so `--with-compat` dynamic modules must
be built against the same configuration. The SYN-ACK patch does not require the
client SYN patch.

```nginx
http {
    tcp_save_synack on;
    log_format upstream_fp '$request ja4ts=$upstream_ja4ts';
    server {
        listen 8080;
        access_log logs/upstream.log upstream_fp;
        location / {
            proxy_pass http://127.0.0.1:9000;
            add_header X-Upstream-JA4TS $upstream_ja4ts;
        }
        location /uncaptured/ {
            tcp_save_synack off;
            proxy_pass http://127.0.0.1:9000;
        }
    }
}
```

`tcp_save_synack` defaults to `off` and inherits through `http`, `server` and
`location`. It is invalid at main scope, inside `upstream`, and in `stream`
(stream proxying is not captured).

`$upstream_ja4ts` returns `window_options_mss_window-scale`, such as
`64240_2-4-8-1-3_1460_7`, for the final upstream attempt. Unlike `$upstream_addr`
or `$upstream_status`, it is not a per-attempt list. It remains available in
access logs after that connection closes. JA4TS has no hashed form, so there is
no `_string` variant. The policy of the location that proxied
the request applies, so the value survives `error_page` and other internal
redirects into locations with capture off. Early evaluation, capture disabled
where the request was proxied, no upstream, refused connections and missing
records produce an empty value. A later successful capture can replace an early
empty result. TLS is optional.

Keepalive reuse retains the socket's original capture policy. Off requests always
see empty values; turning capture on cannot recover a handshake that was never
captured. IPv4, IPv6 and conventional DNAT/SNAT are supported for upstreams on
other hosts or in other network namespaces; an upstream in nginx's own
namespace reached through NAT (e.g. REDIRECT) is not captured. UDP, Unix sockets
and QUIC are excluded. Upstream connections do not use TCP Fast Open (stock nginx
never enables it), so a SYN-ACK that acknowledges SYN data is not matched.
Original bytes are those observed at early PREROUTING, before later hook rewrites.
Retransmission timing and RST suffixes are not included.

Default-off startup creates no BPF resources. Configuration tests and signal-only
commands do not load BPF, so `nginx -t` cannot detect a kernel that will refuse the
programs. Enabled capture that cannot initialize fails startup by design;
individual capture failures leave proxy traffic working. Reloads reuse resources,
but enabling capture from an entirely disabled running instance requires restart.

Known limitations:

- Only IP/TCP headers in the linear part of the socket buffer are read. Drivers
  that leave the TCP header in page fragments at PREROUTING produce no capture
  (the request still succeeds with an empty value). Loopback and veth are linear.
- XDP and TC mangling is out of scope. A SYN-ACK whose bytes are rewritten on
  ingress before netfilter (MSS clamping, option or window rewriting) is
  fingerprinted as rewritten, and asymmetric address rewriting (decapsulation,
  DSR) prevents capture. Symmetric BPF NAT, such as Cilium's BPF masquerading,
  works.
- Unprivileged workers are verified on Linux 6.8. On 6.4, kernels with
  `kernel.unprivileged_bpf_disabled` set may refuse map access from non-root
  workers; this is unverified.
See the [design document](doc/ja4ts_ebpf_design.md) and the
[privileged tests](test/ebpf/README.md).

## Testing

Run both suites from the repository root. The [CI workflows](.github/workflows) show the build and dependency setup.

### Test::Nginx

The Perl suite (`test/*.t`) checks module loading, variable behavior on plain HTTP, JA4H request fingerprints, TLS ClientHello cases and JA4T/JA4TS TCP fingerprints.

Use nginx built with both patches and HTTP/2 support. Install [Test::Nginx](https://github.com/openresty/test-nginx) with `cpanm`, and build [curlu](https://github.com/lynch1981/curlu) with Go 1.24.0 using the curlu version pinned in [CI](.github/workflows/test-nginx.yaml). Its `curl` wrapper must be on `PATH` for the TLS and JA4T cases.

```bash
cpanm --local-lib="$HOME/perl5" Test::Nginx
export PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}"
export TEST_NGINX_BINARY=/path/to/nginx/objs/nginx
export PATH="/path/to/curlu:$PATH"
prove -v test/*.t
```

JA4T tests need Linux, root, `ip` and `nft`; they are skipped without root or curlu. Run them with:

```bash
sudo -E env PATH="$PATH" PERL5LIB="$PERL5LIB" \
    TEST_NGINX_BINARY="$TEST_NGINX_BINARY" prove -v test/ja4t-variables.t
```

JA4TS has a separate privileged suite and collector/lifecycle runners. They run in
their own [eBPF workflow](.github/workflows/test-ebpf.yaml), triggered by changes
to the addon, patches, module sources or these tests; it runs them as root and
rejects skipped JA4TS coverage. Follow the
[capture test instructions](test/ebpf/README.md), including the test-only
instrumented build used to inspect immediate handoff and failure handling.

### pytest integration tests

The Python suite checks TLS fingerprints, ClientHello edge cases and JA4H against golden files in `test/testdata/`, using containerized curl, Go/uTLS and `curl_cffi` clients.

Start the Quick start environment first. With Python 3, Go 1.24+ and Docker host networking available, run these commands in a Python virtual environment:

```bash
python -m pip install pytest 'curl_cffi==0.16.2'
python -m pytest
```

The `curl_cffi` pin matches CI so the client fingerprints remain reproducible. To intentionally update golden files, run `python -m pytest --record` and review the resulting changes.

## Questions

If you have questions, feel free to reach out to us at info@foxio.io.

## License

See [LICENSE](LICENSE) for the FoxIO License 1.1 terms.
