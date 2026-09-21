# JA4+ Nginx Module

An nginx module exposing JA4+ fingerprints as nginx variables for logging and request handling.

The module requires rebuilding nginx with [patches/nginx.patch](patches/nginx.patch), which captures TLS ClientHello information. JA4T additionally requires the [SYN capture patch](patches/nginx-tcp-save-syn.patch).

## Supported fingerprints

| Fingerprint | Nginx variables | Output |
| --- | --- | --- |
| JA4 | `$http_ssl_ja4`, `$http_ssl_ja4_string` | TLS client fingerprint; `_string` exposes the unhashed components. |
| JA4one | `$http_ssl_ja4one` | TLS client fingerprint variant that excludes dynamic extensions from its extension count and hash. |
| JA4H | `$http_ssl_ja4h`, `$http_ssl_ja4h_string` | HTTP request fingerprint; `_string` exposes header names and cookie data before hashing. |
| JA4T | `$http_ssl_ja4t`, `$http_ssl_ja4t_string` | TCP SYN fingerprint; both variables return the same value. Requires [SYN capture](#ja4t). |

JA4 and JA4one require TLS and are empty on plain HTTP. JA4H works with both HTTP and HTTPS; JA4T is independent of TLS.

## Quick start

The root [Dockerfile](Dockerfile) and [Compose configuration](docker-compose.yaml) provide a development/reference environment. Make sure Docker Compose and OpenSSL are installed, and ports 80 and 443 are available.

From the repository root, generate the local test certificate and key (neither is committed), then start nginx:

```bash
mkdir -p nginx_utils/logs
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout nginx_utils/server.key -out nginx_utils/server.crt \
    -days 1 -subj "/CN=localhost"
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
        ssl_certificate /path/to/server.crt;
        ssl_certificate_key /path/to/server.key;
        access_log logs/access.log fingerprints;
    }
}
```

### JA4T

JA4T requires the optional SYN capture patch and a Linux kernel with `TCP_SAVE_SYN` support. Enable capture in the relevant `server` block (or at `http` scope):

```nginx
tcp_save_syn on;
```

Capture defaults to off because saved SYN packets cost memory. A fingerprint such as `64240_2-4-8-1-3_1460_7` contains the TCP window size, option kinds, MSS and window scale.

`TCP_SAVE_SYN` applies to the listening socket. If server blocks share a listen address, enabling capture in either block saves SYNs for every connection on that socket. Use a dedicated address/port to isolate the cost.

JA4T is empty when nginx is built without `NGX_HAVE_TCP_SAVE_SYN`, capture is off, or no SYN is available (for example with SYN cookies, Unix sockets or QUIC). Behind a TCP proxy, it fingerprints the proxy's connection to nginx.

## Testing

Run both suites from the repository root. The [CI workflows](.github/workflows) show the build and dependency setup.

### Test::Nginx

The Perl suite (`test/*.t`) checks module loading, variable behavior on plain HTTP, JA4H request fingerprints, TLS ClientHello cases and JA4T SYN fingerprints.

Use nginx built with both patches and HTTP/2 support. Install [Test::Nginx](https://github.com/openresty/test-nginx) with `cpanm`, and build [curlu](https://github.com/lynch1981/curlu) using the version pinned in [CI](.github/workflows/test-nginx.yaml). Its `curl` wrapper must be on `PATH` for the TLS and JA4T cases.

```bash
cpanm --local-lib="$HOME/perl5" Test::Nginx
export PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}"
export TEST_NGINX_BINARY=/path/to/nginx/objs/nginx
export PATH="/path/to/curlu:$PATH"
mkdir -p test/certs
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout test/certs/server.key -out test/certs/server.crt \
    -days 1 -subj "/CN=localhost"
prove -v test/*.t
```

JA4T tests need Linux, root, `ip` and `nft`; they are skipped without root or curlu. Run them with:

```bash
sudo -E env PATH="$PATH" PERL5LIB="$PERL5LIB" \
    TEST_NGINX_BINARY="$TEST_NGINX_BINARY" prove -v test/ja4t-variables.t
```

### pytest integration tests

The Python suite checks TLS fingerprints, ClientHello edge cases and JA4H against golden files in `test/testdata/`, using containerized curl, Go/uTLS and `curl_cffi` clients.

Start the Quick start environment first. With Python 3, Go 1.24+ and Docker host networking available, run these commands in a Python virtual environment:

```bash
python -m pip install pytest 'curl_cffi==0.16.2'
python -m pytest
```

The `curl_cffi` pin matches CI so the client fingerprints remain reproducible. To intentionally update golden files, run `python -m pytest --record` and review the resulting changes.

## License

See [LICENSE](LICENSE) for the FoxIO License 1.1 terms.
