# vi:filetype=perl
# JA4TS of the upstream server: $upstream_ja4ts is the fingerprint of the
# SYN-ACK nginx received from the upstream peer that served the request.
# It is not computed for client connections (nginx as the server).
#
# Capture is enabled by `tcp_save_synack on|off` (http, server,
# location; default off). The setting of the location that proxies the
# request applies; with it off the variable is empty.
#
# This file covers capture policy, fingerprint goldens and variable
# semantics over loopback IPv4. Directive parsing is in the non-root
# ja4ts-config.t. Network paths (IPv6, NAT, later rewrites,
# untracked traffic) are in ja4ts-network.t. Goldens are produced by
# rewriting the upstream's SYN-ACK with nftables; see test/lib/Ja4tsCapture.pm
# for the `--- synack` section format.
#
# JA4TS here is window_options_mss_wscale only. nginx ACKs the first
# SYN-ACK, so the retransmission delays and RST suffix never apply.
#
# Needs root (a private network namespace, nft, and the capture itself):
#
#   sudo -E env \
#       PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}" \
#       TEST_NGINX_BINARY=/path/to/nginx \
#       prove -v test/ja4ts-variables.t

use FindBin;
use lib "$FindBin::Bin/lib";
use Ja4tsCapture;

BEGIN { Ja4tsCapture::enter_namespace() }

use Test::Nginx::Socket 'no_plan';

Ja4tsCapture::install();

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: no upstream produces an empty JA4TS
--- config
    location /t {
        tcp_save_synack on;
        default_type text/plain;
        return 200 "ja4ts=[$upstream_ja4ts]\n";
    }
--- request
GET /t
--- response_body
ja4ts=[]
--- no_error_log
[error]



=== TEST 2: off by default
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: []
--- no_error_log
[error]



=== TEST 3: explicit off
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack off;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: []
--- no_error_log
[error]



=== TEST 4: http context on is inherited
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    tcp_save_synack on;
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 5: server context on is inherited
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    tcp_save_synack on;

    location /t {
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 6: location on does not leak to a sibling location
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /on {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
    location /off {
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request eval
["GET /on", "GET /off", "GET /on"]
--- response_headers eval
["X-JA4TS: [8192_2-4-8-1-3_1460_7]",
 "X-JA4TS: []",
 "X-JA4TS: [8192_2-4-8-1-3_1460_7]"]
--- no_error_log
[error]



=== TEST 7: location off overrides http on
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    tcp_save_synack on;
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /on {
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
    location /off {
        tcp_save_synack off;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request eval
["GET /off", "GET /on"]
--- response_headers eval
["X-JA4TS: []",
 "X-JA4TS: [8192_2-4-8-1-3_1460_7]"]
--- no_error_log
[error]



=== TEST 8: unmodified loopback SYN-ACK
# Window, MSS and window scale depend on the loopback MTU and rmem sysctls.
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers_like
X-JA4TS: ^[0-9]+_2-4-8-1-3_[0-9]+_[0-9]+$
--- no_error_log
[error]



=== TEST 9: linux-like SYN-ACK golden
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 10: single-digit window scale
--- synack
up1: window=65535 mss=1460 wscale=3
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 65535_2-4-8-1-3_1460_3
--- no_error_log
[error]



=== TEST 11: window scale 0 prints as 00, like JA4T
--- synack
up1: window=29200 mss=1460 wscale=0
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 29200_2-4-8-1-3_1460_00
--- no_error_log
[error]



=== TEST 12: single-digit MSS padding
--- synack
up1: window=8192 mss=9 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_09_7
--- no_error_log
[error]



=== TEST 13: timestamps removed leave NOPs in the option list
--- synack
up1: window=8192 mss=1460 wscale=7 reset=timestamp
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 8192_2-4-1-1-1-1-1-1-1-1-1-1-1-3_1460_7
--- no_error_log
[error]



=== TEST 14: SACK permitted removed
--- synack
up1: window=8192 mss=1460 wscale=7 reset=sack-perm
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 8192_2-1-1-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 15: no window scale option
--- synack
up1: window=8192 mss=1460 reset=window
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 8192_2-4-8-1-1-1-1_1460_00
--- no_error_log
[error]



=== TEST 16: no MSS option
--- synack
up1: window=8192 wscale=7 reset=maxseg
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-JA4TS: 8192_1-1-1-1-4-8-1-3_00_7
--- no_error_log
[error]



=== TEST 17: HTTPS upstream uses the TCP SYN-ACK
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT ssl;
        ssl_certificate     $TEST_NGINX_CERT_DIR/server.crt;
        ssl_certificate_key $TEST_NGINX_CERT_DIR/server.key;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass https://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 18: failed upstream TLS handshake keeps the TCP snapshot
# up1 speaks plain HTTP, so it answers nginx's ClientHello with a 400 and the
# TLS handshake fails after the TCP handshake was captured.
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]" always;
        proxy_pass https://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- error_code: 502
--- response_headers
X-JA4TS: [8192_2-4-8-1-3_1460_7]
--- error_log
SSL_do_handshake() failed



=== TEST 19: empty before the upstream connects, set after (not cached)
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        set $early "[$upstream_ja4ts]";
        add_header X-Early $early;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_headers
X-Early: []
X-JA4TS: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 20: available in the log phase
# The access log is written to error.log so --- error_log can match it.
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    log_format ja4ts "ja4ts access: $upstream_ja4ts";
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        access_log logs/error.log ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- error_log
ja4ts access: 8192_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 21: next upstream reports the peer that answered
--- synack
up1: window=8192 mss=1460 wscale=7
up2: window=65535 mss=1400 wscale=3
--- http_config
    upstream backend {
        server 127.0.0.1:$TEST_NGINX_UP1_PORT;
        server 127.0.0.1:$TEST_NGINX_UP2_PORT;
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 503; }
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP2_PORT;
        location / { return 200 "up2\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-Status $upstream_status;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_next_upstream http_503;
        proxy_pass http://backend;
    }
--- request
GET /t
--- response_body
up2
--- response_headers
X-Status: 503, 200
X-JA4TS: 65535_2-4-8-1-3_1400_3
--- no_error_log
[error]



=== TEST 22: refused upstream produces an empty JA4TS
# Nothing listens on up1, so the kernel answers the SYN with RST.
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]" always;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- error_code: 502
--- response_headers
X-JA4TS: []
--- error_log
connect() failed (111: Connection refused)



=== TEST 23: consecutive requests to different upstreams do not mix
--- synack
up1: window=8192 mss=1460 wscale=7
up2: window=65535 mss=1400 wscale=3
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP2_PORT;
        location / { return 200 "up2\n"; }
    }
--- config
    location /a {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
    location /b {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP2_PORT;
    }
--- request eval
["GET /a", "GET /b", "GET /a"]
--- response_body eval
["up1\n", "up2\n", "up1\n"]
--- response_headers eval
["X-JA4TS: 8192_2-4-8-1-3_1460_7",
 "X-JA4TS: 65535_2-4-8-1-3_1400_3",
 "X-JA4TS: 8192_2-4-8-1-3_1460_7"]
--- no_error_log
[error]



=== TEST 24: reused keepalive connection keeps its JA4TS
# The upstream body is $connection_requests, so "2" proves reuse.
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    upstream backend {
        server 127.0.0.1:$TEST_NGINX_UP1_PORT;
        keepalive 4;
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "$connection_requests\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass http://backend;
    }
--- request eval
["GET /t", "GET /t"]
--- response_body eval
["1\n", "2\n"]
--- response_headers eval
["X-JA4TS: 8192_2-4-8-1-3_1460_7",
 "X-JA4TS: 8192_2-4-8-1-3_1460_7"]
--- no_error_log
[error]



=== TEST 25: unix socket upstream produces an empty JA4TS
--- http_config
    server {
        listen unix:$TEST_NGINX_SERVROOT/ja4ts-up.sock;
        location / { return 200 "unix\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://unix:$TEST_NGINX_SERVROOT/ja4ts-up.sock;
    }
--- request
GET /t
--- response_body
unix
--- response_headers
X-JA4TS: []
--- no_error_log
[error]



=== TEST 26: shared keepalive pool enabled then disabled then enabled
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    upstream shared_capture {
        server 127.0.0.1:$TEST_NGINX_UP1_PORT;
        keepalive 4;
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    location /on {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://shared_capture;
    }
    location /off {
        tcp_save_synack off;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://shared_capture;
    }
--- request eval
["GET /on", "GET /off", "GET /on"]
--- response_body eval
["up1\n", "up1\n", "up1\n"]
--- response_headers eval
["X-JA4TS: [8192_2-4-8-1-3_1460_7]", "X-JA4TS: []", "X-JA4TS: [8192_2-4-8-1-3_1460_7]"]
--- grep_error_log
get keepalive peer: using connection
--- grep_error_log_out eval
["", "get keepalive peer: using connection\n", "get keepalive peer: using connection\n"]
--- no_error_log
[error]



=== TEST 27: shared keepalive pool disabled then enabled cannot reconstruct
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    upstream shared_capture {
        server 127.0.0.1:$TEST_NGINX_UP1_PORT;
        keepalive 4;
    }
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    location /on {
        tcp_save_synack on;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://shared_capture;
    }
    location /off {
        tcp_save_synack off;
        add_header X-JA4TS "[$upstream_ja4ts]";
        proxy_pass http://shared_capture;
    }
--- request eval
["GET /off", "GET /on", "GET /off"]
--- response_body eval
["up1\n", "up1\n", "up1\n"]
--- response_headers eval
["X-JA4TS: []", "X-JA4TS: []", "X-JA4TS: []"]
--- grep_error_log
get keepalive peer: using connection
--- grep_error_log_out eval
["", "get keepalive peer: using connection\n", "get keepalive peer: using connection\n"]
--- no_error_log
[error]



=== TEST 28: error_page into a location with capture off keeps the snapshot
# Policy applies where the request is proxied, not where the variable is read.
--- synack
up1: window=8192 mss=1460 wscale=7
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 503; }
    }
--- config
    location /t {
        tcp_save_synack on;
        proxy_intercept_errors on;
        error_page 503 = @fallback;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
    location @fallback {
        tcp_save_synack off;
        default_type text/plain;
        return 200 "ja4ts=[$upstream_ja4ts]\n";
    }
--- request
GET /t
--- response_body
ja4ts=[8192_2-4-8-1-3_1460_7]
--- no_error_log
[error]
