# vi:filetype=perl
# JA4TS across network paths: the fingerprint must always be that of the
# server that sent the SYN-ACK, and a path the capture does not support must
# leave it empty without disturbing the request.
#
# Every upstream here is in nginx's own network namespace (loopback). The
# capture keys a SYN-ACK by the SYN's wire tuple, after NAT. A reply from
# another host or namespace arrives in that form; it is covered across
# DNAT/SNAT by test/ebpf/capture.py. A reply that loops back inside this
# namespace is un-NATed on its way out, so the NAT cases below (TESTs 2-10)
# are deliberately not captured: such local backends say little. `--- nat`
# holds raw nft rules for the nat output (DNAT/REDIRECT) or postrouting
# (SNAT) hook, with $TEST_NGINX_* expanded:
#
#   output: ip daddr 127.0.0.1 tcp dport $TEST_NGINX_VIRT_PORT dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
#
# The --- synack rules match the upstream's real port before reverse NAT,
# so the golden is always the fingerprint of the server that answered.
# `--- prerouting` adds a later rewrite that must not change the captured
# bytes, and `--- notrack` bypasses conntrack. See test/lib/Ja4tsCapture.pm.
#
# Needs root; everything, including the routes below, lives in this run's
# private network namespace:
#
#   sudo -E env \
#       PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}" \
#       TEST_NGINX_BINARY=/path/to/nginx \
#       prove -v test/ja4ts-network.t

use FindBin;
use lib "$FindBin::Bin/lib";
use Ja4tsCapture;

BEGIN { Ja4tsCapture::enter_namespace() }

# The non-local DNAT test needs a deterministic source without host routes.
BEGIN {
    Ja4tsCapture::run(qw(ip link add ja4ts_route type dummy));
    Ja4tsCapture::run(qw(ip addr add 192.0.2.1/24 dev ja4ts_route));
    Ja4tsCapture::run(qw(ip link set ja4ts_route up));
}

use Test::Nginx::Socket 'no_plan';

Ja4tsCapture::install();

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: IPv6 upstream
--- synack
up1: window=8192 mss=1440 wscale=7
--- http_config
    server {
        listen [::1]:$TEST_NGINX_UP1_PORT ipv6only=on;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://[::1]:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
X-JA4TS: 8192_2-4-8-1-3_1440_7
--- no_error_log
[error]



=== TEST 2: DNAT to another port: not captured
# nginx connects to VIRT; the SYN-ACK comes from UP1.
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
output: ip daddr 127.0.0.1 tcp dport $TEST_NGINX_VIRT_PORT dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-Upstream $upstream_addr;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_VIRT_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers eval
"X-Upstream: 127.0.0.1:$ENV{TEST_NGINX_VIRT_PORT}
!X-JA4TS"
--- no_error_log
[error]



=== TEST 3: DNAT to another address: not captured
# up1 only listens on 127.0.0.1; nginx connects to 127.0.0.2.
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
output: ip daddr 127.0.0.2 tcp dport $TEST_NGINX_UP1_PORT dnat ip to 127.0.0.1
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.2:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 4: DNAT from a non-local address and port: not captured
# 192.0.2.10 is reached through the fixture's deterministic dummy route.
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
output: ip daddr 192.0.2.10 tcp dport 80 dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_connect_timeout 2s;
        proxy_pass http://192.0.2.10:80;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 5: DNAT onto another configured upstream's port: not captured
# nginx believes it talks to up2, but up1 answers: the fingerprint must be
# that of the server that sent the SYN-ACK.
--- synack
up1: window=8192 mss=1460 wscale=7
up2: window=65535 mss=1400 wscale=3
--- nat
output: ip daddr 127.0.0.1 tcp dport $TEST_NGINX_UP2_PORT dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
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
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP2_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 6: REDIRECT to a local port: not captured
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
output: ip daddr 127.0.0.1 tcp dport $TEST_NGINX_VIRT_PORT redirect to :$TEST_NGINX_UP1_PORT
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_VIRT_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 7: SNAT of nginx's source address and port: not captured
# nginx binds 127.0.0.3; the upstream sees 127.0.0.4:40000-40999 and sends
# the SYN-ACK there.
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
postrouting: ip saddr 127.0.0.3 ip daddr 127.0.0.1 tcp dport $TEST_NGINX_UP1_PORT snat ip to 127.0.0.4:40000-40999
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "$remote_addr\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_bind 127.0.0.3;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP1_PORT;
    }
--- request
GET /t
--- response_body
127.0.0.4
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 8: DNAT and SNAT on the same connection: not captured
--- synack
up1: window=8192 mss=1460 wscale=7
--- nat
output: ip daddr 127.0.0.2 tcp dport $TEST_NGINX_VIRT_PORT dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
postrouting: ip saddr 127.0.0.3 ip daddr 127.0.0.1 tcp dport $TEST_NGINX_UP1_PORT snat ip to 127.0.0.4:40000-40999
--- http_config
    server {
        listen 127.0.0.1:$TEST_NGINX_UP1_PORT;
        location / { return 200 "$remote_addr\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_bind 127.0.0.3;
        proxy_pass http://127.0.0.2:$TEST_NGINX_VIRT_PORT;
    }
--- request
GET /t
--- response_body
127.0.0.4
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 9: IPv6 DNAT to another port: not captured
--- synack
up1: window=8192 mss=1440 wscale=7
--- nat
output: ip6 daddr ::1 tcp dport $TEST_NGINX_VIRT_PORT dnat ip6 to [::1]:$TEST_NGINX_UP1_PORT
--- http_config
    server {
        listen [::1]:$TEST_NGINX_UP1_PORT ipv6only=on;
        location / { return 200 "up1\n"; }
    }
--- config
    location /t {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://[::1]:$TEST_NGINX_VIRT_PORT;
    }
--- request
GET /t
--- response_body
up1
--- response_headers
!X-JA4TS
--- no_error_log
[error]



=== TEST 10: NATed connections stay uncaptured, direct ones are captured
# /nat reaches up1 through DNAT; /direct reaches up2 unchanged.
--- synack
up1: window=8192 mss=1460 wscale=7
up2: window=65535 mss=1400 wscale=3
--- nat
output: ip daddr 127.0.0.1 tcp dport $TEST_NGINX_VIRT_PORT dnat ip to 127.0.0.1:$TEST_NGINX_UP1_PORT
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
    location /nat {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_VIRT_PORT;
    }
    location /direct {
        tcp_save_synack on;
        add_header X-JA4TS $upstream_ja4ts;
        proxy_pass http://127.0.0.1:$TEST_NGINX_UP2_PORT;
    }
--- request eval
["GET /nat", "GET /direct", "GET /nat", "GET /direct"]
--- response_body eval
["up1\n", "up2\n", "up1\n", "up2\n"]
--- response_headers eval
["!X-JA4TS",
 "X-JA4TS: 65535_2-4-8-1-3_1400_3",
 "!X-JA4TS",
 "X-JA4TS: 65535_2-4-8-1-3_1400_3"]
--- no_error_log
[error]



=== TEST 11: later PREROUTING rewrite does not change captured bytes
--- synack
up1: window=8192 mss=1460 wscale=7
--- prerouting
tcp sport $TEST_NGINX_UP1_PORT tcp flags & (syn|ack) == syn|ack tcp window set 4096
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



=== TEST 12: untracked TCP capture does not require conntrack
--- notrack
on
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
