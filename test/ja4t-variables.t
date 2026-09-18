# vi:filetype=perl
# JA4T goldens via curlu --ja4t (https://github.com/lynch1981/curlu),
# plus IPv6 SYN coverage through an nginx proxy hop.
# The IPv6 case uses the default Test::Nginx IPv4 socket client, then nginx
# connects to ::1. Requires IPv6 loopback; the kernel JA4T is not pinned.
#
# Test::Nginx only execs `curl` when HTTP/2 is on (--- http2). That adds
# --http2-prior-knowledge; curlu accepts it. --ja4t is HTTP-only (no https).
# Use --ja4t=fp (one argv): Test::Nginx passes --- curl_options as a single
# argument, so `--ja4t fp` never matches the curlu wrapper's --ja4t check.
# The curlu `curl` wrapper needs root, ip, and nft.
#
#   git clone https://github.com/lynch1981/curlu.git && (cd curlu && ./build.sh)
#   sudo -E env \
#       PATH="/path/to/curlu:$PATH" \
#       PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}" \
#       TEST_NGINX_BINARY=/path/to/nginx \
#       prove -v test/ja4t-variables.t

use File::Spec;
use Test::More;

BEGIN {
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    my $help = `curl --help 2>&1`;
    plan skip_all => 'curlu not on PATH (curl --help has no --ja4t)'
        unless defined $help && $help =~ /--ja4t/;
    plan skip_all => '--ja4t requires root (sudo -E env PATH=... PERL5LIB=... prove -v test/ja4t-variables.t)'
        unless $> == 0;
}

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: tcp_save_syn off produces an empty JA4T
--- http_config
    tcp_save_syn off;
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4t=$http_ssl_ja4t\n";
    }
--- request
GET /t
--- error_code: 200
--- response_body
ja4t=
--- no_error_log
[error]



=== TEST 2: linux chrome-like SYN
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=64240_2-4-8-1-3_1460_7
--- timeout: 10
--- request
GET /t
--- response_body
64240_2-4-8-1-3_1460_7
--- no_error_log
[error]



=== TEST 3: no TCP options
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_00_00_00
--- timeout: 10
--- request
GET /t
--- response_body
8192_00_00_00
--- no_error_log
[error]



=== TEST 4: single-digit MSS padding
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_2_09_00
--- timeout: 10
--- request
GET /t
--- response_body
8192_2_09_00
--- no_error_log
[error]



=== TEST 5: window scale 0
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=5744_2-4-8-1-3_1436_00
--- timeout: 10
--- request
GET /t
--- response_body
5744_2-4-8-1-3_1436_00
--- no_error_log
[error]



=== TEST 6: IPv6 SYN produces a JA4T fingerprint
# Loopback MTU 65536 yields a large IPv6 MSS (typically 65476); this is
# expected in JA4T.
--- http_config
    tcp_save_syn on;
--- config
    listen [::1]:$TEST_NGINX_SERVER_PORT ipv6only=on;

    location = /t {
        proxy_pass http://[::1]:$TEST_NGINX_SERVER_PORT/fingerprint;
    }

    location = /fingerprint {
        default_type text/plain;
        return 200 "$remote_addr $http_ssl_ja4t\n";
    }
--- request
GET /t
--- error_code: 200
--- response_body_like chomp
^::1 [0-9]+_[0-9]+(?:-[0-9]+)*_[0-9]+_[0-9]+$
--- no_error_log
[error]



=== TEST 7: option order and repeated NOPs
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=65535_2-1-3-1-1-4_1460_8
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
65535_2-1-3-1-1-4_1460_8
--- no_error_log
[error]



=== TEST 8: Mac/iPhone trailing option zeros
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=65535_2-1-3-1-1-8-4-0-0_1460_6
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
65535_2-1-3-1-1-8-4-0-0_1460_6
--- no_error_log
[error]



=== TEST 9: window scale without MSS
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_1-3_00_7
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
8192_1-3_00_7
--- no_error_log
[error]



=== TEST 10: two-digit window scale
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=64240_2-4-8-1-3_1460_14
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
64240_2-4-8-1-3_1460_14
--- no_error_log
[error]



=== TEST 11: kinds after EOL stay in the fingerprint
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_2-0-1-1-1_1460_00
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
8192_2-0-1-1-1_1460_00
--- no_error_log
[error]



=== TEST 12: window scale after EOL is ignored
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_2-0-3_1460_7
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
8192_2-0-3_1460_00
--- no_error_log
[error]



=== TEST 13: MSS after EOL is ignored
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options: --ja4t=8192_3-0-2_1460_7
--- timeout: 10
--- request
GET /t
--- error_code: 200
--- response_body
8192_3-0-2_00_7
--- no_error_log
[error]
