# vi:filetype=perl
# Variable cache tests for ngx_http_ssl_ja4_module.
# Requires Test::Nginx, nginx built with this module, tcp_save_syn support,
# --with-debug, --with-http_v2_module and test/test-nginx/certs/server.{crt,key}.
# The `curl` on PATH must be a real curl with HTTP/2; the curlu wrapper
# rejects the extra URL in TEST 2.
# No root privileges needed.
# No crafted SYN packets needed.
#
# Run with TEST_NGINX_BINARY pointing to nginx and PERL5LIB set as needed:
#   prove -v test/test-nginx/cache-variables.t

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/test-nginx/servroot');
    $ENV{TEST_NGINX_CERT_DIR} ||= File::Spec->rel2abs('test/test-nginx/certs');
}

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
check_accum_error_log();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: JA4T reused on HTTP/1.1 keepalive
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- pipelined_requests eval
["GET /t", "GET /t"]
--- error_code eval
[200, 200]
--- grep_error_log: ja4t cache hit
--- grep_error_log_out
ja4t cache hit



=== TEST 2: JA4T reused on HTTP/2 streams
# Add the same URL to one curl invocation so both HTTP/2 streams share a connection.
--- http_config
    tcp_save_syn on;
--- config
    location /t {
        default_type text/plain;
        return 200 "$http_ssl_ja4t\n";
    }
--- http2
--- curl_options eval
'http://127.0.0.1:' . Test::Nginx::Util::server_port_for_client() . '/t'
--- request
GET /t
--- ignore_response
--- error_log
ja4t cache hit



=== TEST 3: JA4 computed once per HTTP/2 connection
# curl expands {1,2} into two streams of one HTTP/2 connection. Each
# request logs the protocol and JA4 into error.log: the first request
# computes JA4, the second request is a cache hit, and both log the same
# value. The TLS server listens on 127.0.0.1 at the default server's port;
# nginx prefers the more specific address, so curl's https:// URL reaches it.
--- http_config
    log_format ja4vals 'ja4vals $server_protocol $http_ssl_ja4';

    server {
        listen 127.0.0.1:$TEST_NGINX_SERVER_PORT ssl;
        http2 on;
        ssl_certificate     $TEST_NGINX_CERT_DIR/server.crt;
        ssl_certificate_key $TEST_NGINX_CERT_DIR/server.key;
        ssl_session_cache   off;

        location /t {
            access_log logs/error.log ja4vals;
            return 200 "ok\n";
        }
    }
--- config
    # unused, but without --- config Test::Nginx keeps the previous server
--- http2
--- curl_protocol: https
--- curl_options: -k
--- request
GET /t?r={1,2}
--- ignore_response
--- grep_error_log eval
qr/ja4: computing fingerprint|ja4 cache hit|ja4vals \S+ \S+/
--- grep_error_log_out eval
qr/\A
    ja4:\ computing\ fingerprint\n   # request 1 computes JA4
    ja4vals\ HTTP\/2\.0\ (t13i\S+)\n
    ja4\ cache\ hit\n                # request 2 reuses it
    ja4vals\ HTTP\/2\.0\ \1\n        # with the same value
\z/x
--- no_error_log
[error]
