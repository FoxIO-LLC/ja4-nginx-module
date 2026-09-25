# vi:filetype=perl
# Variable cache tests for ngx_http_ssl_ja4_module.
# Requires Test::Nginx, nginx built with this module, tcp_save_syn support,
# --with-debug and --with-http_v2_module.
# No curlu wrapper needed.
# No root privileges needed.
# No crafted SYN packets needed.
#
# Run with TEST_NGINX_BINARY pointing to nginx and PERL5LIB set as needed:
#   prove -v test/cache-variables.t

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
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
