# vi:filetype=perl
# Test::Nginx HTTP/3 (QUIC) cases for ngx_http_ssl_ja4_module.
#
# Client: Test::Nginx runs `curl --http3-only -k` for --- http3 blocks, so the
# `curl` on PATH must support HTTP/3 (`curl -V` lists HTTP3). Requires nginx
# with http_ssl_module + http_v3_module and test/test-nginx/certs/server.{crt,key}.
#
# The ClientHello comes from curl's QUIC stack (ngtcp2 + its TLS library), so
# exact hashes change with those versions. These cases pin what does not:
# the QUIC prefix, ALPN h3, quic_transport_parameters (0039), and SNI d
# versus IP i.
#
# Run:
#   export TEST_NGINX_BINARY=/path/to/nginx
#   export PERL5LIB=$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}
#   PATH=/path/to/curl-with-http3/bin:$PATH prove -v test/test-nginx/http3-ja4-variables.t

BEGIN {
    use File::Spec;
    use Test::More;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/test-nginx/servroot');
    plan skip_all => 'curl on PATH has no HTTP/3 support (curl -V lacks HTTP3)'
        unless `curl -V 2>&1` =~ /^Features:.*\bHTTP3\b/m;
}

use Test::Nginx::Socket 'no_plan';

no_root_location();

my $crt = File::Spec->rel2abs('test/test-nginx/certs/server.crt');
my $key = File::Spec->rel2abs('test/test-nginx/certs/server.key');

add_block_preprocessor(sub {
    my $block = shift;
    $block->set_value(http3 => 1);
    $block->set_value(config => "ssl_certificate     $crt;\n"
                                . "ssl_certificate_key $key;\n"
                                . ($block->config // ''));
});

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: http3_request_reports_quic_ja4
# QUIC is JA4 protocol q. curl's QUIC stack offers only TLS 1.3, and ALPN
# h3. An IP target sends no SNI (i).
--- config
    location /t {
        default_type text/plain;
        return 200 "proto=$server_protocol\nh3=$http3\nja4=$http_ssl_ja4\nja4one=$http_ssl_ja4one\n";
    }
--- request
GET /t
--- response_body_like chomp
^proto=HTTP/3\.0
h3=h3
ja4=q13i\d{4}h3_[0-9a-f]{12}_[0-9a-f]{12}
ja4one=q13i\d{4}h3_[0-9a-f]{12}_[0-9a-f]{12}$
--- no_error_log
[error]



=== TEST 2: http3_raw_string_has_quic_transport_parameters
# Every QUIC ClientHello carries quic_transport_parameters (0x0039).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4_string=$http_ssl_ja4_string\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4_string=q13i\d{4}h3_[0-9a-f]{4}(?:,[0-9a-f]{4})*_(?:[0-9a-f]{4},)*0039(?:,[0-9a-f]{4})*_[0-9a-f]{4}(?:,[0-9a-f]{4})*$
--- no_error_log
[error]



=== TEST 3: http3_sni_hostname
# A hostname target sends SNI (d). localhost resolves without --resolve,
# which Test::Nginx cannot pass: it hands curl_options to curl as one
# argument. -4 keeps curl off ::1, where nginx does not listen.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4one=$http_ssl_ja4one\n";
    }
--- server_addr_for_client: localhost
--- curl_options: -4
--- request
GET /t
--- response_body_like chomp
^ja4=q13d\d{4}h3_[0-9a-f]{12}_[0-9a-f]{12}
ja4one=q13d\d{4}h3_[0-9a-f]{12}_[0-9a-f]{12}$
--- no_error_log
[error]
