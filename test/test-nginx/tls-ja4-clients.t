# vi:filetype=perl
# Exact JA4 goldens from real TLS client implementations, as opposed to the
# uTLS parrots in tls-ja4-variables.t.
#
# `--- client` names a directory under test/test-nginx/clients/ whose `curl`
# Test::Nginx runs for that block. Both run in Docker with host networking:
#   alpine-curl  curl 8.14.1 + OpenSSL from a pinned alpine/curl image
#   curl-cffi    curl_cffi 0.16.2 impersonating chrome136 (BoringSSL), in an
#                image built on first use
# The goldens depend on these exact client versions; update them together.
#
# Requires nginx with http_ssl_module + http_v2_module, and
# test/test-nginx/certs/server.{crt,key}. Blocks that send SNI connect to
# localhost (JA4 'd'); the rest connect to 127.0.0.1 (JA4 'i').
#
# Run:
#   export TEST_NGINX_BINARY=/path/to/nginx
#   export PERL5LIB=$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}
#   prove -v test/test-nginx/tls-ja4-clients.t

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/test-nginx/servroot');
    $ENV{TEST_NGINX_USE_HTTP2} = 1;
}

use Test::Nginx::Socket 'no_plan';

no_root_location();

# Default server stays HTTP on TEST_NGINX_PORT; clients hit a second SSL
# server, which gets each block's --- config. TEST_NGINX_USE_HTTP2 is only
# so the client is curl.
$ENV{TEST_NGINX_SSL_PORT} ||= server_port() + 10;
server_port_for_client($ENV{TEST_NGINX_SSL_PORT});

my $crt = File::Spec->rel2abs('test/test-nginx/certs/server.crt');
my $key = File::Spec->rel2abs('test/test-nginx/certs/server.key');
my $clients = File::Spec->rel2abs('test/test-nginx/clients');
my $ssl_port = $ENV{TEST_NGINX_SSL_PORT};
my $path = $ENV{PATH};

# Pull and build the client images now, outside the per-request timeout.
for my $client (qw(alpine-curl curl-cffi)) {
    system("$clients/$client/curl", '--prepare') == 0
        or die "$client: --prepare failed\n";
}

add_block_preprocessor(sub {
    my $block = shift;
    my $loc = $block->config // '';
    $block->set_value(http_config => <<"_EOC_");
    server {
        listen 127.0.0.1:$ssl_port ssl;
        http2 on;
        ssl_certificate     $crt;
        ssl_certificate_key $key;
        ssl_session_cache   off;
        $loc
    }
_EOC_
    $block->set_value(config => "location / { return 200; }\n");
    my $client = $block->client
        or bail_out($block->name . ": missing --- client");
    $ENV{PATH} = "$clients/$client:$path";
});

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: openssl_tls13_h2_sni
--- client: alpine-curl
--- server_addr_for_client: localhost
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- timeout: 10
--- curl_protocol: https
--- curl_options: -k --http2 --tls-max 1.3
--- request
GET /t
--- response_body
ja4=t13d3012h2_1d37bd780c83_882d495ac381
ja4_string=t13d3012h2_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0016,0017,002b,002d,0031,0033,ff01_0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602
ja4one=t13d3010h2_1d37bd780c83_dd318dcc5b7c
--- no_error_log
[error]



=== TEST 2: openssl_tls12_h1_sni
--- client: alpine-curl
--- server_addr_for_client: localhost
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- timeout: 10
--- curl_protocol: https
--- curl_options: -k --http1.1 --tls-max 1.2
--- request
GET /t
--- response_body
ja4=t12d2708h1_a2460661a67a_eed5f1524d5c
ja4_string=t12d2708h1_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0016,0017,ff01_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602
ja4one=t12d2706h1_a2460661a67a_50609fb482d1
--- no_error_log
[error]



=== TEST 3: openssl_ip_no_sni
--- client: alpine-curl
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- timeout: 10
--- curl_protocol: https
--- curl_options: -k
--- request
GET /t
--- response_body
ja4=t13i3011h2_1d37bd780c83_882d495ac381
ja4_string=t13i3011h2_002f,0033,0035,0039,003c,003d,0067,006b,009c,009d,009e,009f,1301,1302,1303,c009,c00a,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa_000a,000b,000d,0016,0017,002b,002d,0031,0033,ff01_0905,0906,0904,0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602
ja4one=t13i3010h2_1d37bd780c83_dd318dcc5b7c
--- no_error_log
[error]



=== TEST 4: chrome136_ech_alps
# chrome136 offers ALPS (44cd) and GREASE ECH (fe0d).
--- client: curl-cffi
--- server_addr_for_client: localhost
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- timeout: 10
--- curl_protocol: https
--- curl_options: -k
--- request
GET /t
--- response_body
ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd
ja4_string=t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
ja4one=t13d1514h2_8daaf6152771_1e53c2b25e87
--- no_error_log
[error]
