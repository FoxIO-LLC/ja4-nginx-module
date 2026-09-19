# vi:filetype=perl
# Test::Nginx TLS JA4 cases for ngx_http_ssl_ja4_module.
#
# Client: Test::Nginx HTTP/2 curl path. The `curl` on PATH must be
# curlu's bash curl wrapper (needs --utls-alpn-hex / --utls-alpn-none / --resolve).
# Requires nginx with http_ssl_module + http_v2_module, and
# test/certs/server.{crt,key}. SNI cases
# use --resolve so the URL host is example.test (JA4 'd') while TCP stays on
# 127.0.0.1.
#
# Python coverage (test/test_alpn.py, test/test_integration.py):
#   TESTs 6-7  invalid_cipher_count / scsv_inclusion
#   TEST 8     ech_alps (HelloChrome_133 analogue of chrome136 goldens)
#   TESTs 9-14 test_alpn.py encodings 00/hh/60/28/20/2d
#   TESTs 15-16 SNI d vs IP i (tls13_h2 / no_sni_ip) and TLS 1.2 + h1 (tls12_h11)
# alpine/curl 30-cipher ClientHellos are not reproducible with curlu parrots.
#
# Run:
#   export TEST_NGINX_BINARY=/path/to/nginx
#   export PERL5LIB=$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}
#   prove -v test/tls-ja4-variables.t

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    $ENV{TEST_NGINX_USE_HTTP2} = 1;
}

use Test::Nginx::Socket 'no_plan';

no_root_location();

# Default server stays HTTP on TEST_NGINX_PORT (OpenResty SSL style).
# curlu hits a second SSL server; TEST_NGINX_USE_HTTP2 is only so the client is curl.
$ENV{TEST_NGINX_SSL_PORT} ||= server_port() + 10;
server_port_for_client($ENV{TEST_NGINX_SSL_PORT});

my $crt = File::Spec->rel2abs('test/certs/server.crt');
my $key = File::Spec->rel2abs('test/certs/server.key');
my $ssl_port = $ENV{TEST_NGINX_SSL_PORT};

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
    # Accept the self-signed test certificate in every TLS case.
    my $opts = '-k ' . ($block->curl_options // '');
    my $target_addr = $block->server_addr_for_client;
    if (defined $target_addr && $target_addr ne '127.0.0.1') {
        $opts .= " --resolve $target_addr:$ssl_port:127.0.0.1";
    }
    $block->set_value(curl_options => $opts);
});

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: firefox_55_ja4
# HelloFirefox_55 (uTLS): TLS 1.2, ALPN h2, 15 ciphers. IP omits SNI;
# hello is <256 bytes so no PADDING. Remaining 8 extensions per JA4
# spec (0005,000a,000b,000d,0010,0017,0023,ff01).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloFirefox_55
--- request
GET /t
--- response_body_like chomp
^ja4=t12i1508h2_073e58a039a6_e70312a1ce2c$
--- no_error_log
[error]



=== TEST 2: chrome_120_ja4
# HelloChrome_120: TLS 1.3, client ALPN h2 (JA4 uses the ClientHello ALPN).
# PADDING (0015) is intermittent; pin cipher hash only, not the extension hash.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}h2_8daaf6152771_[0-9a-f]{12}$
--- no_error_log
[error]



=== TEST 3: golang_default_ja4
# HelloGolang is Go 1.24 crypto/tls (curlu pin), ALPN http/1.1 only.
# IP and no session cache: 10 extensions (0005,000a,000b,000d,0010,
# 0012,0017,002b,0033,ff01).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\n";
    }
--- curl_protocol: https
--- request
GET /t
--- response_body_like chomp
^ja4=t13i1310h1_f57a46bbacb6_e7c285222651$
--- no_error_log
[error]



=== TEST 4: chrome_120_ja4_string
# Raw cipher list is stable. Extension list may include PADDING (0015).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4_string=$http_ssl_ja4_string\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120
--- request
GET /t
--- response_body_like chomp
^ja4_string=t13i15[0-9]{2}h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_
--- no_error_log
[error]



=== TEST 5: chrome_120_ja4one
# HelloChrome_120 over IP (i). JA4one drops SNI/ALPN/PSK/PADDING from the
# extension count, so a is stable at t13i1514h2 (unlike TEST 2's JA4 a).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120
--- request
GET /t
--- response_body_like chomp
^ja4one=t13i1514h2_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 6: cipher_append_count
# Appending 0x1234 (unknown cipher) raises the JA4 cipher-count digits by 1
# vs TEST 2 (15 -> 16). GREASE is already excluded by the module.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-cipher-append 0x1234
--- request
GET /t
--- response_body_like chomp
^ja4=t13i16[0-9]{2}h2_f09016901046_[0-9a-f]{12}$
--- no_error_log
[error]



=== TEST 7: scsv_in_ja4_string
# TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) is a real cipher list entry.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4_string=$http_ssl_ja4_string\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-cipher-append 0x00ff
--- request
GET /t
--- response_body_like chomp
^ja4_string=t13i16[0-9]{2}h2_002f,0035,009c,009d,00ff,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_
--- no_error_log
[error]



=== TEST 8: chrome_133_ech_alps
# uTLS analogue of test_integration[ech_alps] (curl_cffi chrome136 golden
# t13d1516h2_8daaf6152771_d8a2da3f94cd / ja4one t13d1514h2_…_1e53c2b25e87).
# HelloChrome_133 is not chrome136; hashes still match. example.test sends SNI
# (d). ja4one uses extensions_no_psk_count (excludes SNI/ALPN/PSK/PADDING),
# so 14 vs ja4's 16. GREASE 0a0a..fafa must not appear as 4-hex tokens
# (000a is supported_groups, not GREASE).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloChrome_133
--- request
GET /t
--- response_body_like chomp
^ja4=t13d15[0-9]{2}h2_8daaf6152771_d8a2da3f94cd
ja4_string=(?![^\n]*(?:,|_)(?:0a0a|1a1a|2a2a|3a3a|4a4a|5a5a|6a6a|7a7a|8a8a|9a9a|aaaa|baba|caca|dada|eaea|fafa)(?:,|_|\n))t13d15[0-9]{2}h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*44cd,.*fe0d.*
ja4one=t13d1514h2_8daaf6152771_1e53c2b25e87$
--- no_error_log
[error]



=== TEST 9: alpn_none
# No ALPN extension -> a-suffix 00 (test_alpn.py no_alpn).
# ja4_string continues after the cipher list (extensions, then ja4one).
# ALPN is ignored for hashing, so ja4one keeps TEST 5's 36142f6fd6ef.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-none
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}00_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}00_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i151400_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 10: alpn_one_char
# First ALPN "h" -> hh (test_alpn.py one_char).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-hex 68
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}hh_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}hh_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i1514hh_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 11: alpn_char_space
# First ALPN "h " -> 60 (test_alpn.py char_space).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-hex 6820
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}60_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}60_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i151460_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 12: alpn_space_char
# First ALPN " h" -> 28 (test_alpn.py space_char).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-hex 2068
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}28_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}28_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i151428_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 13: alpn_space_space
# First ALPN "  " -> 20 (test_alpn.py space_space).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-hex 2020
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}20_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}20_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i151420_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 14: alpn_non_alnum
# First ALPN "--" -> 2d (test_alpn.py non_alnum).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloChrome_120 --utls-alpn-hex 2d2d
--- request
GET /t
--- response_body_like chomp
^ja4=t13i15[0-9]{2}2d_8daaf6152771_[0-9a-f]{12}
ja4_string=t13i15[0-9]{2}2d_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_.*
ja4one=t13i15142d_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 15: chrome_120_sni
# Analogue of test_integration[tls13_h2] vs [no_sni_ip]: same HelloChrome_120
# as TEST 2, but example.test sends SNI (d) and the JA4 extension count rises
# (SNI is counted). ja4one excludes SNI so count/hash stay TEST 5's
# t13d1514h2_…_36142f6fd6ef. alpine/curl 30-cipher goldens are not parroted.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloChrome_120
--- request
GET /t
--- response_body_like chomp
^ja4=t13d15[0-9]{2}h2_8daaf6152771_[0-9a-f]{12}
ja4one=t13d1514h2_8daaf6152771_36142f6fd6ef$
--- no_error_log
[error]



=== TEST 16: tls12_h1_sni
# Analogue of test_integration[tls12_h11] (alpine/curl golden t12d2708h1_…).
# Same HelloFirefox_55 as TEST 1 (t12, 15 ciphers). example.test -> SNI (d).
# --utls-alpn-hex 687474702f312e31 is ASCII "http/1.1" -> a-suffix h1.
# SNI/ALPN are counted not hashed, and this hello stays under 256 bytes
# (no PADDING), so c stays TEST 1's e70312a1ce2c. Count is 09 (TEST 1's 08 + SNI).
# alpine/curl 27-cipher hellos are not parroted.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloFirefox_55 --utls-alpn-hex 687474702f312e31
--- request
GET /t
--- response_body_like chomp
^ja4=t12d1509h1_073e58a039a6_e70312a1ce2c$
--- no_error_log
[error]



