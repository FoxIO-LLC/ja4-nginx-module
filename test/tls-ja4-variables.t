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
# Relocation regressions:
#   TESTs 17-19 GREASE lookalikes, all 16 GREASE cipher IDs, and duplicates
#   TESTs 20-21 exact extension/signature lists, ALPN counts, variable-read order
#   TESTs 22-23 offered ALPN/TLS values versus negotiated values
# These use existing curlu flags; arbitrary extension IDs are not injectable.
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



=== TEST 17: non_grease_cipher_with_matching_low_nibbles
# 0x1a2a is not GREASE: the bytes differ despite matching low nibbles.
# Keep it in the count and hash. Chrome_133 has no PADDING extension,
# so the complete fingerprint is stable despite shuffled wire extensions.
# Cipher hash = SHA256(sorted comma-separated list below)[:12].
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloChrome_133 --utls-cipher-append 0x1a2a
--- request
GET /t
--- response_body
ja4=t13d1616h2_38af97adec30_d8a2da3f94cd
ja4_string=t13d1616h2_002f,0035,009c,009d,1301,1302,1303,1a2a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
ja4one=t13d1614h2_38af97adec30_1e53c2b25e87
--- no_error_log
[error]



=== TEST 18: all_grease_cipher_ids_are_excluded
# Append every actual GREASE cipher after curlu has built its preset.
# Counts, hashes, and raw lists must stay identical to unmodified Chrome_133.
# The exact extension list also excludes the preset's GREASE extensions.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options eval
CORE::join ' ', '--utls-hello HelloChrome_133',
    map { sprintf '--utls-cipher-append 0x%04x', 0x0a0a + $_ * 0x1010 } 0..15
--- request
GET /t
--- response_body
ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd
ja4_string=t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
ja4one=t13d1514h2_8daaf6152771_1e53c2b25e87
--- no_error_log
[error]



=== TEST 19: grease_lookalikes_and_duplicate_cipher_are_preserved
# 0x0afa and 0xfa0a also have GREASE-shaped low nibbles with unequal bytes.
# The appended 0x1301 is a duplicate, counted and hashed twice. Appended
# order differs from numeric order, so the raw output must be sorted.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloChrome_133 --utls-cipher-append 0xfa0a --utls-cipher-append 0x0afa --utls-cipher-append 0x1301
--- request
GET /t
--- response_body
ja4=t13d1816h2_41fd13d58192_d8a2da3f94cd
ja4_string=t13d1816h2_002f,0035,009c,009d,0afa,1301,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9,fa0a_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
ja4one=t13d1814h2_41fd13d58192_1e53c2b25e87
--- no_error_log
[error]



=== TEST 20: no_alpn_preserves_extension_hash_and_signature_order
# Firefox_55 is small enough to avoid PADDING. Removing ALPN lowers the
# extension count from 08 to 07 while leaving the extension hash unchanged.
# Signature schemes stay in offered order, not numeric order.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloFirefox_55 --utls-alpn-none
--- request
GET /t
--- response_body
ja4=t12i150700_073e58a039a6_e70312a1ce2c
ja4_string=t12i150700_000a,002f,0033,0035,0039,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201
ja4one=t12i150700_073e58a039a6_8ebfdaddfa31
--- no_error_log
[error]



=== TEST 21: raw_and_ja4one_can_be_read_before_ja4
# Read the raw and JA4one variables first, then repeat them after JA4.
# SNI/ALPN raise the extension count to 09 but stay out of both hashes.
# Separate set evaluations invoke the non-cacheable variable handlers again.
# This checks handler reevaluation and read order; formatted fingerprints
# remain cached in the module's request context.
--- config
    location /t {
        default_type text/plain;
        set $raw_first $http_ssl_ja4_string;
        set $one_first $http_ssl_ja4one;
        set $ja4_value $http_ssl_ja4;
        set $raw_again $http_ssl_ja4_string;
        set $one_again $http_ssl_ja4one;
        return 200 "raw_first=$raw_first\none_first=$one_first\nja4=$ja4_value\nraw_again=$raw_again\none_again=$one_again\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloFirefox_55
--- request
GET /t
--- response_body
raw_first=t12d1509h2_000a,002f,0033,0035,0039,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201
one_first=t12d1507h2_073e58a039a6_8ebfdaddfa31
ja4=t12d1509h2_073e58a039a6_e70312a1ce2c
raw_again=t12d1509h2_000a,002f,0033,0035,0039,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201
one_again=t12d1507h2_073e58a039a6_8ebfdaddfa31
--- no_error_log
[error]



=== TEST 22: first_offered_alpn_is_not_the_negotiated_protocol
# The client offers "h9" first, then "http/1.1". nginx selects http/1.1,
# while JA4 must retain the first offered value h9 in every representation.
--- config
    location /t {
        default_type text/plain;
        return 200 "negotiated=$ssl_alpn_protocol\nja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- curl_options: --utls-hello HelloFirefox_55 --utls-alpn-hex 6839
--- request
GET /t
--- response_body
negotiated=http/1.1
ja4=t12i1508h9_073e58a039a6_e70312a1ce2c
ja4_string=t12i1508h9_000a,002f,0033,0035,0039,c009,c00a,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0017,0023,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201
ja4one=t12i1507h9_073e58a039a6_8ebfdaddfa31
--- no_error_log
[error]



=== TEST 23: highest_offered_tls_version_survives_tls12_negotiation
# Chrome_133 offers TLS 1.3 and 1.2 plus GREASE. The server only accepts
# TLS 1.2; JA4 must still report t13 from supported_versions, not t12 from
# the negotiated protocol or ClientHello legacy_version.
--- config
    ssl_protocols TLSv1.2;
    location /t {
        default_type text/plain;
        return 200 "negotiated=$ssl_protocol\nja4=$http_ssl_ja4\nja4_string=$http_ssl_ja4_string\nja4one=$http_ssl_ja4one\n";
    }
--- curl_protocol: https
--- server_addr_for_client: example.test
--- curl_options: --utls-hello HelloChrome_133
--- request
GET /t
--- response_body
negotiated=TLSv1.2
ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd
ja4_string=t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
ja4one=t13d1514h2_8daaf6152771_1e53c2b25e87
--- no_error_log
[error]
