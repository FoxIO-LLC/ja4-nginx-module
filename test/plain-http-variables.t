# vi:filetype=perl
# Test::Nginx tests for ngx_http_ssl_ja4_module.
#
# Client: Test::Nginx default (Perl IO::Socket, plain HTTP/1.1).
# Scope: module load, plain-HTTP safety when JA4 variables are referenced,
#        JA4H HTTP-layer fields (method, Cookie, Referer, Accept-Language),
#        JA4H.png hashes (header order, cookie fields sorted).
# Not covered here: TLS ClientHello / JA4 golden fingerprints (see test/*.py).
#
# Run (requires nginx built with this module + Test::Nginx):
#   export TEST_NGINX_BINARY=/path/to/nginx
#   export PERL5LIB=$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}
#   prove -v test/plain-http-variables.t
# TEST_NGINX_SERVROOT is optional; defaults to test/servroot below.

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
}

use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: module_loads (JA4H variable is registered)
# JA4H is HTTP-layer and works without TLS. A non-empty value proves the
# module was compiled in and its variables are available to the rewrite
# engine.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn
--- no_error_log
[error]



=== TEST 2: plain_http_no_crash (SSL JA4 vars on plain HTTP)
# On non-TLS connections ngx_ssl_ja4() declines; handlers must not crash
# the worker. Current behavior substitutes an empty value (not 500).
# JA4X is registered as $https_ssl_ja4x (not $http_ssl_ja4x).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4 ja4_string=$http_ssl_ja4_string ja4one=$http_ssl_ja4one ja4s=$http_ssl_ja4s ja4s_string=$http_ssl_ja4s_string ja4l=$http_ssl_ja4l ja4t=$http_ssl_ja4t ja4t_string=$http_ssl_ja4t_string ja4ts=$http_ssl_ja4ts ja4ts_string=$http_ssl_ja4ts_string ja4x=$https_ssl_ja4x ja4x_string=$https_ssl_ja4x_string\n";
    }
--- request
GET /t
--- response_body
ja4= ja4_string= ja4one= ja4s= ja4s_string= ja4l= ja4t= ja4t_string= ja4ts= ja4ts_string= ja4x= ja4x_string=
--- no_error_log
[error]



=== TEST 3: no_error_on_missing_ssl (mixed dump including JA4H)
# Reference SSL + HTTP JA4 variables together on plain HTTP. SSL-derived
# fields stay empty; JA4H is still computed from the request line/headers.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4=$http_ssl_ja4 ja4h=$http_ssl_ja4h\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4= ja4h=ge11nn
--- no_error_log
[error]



=== TEST 4: ja4h_with_cookie
# Cookie presence is 'c'. Cookie is excluded from the 2-digit header count
# (baseline GET is 02: Host + Connection).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: a=1
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cn02
--- no_error_log
[error]



=== TEST 5: ja4h_with_referer
# Referer presence is 'r'. Referer is excluded from the header count.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Referer: http://example.test/
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nr02
--- no_error_log
[error]



=== TEST 6: ja4h_cookie_and_referer
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: a=1
Referer: http://example.test/
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cr02
--- no_error_log
[error]



=== TEST 7: ja4h_post
# First two letters of POST, lowercased. Do not pin header count:
# Test::Nginx may add Content-Length for the body.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
POST /t
hello
--- response_body_like chomp
^ja4h=po11nn
--- no_error_log
[error]



=== TEST 8: ja4h_accept_language
# Primary Accept-Language: skip hyphens, first 4 alphanumerics, lowercased
# (en-US -> enus). Accept-Language is counted (baseline 02 -> 03).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Accept-Language: en-US,en;q=0.9
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn03enus_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$
--- no_error_log
[error]



=== TEST 9: ja4h_string_no_cookie
# $http_ssl_ja4h_string is A-section, raw header names, raw cookie fields,
# raw cookie values. No cookies => empty trailing field/value segments.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h_string=$http_ssl_ja4h_string\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4h_string=ge11nn\d{2}0000_.+__$
--- no_error_log
[error]



=== TEST 10: ja4h_string_with_cookie
# Cookie: a=1 => raw cookie fields "a", raw cookie values "1".
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h_string=$http_ssl_ja4h_string\n";
    }
--- more_headers
Cookie: a=1
--- request
GET /t
--- response_body_like chomp
^ja4h_string=ge11cn\d{2}0000_.+_a_1$
--- no_error_log
[error]



=== TEST 11: ja4h_spec_no_cookie
# JA4H.png: b = truncated SHA-256 of header names in wire order (Host then
# Connection). No delimiter specified; pieces are concatenated. Missing
# cookies still produce c/d (empty SHA-256), not spec zeros.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn020000_7a4d84769e2f_e3b0c44298fc_e3b0c44298fc$
--- no_error_log
[error]



=== TEST 12: ja4h_spec_cookie
# Cookie is ignored in the a-section count, not in b (headers in the order
# they appear). c = sha256 of cookie field name "a"; d = sha256 of "a=1".
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: a=1
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cn020000_732b78a28558_ca978112ca1b_c22fea5d7428$
--- no_error_log
[error]



=== TEST 13: ja4h_spec_cookie_sort
# Cookie fields sorted: names a then z; pairs a=1 then z=9. Concatenated
# (diagram does not specify commas).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: z=9; a=1
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cn020000_732b78a28558_9c0ada37bf74_509a74b46377$
--- no_error_log
[error]



=== TEST 14: ja4h_spec_referer_in_hash_not_count
# Referer is ignored in the a-section count (still 02) but is a header that
# appears, so b is sha256("HostConnectionReferer"), not TEST 11's b.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Referer: http://example.test/
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nr020000_864f5fba6472_e3b0c44298fc_e3b0c44298fc$
--- no_error_log
[error]



=== TEST 15: ja4h_http10
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
GET /t HTTP/1.0
--- response_body_like chomp
^ja4h=ge10nn
--- no_error_log
[error]



=== TEST 16: ja4h_put
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
PUT /t
--- response_body_like chomp
^ja4h=pu11nn
--- no_error_log
[error]



=== TEST 17: ja4h_accept_language_short
# Accept-Language "en" pads to en00 (first 4 alphanumerics, right-padded).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Accept-Language: en
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn03en00
--- no_error_log
[error]

