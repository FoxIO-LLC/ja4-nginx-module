# vi:filetype=perl
# Test::Nginx tests for ngx_http_ssl_ja4_module.
#
# Client: Test::Nginx default (Perl IO::Socket, plain HTTP/1.1).
# Scope: module load, plain-HTTP safety when JA4 variables are referenced,
#        JA4H HTTP-layer fields (method, Cookie, Referer, Accept-Language),
#        JA4H goldens from FoxIO rust/ja4/src/http.rs (comma-join, hash12 zeros).
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
# Cookie+Referer dropped from b (same hash as TEST 11). c/d as TEST 12.
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
^ja4h=ge11cr020000_d5c75abc5c2c_ca978112ca1b_c22fea5d7428$
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
# JA4H_r: a + unhashed b/c/d inputs. Cookie/Referer dropped from headers.
# No cookies => empty cookie-name and pair segments.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h_string=$http_ssl_ja4h_string\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4h_string=ge11nn020000_Host,Connection__$
--- no_error_log
[error]



=== TEST 10: ja4h_string_with_cookie
# JA4H_r: Cookie dropped from the header list; last segments are name and
# name=value (not value only).
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
^ja4h_string=ge11cn020000_Host,Connection_a_a=1$
--- no_error_log
[error]



=== TEST 11: ja4h_spec_no_cookie
# FoxIO rust/ja4: b = hash12(join(',', header names)), Cookie/Referer dropped.
# Empty cookies: hash12("") = 000000000000 (not sha256 of empty bytes).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn020000_d5c75abc5c2c_000000000000_000000000000$
--- no_error_log
[error]



=== TEST 12: ja4h_spec_cookie
# Cookie is dropped from b (same as TEST 11). c = hash12("a"); d = hash12("a=1").
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
^ja4h=ge11cn020000_d5c75abc5c2c_ca978112ca1b_c22fea5d7428$
--- no_error_log
[error]



=== TEST 13: ja4h_spec_cookie_sort
# Sorted cookie names/pairs comma-joined: hash12("a,z") / hash12("a=1,z=9").
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
^ja4h=ge11cn020000_d5c75abc5c2c_5580854b5248_1eae8af021d5$
--- no_error_log
[error]



=== TEST 14: ja4h_spec_referer_dropped_from_b
# Referer is ignored in the count (02) and dropped from b (same as TEST 11).
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
^ja4h=ge11nr020000_d5c75abc5c2c_000000000000_000000000000$
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



=== TEST 18: ja4h_spec_two_cookie_headers
# Two Cookie lines. Count ignores both (still 02). b drops Cookie (same as
# TEST 11). c/d match TEST 13 (comma-joined sorted names/pairs).
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: z=9
Cookie: a=1
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cn020000_d5c75abc5c2c_5580854b5248_1eae8af021d5$
--- no_error_log
[error]



=== TEST 19: ja4h_spec_cookie_no_equals
# Cookie token with no "=": field and fields+values are both the name.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Cookie: flag
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11cn020000_d5c75abc5c2c_807d0fbcae7c_807d0fbcae7c$
--- no_error_log
[error]



=== TEST 20: ja4h_accept_language_empty
# Header present (count 03) but empty value keeps default 0000.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Accept-Language:
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn030000_6fe3288294a7_000000000000_000000000000$
--- no_error_log
[error]



=== TEST 21: ja4h_accept_language_q_only
# No language subtag; first char ';' stops the loop -> 0000.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Accept-Language: ;q=0.9
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn030000_6fe3288294a7_000000000000_000000000000$
--- no_error_log
[error]



=== TEST 22: ja4h_accept_language_truncated
# More than 4 kept chars: english -> engl.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
Accept-Language: english
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn03engl_6fe3288294a7_000000000000_000000000000$
--- no_error_log
[error]



=== TEST 23: ja4h_spec_headers_second_part
# nginx nalloc=20: Host, Connection, X-0 .. X-17 fill the first part;
# X-18 is on part.next. Count must be 21, not first-part 20.
# b is hash12 of comma-joined names including X-18.
--- config
    location /t {
        default_type text/plain;
        return 200 "ja4h=$http_ssl_ja4h\n";
    }
--- more_headers
X-0: 1
X-1: 1
X-2: 1
X-3: 1
X-4: 1
X-5: 1
X-6: 1
X-7: 1
X-8: 1
X-9: 1
X-10: 1
X-11: 1
X-12: 1
X-13: 1
X-14: 1
X-15: 1
X-16: 1
X-17: 1
X-18: 1
--- request
GET /t
--- response_body_like chomp
^ja4h=ge11nn210000_e46fbdfb6ecf_000000000000_000000000000$
--- no_error_log
[error]
