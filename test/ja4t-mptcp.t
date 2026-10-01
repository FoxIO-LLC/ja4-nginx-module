# vi:filetype=perl
# tcp_save_syn skips MPTCP listeners ("listen ... multipath", nginx 1.29.7+).
# The kernel rejects TCP_SAVE_SYN on MPTCP sockets with ENOPROTOOPT, so the
# listener must not get the setsockopt (no startup alert) and $http_ssl_ja4t
# stays empty. Requires net.mptcp.enabled=1.
#
#   PERL5LIB="$HOME/perl5/lib/perl5${PERL5LIB:+:$PERL5LIB}" \
#   TEST_NGINX_BINARY=/path/to/nginx \
#       prove -v test/ja4t-mptcp.t

use File::Spec;
use Test::More;

BEGIN {
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    my $mptcp = `sysctl -n net.mptcp.enabled 2>/dev/null`;
    plan skip_all => 'MPTCP disabled (net.mptcp.enabled != 1)'
        unless defined $mptcp && $mptcp =~ /^1$/m;
}

use Test::Nginx::Socket 'no_plan';

$ENV{TEST_NGINX_MPTCP_PORT} ||= ($ENV{TEST_NGINX_SERVER_PORT} || 1984) + 10;

my $configure = `$Test::Nginx::Util::NginxBinary -V 2>&1`;
our $HAVE_STREAM = $configure =~ m{--with-stream\b};

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: http multipath listener gets no TCP_SAVE_SYN and an empty JA4T
--- skip_nginx: 3: < 1.29.7
--- http_config
    tcp_save_syn on;

    server {
        listen 127.0.0.1:$TEST_NGINX_MPTCP_PORT multipath;

        location = /fingerprint {
            default_type text/plain;
            return 200 "ja4t=$http_ssl_ja4t\n";
        }
    }
--- config
    location = /t {
        proxy_pass http://127.0.0.1:$TEST_NGINX_MPTCP_PORT/fingerprint;
    }
--- request
GET /t
--- error_code: 200
--- response_body
ja4t=
--- no_error_log
TCP_SAVE_SYN
[alert]
[error]



=== TEST 2: stream multipath listener gets no TCP_SAVE_SYN
--- skip_nginx: 3: < 1.29.7
--- skip_eval: 3: !$::HAVE_STREAM
--- main_config
    stream {
        tcp_save_syn on;

        server {
            listen 127.0.0.1:$TEST_NGINX_MPTCP_PORT multipath;
            return "ok";
        }
    }
--- config
    location = /t {
        return 200 "ok";
    }
--- request
GET /t
--- error_code: 200
--- response_body chomp
ok
--- no_error_log
TCP_SAVE_SYN
[alert]
