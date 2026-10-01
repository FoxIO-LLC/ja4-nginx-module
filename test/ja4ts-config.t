# vi:filetype=perl
# tcp_save_synack configuration and $upstream_ja4ts without capture.
#
# Nothing here loads BPF or needs root. It runs against nginx with the
# SYN-ACK patch, with or without the ebpf addon; tests that only make sense
# for one of those builds skip themselves. Capture itself is covered by the
# privileged ja4ts-variables.t and ja4ts-network.t.
#
#   TEST_NGINX_BINARY=/path/to/nginx prove -v test/ja4ts-config.t
#
# TEST_NGINX_SERVROOT is optional; defaults to test/servroot below.

use FindBin;
use lib "$FindBin::Bin/lib";
use Ja4tsCapture;

BEGIN {
    use File::Spec;
    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    Ja4tsCapture::require_nginx_binary();
}

use Test::Nginx::Socket 'no_plan';

# What this nginx was configured with.
my $configure = `$Test::Nginx::Util::NginxBinary -V 2>&1`;
our $HAVE_EBPF = $configure =~ m{--add-module=\S*/ebpf\b};
our $HAVE_STREAM = $configure =~ m{--with-stream\b};

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST 1: invalid value is rejected
--- config
    location /t {
        tcp_save_synack yes;
        return 200;
    }
--- must_die
--- error_log
invalid value "yes" in "tcp_save_synack" directive, it must be "on" or "off"



=== TEST 2: not allowed in the main context
--- main_config
    tcp_save_synack on;
--- config
    location /t { return 200; }
--- must_die
--- error_log
"tcp_save_synack" directive is not allowed here



=== TEST 3: not allowed in the upstream context
--- http_config
    upstream forbidden { tcp_save_synack on; server 127.0.0.1:12345; }
--- config
    location / { return 200; }
--- must_die
--- error_log
"tcp_save_synack" directive is not allowed here



=== TEST 4: the variable exists and is empty when capture is unset or off
--- config
    location /default {
        default_type text/plain;
        return 200 "ja4ts=[$upstream_ja4ts]\n";
    }
    location /off {
        tcp_save_synack off;
        default_type text/plain;
        return 200 "ja4ts=[$upstream_ja4ts]\n";
    }
--- request eval
["GET /default", "GET /off"]
--- response_body eval
["ja4ts=[]\n", "ja4ts=[]\n"]
--- no_error_log
[error]



=== TEST 5: on without the ebpf addon fails with a build requirement
--- skip_eval: 2: $::HAVE_EBPF
--- config
    location /t {
        tcp_save_synack on;
        return 200;
    }
--- must_die
--- error_log
tcp_save_synack requires the optional ebpf core module



=== TEST 6: not allowed in the stream context
# Capture is HTTP-only.
--- skip_eval: 2: !$::HAVE_STREAM
--- main_config
    stream { tcp_save_synack on; }
--- config
    location /t { return 200; }
--- must_die
--- error_log
"tcp_save_synack" directive is not allowed here



=== TEST 7: on with the ebpf addon fails clearly without BPF privileges
# Needs the addon and a non-root run: as root the programs would load.
--- skip_eval: 2: !$::HAVE_EBPF || $> == 0
--- config
    location /t {
        tcp_save_synack on;
        return 200;
    }
--- must_die
--- error_log
tcp_save_synack: cannot load the BPF capture programs; the master process needs root
