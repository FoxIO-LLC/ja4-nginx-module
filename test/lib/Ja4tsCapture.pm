package Ja4tsCapture;

# Shared fixture for the privileged JA4TS suites (ja4ts-variables.t and
# ja4ts-network.t).
#
# Upstreams are extra server blocks in the same nginx (127.0.0.1 / ::1). The
# kernel builds their SYN-ACKs, so goldens come from nftables rules that
# rewrite the SYN-ACK in the output hook before nginx receives it. A block's
# `--- synack` section lists one rule per upstream:
#
#   up1: window=8192 mss=1460 wscale=3 reset=timestamp,sack-perm
#
# window/mss/wscale set that field; reset NOPs out the listed options in
# place (maxseg, sack-perm, timestamp, window). wscale is written at a fixed
# offset, so it assumes the Linux default SYN-ACK layout 2-4-8-1-3; the suites
# are skipped unless tcp_timestamps, tcp_sack, and tcp_window_scaling are 1.
# Blocks without `--- synack` see the unmodified kernel SYN-ACK.
#
# Network-path blocks may also carry:
#
#   --- nat         raw nft rules for the nat output (DNAT/REDIRECT) or
#                   postrouting (SNAT) hook, one per line, prefixed with
#                   `output:` or `postrouting:`; $TEST_NGINX_* is expanded
#   --- prerouting  one raw rule for a filter prerouting hook at mangle priority
#   --- notrack     any value: mark all traffic untracked in the raw hooks
#
# Everything runs as root inside a private network namespace; nothing is
# changed on the host.
#
# Usage:
#
#   use lib 'test/lib';
#   use Ja4tsCapture;
#   BEGIN { Ja4tsCapture::enter_namespace() }
#   use Test::Nginx::Socket 'no_plan';
#   Ja4tsCapture::install();
#
# Files that only need the nginx binary check can call
# Ja4tsCapture::require_nginx_binary() from BEGIN instead.

use strict;
use warnings;

use File::Spec;
use Test::More;


# Test::Nginx runs `$TEST_NGINX_BINARY -V`, or `nginx -V` from PATH, and bails
# out with an empty "Failed to get the version of the Nginx in PATH". sudo
# replaces PATH with its secure_path, so an nginx found by the invoking user
# is typically not found by the test. Say so before Test::Nginx is loaded.

sub require_nginx_binary {
    my $bin = $ENV{TEST_NGINX_BINARY};

    if (defined $bin && $bin ne '') {
        return if -f $bin && -x _;
        BAIL_OUT("TEST_NGINX_BINARY=$bin is not an executable file");
    }

    for my $dir (File::Spec->path) {
        return if -f "$dir/nginx" && -x _;
    }

    BAIL_OUT("no nginx in PATH ($ENV{PATH}); set TEST_NGINX_BINARY=/path/to/nginx"
             . ($> == 0 ? " (sudo replaces PATH with its secure_path)" : ""));
}


my $nft_table = 'inet ja4ts_test_' . $$;
my $nft_owner;

my %upstream_port;


# Call from BEGIN, before Test::Nginx::Socket is loaded: it may skip the
# whole file or re-execute it in a private network namespace.

sub enter_namespace {
    if ($ENV{JA4TS_REQUIRE_CAPTURE_TESTS}) {
        die "privileged JA4TS CI requires root and nft\n"
            if $> != 0 || system('nft --version >/dev/null 2>&1') != 0;
    }

    $ENV{TEST_NGINX_SERVROOT} ||= File::Spec->rel2abs('test/servroot');
    $ENV{TEST_NGINX_CERT_DIR} ||= File::Spec->rel2abs('test/certs');

    plan skip_all => "JA4TS requires root (sudo -E env PERL5LIB=... prove -v $0)"
        unless $> == 0;
    plan skip_all => 'nft not found'
        unless system('nft --version >/dev/null 2>&1') == 0;

    require_nginx_binary();

    unless (($ENV{JA4TS_PRIVATE_NETNS} // '') eq "$$") {
        $ENV{JA4TS_PRIVATE_NETNS} = $$;
        exec 'unshare', '--net', '--', $^X, $0;
        die "cannot enter private network namespace: $!\n";
    }

    run('ip', 'link', 'set', 'lo', 'up');

    for my $knob (qw(tcp_timestamps tcp_sack tcp_window_scaling)) {
        open my $fh, '<', "/proc/sys/net/ipv4/$knob" or next;
        chomp(my $v = <$fh>);

        die "net.ipv4.$knob=$v prevents required JA4TS coverage\n"
            if $ENV{JA4TS_REQUIRE_CAPTURE_TESTS} && $v ne '1';
        plan skip_all => "net.ipv4.$knob=$v changes the default SYN-ACK layout"
            unless $v eq '1';
    }
}


# Run a command inside the namespace; failure aborts the suite.

sub run {
    system(@_) == 0 or die "@_ failed\n";
}


# Call after `use Test::Nginx::Socket`: exports the upstream ports and
# installs the --- synack / --- nat / --- prerouting / --- notrack handling.

sub install {
    %upstream_port = map { ("up$_" => Test::Nginx::Util::server_port() + $_) }
                     1 .. 3;

    $ENV{'TEST_NGINX_' . uc($_) . '_PORT'} = $upstream_port{$_}
        for keys %upstream_port;

    # Nothing listens here; `--- nat` rules rewrite it to a real upstream.
    $ENV{TEST_NGINX_VIRT_PORT} = Test::Nginx::Util::server_port() + 10;

    $nft_owner = 1;

    Test::Nginx::Util::add_block_preprocessor(\&preprocess);
}


sub preprocess {
    my $block = shift;

    nft_reset();

    my $synack = $block->synack // '';
    my $nat = $block->nat // '';
    my $prerouting = $block->prerouting // '';
    my $notrack = $block->notrack // '';

    return unless grep { /\S/ } $synack, $nat, $prerouting, $notrack;

    my @mangle;
    for my $line (grep { /\S/ } split /\n/, $synack) {
        my ($name, $spec) = $line =~ /^\s*(\w+):\s*(.*?)\s*$/
            or die "bad --- synack line: $line\n";
        my $port = $upstream_port{$name} or die "unknown upstream: $name\n";
        push @mangle, nft_rule($port, $spec);
    }

    my %nat = (output => [], postrouting => []);
    for my $line (grep { /\S/ } split /\n/, $nat) {
        my ($hook, $rule) = $line =~ /^\s*(output|postrouting):\s*(.*?)\s*$/
            or die "bad --- nat line: $line\n";
        push @{ $nat{$hook} }, expand($rule);
    }

    my $ruleset = "table $nft_table {\n";

    $ruleset .= nft_chain(out => 'filter hook output priority mangle', \@mangle)
        if @mangle;
    $ruleset .= nft_chain(nat_out => 'nat hook output priority dstnat',
                          $nat{output})
        if @{ $nat{output} };
    $ruleset .= nft_chain(nat_post => 'nat hook postrouting priority srcnat',
                          $nat{postrouting})
        if @{ $nat{postrouting} };
    $ruleset .= nft_chain(pre => 'filter hook prerouting priority mangle',
                          [expand($prerouting)])
        if $prerouting =~ /\S/;

    if ($notrack =~ /\S/) {
        $ruleset .= nft_chain(raw_out => 'filter hook output priority raw',
                              ['notrack']);
        $ruleset .= nft_chain(raw_pre => 'filter hook prerouting priority raw',
                              ['notrack']);
    }

    $ruleset .= "}\n";

    open my $nft, '|-', 'nft -f -' or die "nft: $!\n";
    print $nft $ruleset;
    close $nft or die "nft rejected ruleset:\n$ruleset";
}


sub nft_rule {
    my ($port, $spec) = @_;
    my (@set, @reset);

    for my $kv (split ' ', $spec) {
        my ($k, $v) = split /=/, $kv, 2;

        if    ($k eq 'window') { push @set, "tcp window set $v" }
        elsif ($k eq 'mss')    { push @set, "tcp option maxseg size set $v" }
        # Byte 39 of the TCP header in MSS, SACK_PERM, TS, NOP, WS.
        elsif ($k eq 'wscale') { push @set, "\@th,312,8 set $v" }
        elsif ($k eq 'reset')  { push @reset, map { "reset tcp option $_" }
                                              split /,/, $v }
        else                   { die "unknown --- synack key: $k\n" }
    }

    return "tcp sport $port tcp flags & (syn|ack) == syn|ack @set @reset";
}


sub nft_chain {
    my ($name, $hook, $rules) = @_;

    return "  chain $name {\n"
         . "    type $hook; policy accept;\n"
         . join('', map { "    $_\n" } @$rules)
         . "  }\n";
}


sub expand {
    my $rule = shift;

    $rule =~ s/\$(TEST_NGINX_\w+)/$ENV{$1} \/\/ die "\$$1 not set\n"/ge;

    return $rule;
}


sub nft_reset {
    system("nft delete table $nft_table >/dev/null 2>&1");
}


END { local $?; nft_reset() if $nft_owner }


1;
