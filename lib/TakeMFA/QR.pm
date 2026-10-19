package TakeMFA::QR;
use strict;
use warnings;
use IPC::Open3 ();
use Symbol qw(gensym);
use JSON::PP ();
our $PROGRAM='/usr/local/cpanel/3rdparty/take-mfa/qr-svg.py';
sub svg {
    my ($u,$secret)=@_;TakeMFA::Core::username($u);
    die "Invalid setup key\n" unless defined($secret) && $secret =~ /\A[A-Z2-7]{32}\z/;
    my ($in,$out,$err,$pid,$svg);$err=gensym();
    my $ok=eval {
        local $SIG{ALRM}=sub {die "QR timeout\n";};alarm(5);
        # No shell, network request, secret in process arguments, or QR temp file.
        $pid=IPC::Open3::open3($in,$out,$err,'/usr/bin/python3','-B',$PROGRAM);
        print {$in} JSON::PP::encode_json({user=>$u,secret=>$secret});close($in);
        $svg=do {local $/;<$out>};close($out);close($err);waitpid($pid,0);
        die "QR unavailable\n" if $? || !defined($svg) || length($svg)>150_000 || $svg !~ /\A<svg\s/ || $svg !~ m{</svg>\s*\z};
        alarm(0);1;
    };
    alarm(0);
    unless($ok){if($pid){kill('TERM',$pid);waitpid($pid,0);}return '';}
    return $svg;
}
1;
