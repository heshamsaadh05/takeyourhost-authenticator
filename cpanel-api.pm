package Cpanel::API::TakeMFA;
use strict;
use warnings;
use Cpanel ();
use Cpanel::AdminBin::Call ();
our %API=();
sub console {
    my ($args,$result)=@_;
    my $u=$Cpanel::user;my %post;
    my $action=$args->get('action');
    if(defined($action) && length($action)){
        die "POST required\n" unless ($ENV{REQUEST_METHOD}//'') eq 'POST';
        for my $key(qw(action nonce code ack target)){my $v=$args->get($key);$post{$key}=$v if defined $v;}
    }
    my $data=Cpanel::AdminBin::Call::call('Cpanel','take_mfa','CONSOLE',$u,$ENV{cp_security_token},\%post);
    $result->data($data);return 1;
}
1;
