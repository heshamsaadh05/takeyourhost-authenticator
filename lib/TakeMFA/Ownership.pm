package TakeMFA::Ownership;
use strict;
use warnings;
use TakeMFA::Core ();
sub reseller {
    my ($u)=@_;TakeMFA::Core::username($u);return 1 if $u eq 'root';
    if(open(my $fh,'<','/var/cpanel/resellers')){while(my $line=<$fh>){if(index($line,$u.':')==0){close($fh);return 1;}}close($fh);}return 0;
}
sub owns {
    my ($u,$target)=@_;TakeMFA::Core::username($u);TakeMFA::Core::username($target);
    return 0 if $u eq $target || !reseller($u) || !-f '/var/cpanel/users/'.$target;
    require Cpanel::Config::LoadCpUserFile;
    my $c=Cpanel::Config::LoadCpUserFile::loadcpuserfile($target);
    return $u eq 'root' || ($c->{OWNER}//'') eq $u;
}
sub clients {
    my ($u)=@_;return [] unless reseller($u);
    my @out;
    if(open(my $fh,'<','/etc/trueuserowners')){
        while(my $line=<$fh>){my ($target,$owner)=$line =~ /\A([a-z][a-z0-9_]{0,31}):\s*([a-z][a-z0-9_]{0,31})\s*\z/;
            push @out,$target if $target && $target ne $u && ($u eq 'root' || $owner eq $u);
        }close($fh);
    }return [sort @out];
}
1;
