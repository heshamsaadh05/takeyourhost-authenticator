package Cpanel::Admin::Modules::Cpanel::take_mfa;
use strict;
use warnings;
use lib '/usr/local/cpanel/3rdparty/take-mfa/lib';
use parent qw(Cpanel::Admin::Base);
use TakeMFA::Core ();

# CONSOLE additionally requires a restored, authenticated native cPanel session.
sub _actions { return qw(STATUS CHALLENGE VERIFY CONSOLE); }
sub _allowed_parents {
    my @parents=(__PACKAGE__->SUPER::_allowed_parents(),'/usr/local/cpanel/base/securitypolicy.cgi');
    my $compat='/usr/local/cpanel/.rcscpsrvd';my @st=lstat($compat);
    push @parents,$compat if @st && -f _ && !-l _ && $st[4]==0 && ($st[2]&022)==0 && -x $compat;
    return @parents;
}
sub _identity {
    my ($self,$claimed)=@_;
    die "Invalid caller\n" if ref($claimed);
    my $u=TakeMFA::Core::username($self->get_caller_username());
    die "Account mismatch\n" unless defined($claimed) && $claimed eq $u;
    my $allowed=$u eq 'root';
    if (!$allowed && open(my $fh,'<','/var/cpanel/resellers')) {
        while(my $line=<$fh>){if(index($line,$u.':')==0){$allowed=1;last;}}
        close($fh);
    }
    $allowed=1 if -f '/var/cpanel/users/'.$u;
    die "Hosting account required\n" unless $allowed;return $u;
}
sub STATUS {
    my ($self,$claimed,$session,$mode,$app,$actor)=@_;my $u=$self->_identity($claimed);
    die "Invalid input\n" if ref($session) || ref($mode) || ref($app) || length($session//'')>320 || length($mode//'')>30;
    die "Invalid service\n" if defined($app) && $app ne 'cpaneld' && $app ne 'whostmgrd';
    ($u,$session)=$self->_subject($u,$session,$actor) if defined($actor) && $actor ne $u;
    return {protected=>0,verified=>0} unless TakeMFA::Core::protected($u,$app);
    my $interactive=($mode//'') eq 'session' || ($mode//'') eq 'openid_connect';
    return {protected=>1,verified=>$interactive?TakeMFA::Core::verified($u,$session):0};
}
sub CHALLENGE {
    my ($self,$claimed,$session,$actor)=@_;my $u=$self->_identity($claimed);
    die "Invalid input\n" if ref($session) || length($session//'')>320;
    ($u,$session)=$self->_subject($u,$session,$actor) if defined($actor) && $actor ne $u;
    return TakeMFA::Core::challenge($u,$session);
}
sub VERIFY {
    my ($self,$claimed,$session,$nonce,$code,$actor)=@_;my $u=$self->_identity($claimed);
    die "Invalid input\n" if ref($session) || ref($nonce) || ref($code) || length($session//'')>320 || length($nonce//'')>80 || length($code//'')>32;
    ($u,$session)=$self->_subject($u,$session,$actor) if defined($actor) && $actor ne $u;
    return TakeMFA::Core::verify($u,$session,$nonce,$code);
}
sub _subject {
    my ($self,$caller,$session,$actor)=@_;
    TakeMFA::Core::username($actor);
    require Cpanel::Session::Load;
    my $s=Cpanel::Session::Load::loadSession($session);
    die "Invalid possessor session\n" unless ref($s) eq 'HASH' && ($s->{user}//'') eq $caller && !$s->{expired} && !$s->{needs_auth};
    my $primary=$s->{origin}{possessor}//$s->{possessor}//$s->{authenticated_user}//$s->{user};
    die "Invalid possessor identity\n" unless defined($primary) && $primary eq $actor;
    return ($actor,TakeMFA::Core::subject_session($actor,$session));
}
sub CONSOLE {
    my ($self,$claimed,$prefix,$post)=@_;my $u=$self->_identity($claimed);
    die "Invalid route\n" if ref($prefix) || ($prefix//'') !~ m{\A/cpsess[0-9]+\z};
    die "Invalid form\n" unless ref($post) eq 'HASH' && keys(%$post)<=5;
    for my $k(keys %$post){die "Invalid field\n" unless $k =~ /\A(?:action|nonce|code|ack|target)\z/ && !ref($post->{$k}) && defined($post->{$k}) && length($post->{$k})<=256 && $post->{$k} !~ /[\x00-\x1f\x7f-\xff]/;}
    require Cpanel::Session::Restore;
    local $ENV{cp_security_token}=$prefix;
    my ($session,$native)=Cpanel::Session::Restore::restoreSession($u);
    die "Verified native session required\n" unless $session && ref($native) eq 'HASH' && ($native->{user}//'') eq $u && ($native->{successful_internal_auth_with_timestamp} || $native->{successful_external_auth_with_timestamp});
    TakeMFA::Core::sid($u,$session);
    die "MFA required\n" if TakeMFA::Core::protected($u,'cpaneld') && !TakeMFA::Core::verified($u,$session);
    die "Enrollment unavailable\n" unless TakeMFA::Core::enrollment_allowed($u);
    require TakeMFA::Controller;
    require MIME::Base64;require Encode;
    my $body=TakeMFA::Controller::body($u,$session,$prefix,$post,1);
    # cpwrapd's serializer expects byte-safe/ASCII strings, not wide characters.
    return {body_b64=>MIME::Base64::encode_base64(Encode::encode('UTF-8',$body),'')};
}
1;
