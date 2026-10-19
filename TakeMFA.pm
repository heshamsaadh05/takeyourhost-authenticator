package Cpanel::Security::Policy::TakeMFA;
use strict;
use warnings;
use utf8;
use lib '/usr/local/cpanel/3rdparty/take-mfa/lib';
use Cpanel::SecurityPolicy::Base ();
use TakeMFA::Core ();
sub new { return Cpanel::SecurityPolicy::Base->init(__PACKAGE__,15); }
sub description { return 'TakeYourHost Authenticator — WHM and cPanel'; }
sub bypass { return 0; }
sub fails {
    my ($self,$ctx)=@_;
    return 0 unless ($ctx->{appname}//'') eq 'whostmgrd' || ($ctx->{appname}//'') eq 'cpaneld';
    # Machine API tokens remain a separate authentication mechanism.
    return 0 if ($ctx->{authtype}//'') eq 'token';
    my $u=$ctx->{user};return 0 unless defined($u) && length($u);my $failed=1;
    my $actor=$ctx->{is_possessed}?$ctx->{possessor}:$u;
    eval {
        if ($>!=0) {
            require Cpanel::AdminBin::Call;
            my $status=Cpanel::AdminBin::Call::call('Cpanel','take_mfa','STATUS',$u,$ctx->{session_id},$ctx->{authtype},$ctx->{appname},$actor);
            $failed=(!$status->{protected} || $status->{verified})?0:1;
        }
        elsif (!TakeMFA::Core::protected($actor,$ctx->{appname})) {$failed=0;}
        elsif (($ctx->{authtype}//'') eq 'session' || ($ctx->{authtype}//'') eq 'openid_connect') {
            $failed=TakeMFA::Core::verified($actor,TakeMFA::Core::subject_session($actor,$ctx->{session_id}))?0:1;
        }
        1;
    } or $failed=1;
    return $failed;
}
sub get_ui {
    my ($self,$type)=@_;$type//='html';
    return bless {},(($type eq 'json' || $type eq 'xml' || $type eq 'dnsadmin')?'Cpanel::Security::Policy::TakeMFA::DenyUI':'Cpanel::Security::Policy::TakeMFA::HTML');
}

package Cpanel::Security::Policy::TakeMFA::DenyUI;
use strict;
use warnings;
sub process {
    print "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    print '{"metadata":{"result":0,"reason":"TakeMFA: complete Authenticator verification in the browser; use a separately secured API token for automation."},"mfa_required":true}';
    return {error=>'TakeMFA challenge required'};
}

package Cpanel::Security::Policy::TakeMFA::HTML;
use strict;
use warnings;
use utf8;
use TakeMFA::View ();
sub process {
    my ($self,$form,$ctx)=@_;my $error='';my $challenge;my $granted=0;
    my $ok=eval {
        die "Interactive session required\n" unless ($ctx->{authtype}//'') eq 'session' || ($ctx->{authtype}//'') eq 'openid_connect';
        my $caller=$ctx->{user};my $u=$ctx->{is_possessed}?$ctx->{possessor}:$caller;my $native_session=$ctx->{session_id};
        my $session=TakeMFA::Core::subject_session($u,$native_session);
        if (($ENV{REQUEST_METHOD}//'') eq 'POST' && ref($form) eq 'HASH' && exists($form->{code})) {
            my $code=delete $form->{code};my $nonce=delete $form->{nonce};delete $form->{action};
            die "Invalid input\n" if ref($code) || ref($nonce) || !defined($code) || length($code)>32 || !defined($nonce) || length($nonce)>80;
            my $result;
            if ($>!=0) {require Cpanel::AdminBin::Call;$result=Cpanel::AdminBin::Call::call('Cpanel','take_mfa','VERIFY',$caller,$native_session,$nonce,$code,$u);}
            else {$result=TakeMFA::Core::verify($u,$session,$nonce,$code);}
            if ($result->{ok}) {$granted=1;}
            else {$error='الرمز غير صالح أو استُخدم مسبقًا. بعد عدة محاولات، انتظر ثلاث دقائق.';}
        }
        unless ($granted) {
            if ($>!=0) {require Cpanel::AdminBin::Call;$challenge=Cpanel::AdminBin::Call::call('Cpanel','take_mfa','CHALLENGE',$caller,$native_session,$u);}
            else {$challenge=TakeMFA::Core::challenge($u,$session);}
        }
        1;
    };
    if (!$ok) {
        TakeMFA::View::page('تعذر إتمام التحقق','<p>تعذر التحقق من هذه الجلسة. سجّل الدخول من المتصفح، أو استخدم استرداد SSH إذا تعذر الوصول.</p>', '403 Forbidden');
        return {error=>'TakeMFA verification unavailable'};
    }
    if ($granted) {TakeMFA::View::redirect();return {};}
    return {} if !$challenge;
    if ($challenge->{verified}) {TakeMFA::View::redirect();return {};}
    my $body='<p class="notice" data-take-mfa="challenge">أدخل الرمز من تطبيق Authenticator أو أحد رموز الاسترداد المحفوظة. تغيير عنوان الإنترنت لا يلغي تسجيل العامل الثاني.</p>';
    $body.='<p class="error">'.TakeMFA::View::escape($error).'</p>' if $error;
    $body.='<p class="error">المحاولات مقيدة مؤقتًا. انتظر ثلاث دقائق.</p>' if $challenge->{locked};
    $body.=TakeMFA::View::form(TakeMFA::View::prefix().'/', $challenge->{nonce},'رمز التطبيق أو رمز الاسترداد');
    TakeMFA::View::page('التحقق بخطوتين — WHM وcPanel',$body,'403 Forbidden');
    return {error=>'TakeMFA challenge required'};
}
1;
