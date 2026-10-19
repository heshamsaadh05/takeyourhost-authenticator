package TakeMFA::Controller;
use strict;
use warnings;
use utf8;
use TakeMFA::Manage ();
use TakeMFA::Console ();
sub body {
    my ($u,$session,$prefix,$post,$cpanel)=@_;my $result;my $message='';my $error='';
    local $TakeMFA::Console::CPANEL=$cpanel?1:0;
    if(%$post){
        my $action=$post->{action}//'';
        if($action eq 'confirm'){
            $result=TakeMFA::Core::confirm_enrollment($u,$session,$post->{nonce},$post->{code});
            $message='تم ربط التطبيق وتفعيل حماية الحساب. احفظ رموز الاسترداد أدناه.';
        }elsif($action eq 'confirm_rotation'){
            $result=TakeMFA::Manage::confirm_rotation($u,$session,$post->{nonce},$post->{code});
            $message='تم اعتماد التطبيق الجديد وإلغاء المفتاح ورموز الاسترداد السابقة.';
        }elsif($action eq 'client_pause' || $action eq 'client_resume'){
            die "Invalid confirmation\n" unless ($post->{ack}//'') eq '1';
            $result=TakeMFA::Manage::client_action($u,$session,$post->{nonce},$post->{code},$post->{target},$action);
            $message='تم تحديث إعداد حماية cPanel للحساب المملوك لك. لم يتغير تطبيق العميل أو مفتاحه.';
        }else{
            die "Invalid confirmation\n" if $action =~ /\A(?:pause|pause_cpanel|rotate|recovery|global_off)\z/ && ($post->{ack}//'') ne '1';
            $result=TakeMFA::Manage::action($u,$session,$post->{nonce},$post->{code},$action);
            my %messages=(pause=>'أوقفت العامل المخصص لحسابك في WHM وcPanel.',resume=>'تم تشغيل العامل المخصص لحسابك مجددًا.',pause_cpanel=>'أوقفت حماية cPanel فقط لهذا الحساب. لم يتغير إعداد WHM.',resume_cpanel=>'تم تشغيل حماية cPanel لهذا الحساب. يسري ذلك إذا كان العامل العام للحساب والإضافة قيد التشغيل.',rotate=>'امسح QR الجديد وأكّد رمزه. يبقى التطبيق السابق فعالًا حتى التأكيد.',cancel_rotation=>'أُلغي استبدال التطبيق. لم يتغير مفتاحك الحالي.',recovery=>'تم إنشاء رموز استرداد جديدة وإلغاء الرموز السابقة.',global_off=>'أُوقفت الإضافة على مستوى الخادم. جميع عوامل الحسابات محفوظة.',global_on=>'تم تشغيل الإضافة على مستوى الخادم.');
            $message=$messages{$action}//'';
        }
        unless($result->{ok}){$message='';$error='لم يُنفذ التغيير. تحقق من الرمز والمحاولة. انتظر الرمز التالي إذا استُخدم الحالي، أو ثلاث دقائق إذا قُيدت المحاولات.';}
    }
    my $d=TakeMFA::Manage::dashboard($u,$session);my $setup;
    if(!$d->{enrolled}){$setup=TakeMFA::Core::begin_enrollment($u,$session);}
    elsif($d->{rotation}){$setup={%{$d->{rotation}},rotation=>1};}
    return TakeMFA::Console::render($u,$prefix,$d,$setup,$result,$message,$error);
}
1;
