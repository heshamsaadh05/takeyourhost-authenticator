#!/usr/local/cpanel/3rdparty/bin/perl
use strict;
use warnings;
use utf8;
use lib '/usr/local/cpanel','/usr/local/cpanel/3rdparty/take-mfa/lib';
use TakeMFA::Core ();
use TakeMFA::Manage ();
use TakeMFA::Console ();
use TakeMFA::Controller ();
use Cpanel::Session::Restore ();
$TakeMFA::View::CGI=1;
umask(0077);
my $rendered=0;
eval {
    die "Invalid privilege\n" unless $>==0;
    my $u=TakeMFA::Core::username($ENV{REMOTE_USER});
    my $allowed=$u eq 'root';
    if(!$allowed && open(my $fh,'<','/var/cpanel/resellers')){
        while(my $line=<$fh>){if(index($line,$u.':')==0){$allowed=1;last;}}close($fh);
    }
    die "WHM identity required\n" unless $allowed;
    die "Enrollment unavailable\n" unless TakeMFA::Core::enrollment_allowed($u);
    my $prefix=TakeMFA::View::prefix();
    # Trust cPanel's restored native identity, never a request-supplied session.
    my ($session,$native)=Cpanel::Session::Restore::restoreSession($u);
    die "Verified native session required\n" unless $session && ref($native) eq 'HASH' && ($native->{user}//'') eq $u && ($native->{successful_internal_auth_with_timestamp} || $native->{successful_external_auth_with_timestamp});
    TakeMFA::Core::sid($u,$session);
    my $post=TakeMFA::View::post_fields();
    my $body=TakeMFA::Controller::body($u,$session,$prefix,$post,0);
    TakeMFA::View::page('مركز المصادقة الثنائية',$body);$rendered=1;1;
} or do {
    unless($rendered){
        TakeMFA::View::page('تعذر إتمام الطلب','<section class="card challenge-card"><p class="error">لم يُنفذ الطلب. افتح الإضافة من جلسة WHM الموثقة، وتأكد من رمز التأكيد عند تغيير إعدادات الحماية.</p><p>لا ترسل المفتاح أو رموز الاسترداد للدعم. إذا استمرت المشكلة، استخدم وصول SSH الآمن لمراجعة الحالة.</p></section>','403 Forbidden');
    }
};
