#!/usr/local/cpanel/3rdparty/bin/perl
use strict;
use warnings;
use utf8;
use lib '/usr/local/cpanel','/usr/local/cpanel/3rdparty/take-mfa/lib';
use Cpanel::LiveAPI ();
use TakeMFA::View ();
use MIME::Base64 ();
use Encode ();
$TakeMFA::View::CGI=1;
my $panel=Cpanel::LiveAPI->new();
eval {
    my $post=TakeMFA::View::post_fields();
    my $result=$panel->api3('TakeMFA','console',$post);
    my $data=$result->{cpanelresult}{result};
    $data=$result->{result} unless ref($data) eq 'HASH';
    die "Console unavailable\n" unless ref($data) eq 'HASH' && $data->{status} && ref($data->{data}) eq 'HASH' && defined($data->{data}{body_b64});
    my $body=Encode::decode('UTF-8',MIME::Base64::decode_base64($data->{data}{body_b64}),Encode::FB_CROAK());
    TakeMFA::View::page('مركز المصادقة الثنائية',$body);1;
} or do {TakeMFA::View::page('تعذر فتح مركز الحماية','<section class="card challenge-card"><p class="error">تعذر تنفيذ الطلب. افتح الإضافة من جلسة cPanel موثقة وتحقق من رمز التأكيد. لم تتغير إعدادات الحماية.</p></section>','403 Forbidden');};
$panel->end();
