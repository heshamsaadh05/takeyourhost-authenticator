package TakeMFA::View;
use strict;
use warnings;
use utf8;
use TakeMFA::Core ();
use Cpanel::Encoder::URI ();
our $CGI=0;
our $ASSETS='/usr/local/cpanel/3rdparty/take-mfa';

sub escape {
    my ($s)=@_;$s='' unless defined $s;
    $s =~ s/&/&amp;/g;$s =~ s/</&lt;/g;$s =~ s/>/&gt;/g;$s =~ s/"/&quot;/g;$s =~ s/'/&#39;/g;return $s;
}
sub prefix {
    my $p=$ENV{cp_security_token}//'';
    die "Missing authenticated path\n" unless $p =~ m{\A/cpsess[0-9]+\z};return $p;
}
sub post_fields {
    return {} unless ($ENV{REQUEST_METHOD}//'') eq 'POST';
    die "Invalid form\n" unless ($ENV{CONTENT_TYPE}//'') =~ m{\Aapplication/x-www-form-urlencoded(?:;|\z)};
    my $length=$ENV{CONTENT_LENGTH}//'';
    die "Invalid form size\n" unless $length =~ /\A[0-9]{1,4}\z/ && $length>0 && $length<=4096;
    my $body='';while(length($body)<$length) {my $n=read(STDIN,my $chunk,$length-length($body));die "Incomplete form\n" unless $n;$body.=$chunk;}
    my %values;
    for my $pair (split /&/,$body) {
        my ($key,$value)=split /=/,$pair,2;$value//='';
        for ($key,$value) {s/\+/ /g;die "Invalid encoding\n" if /%(?![0-9A-Fa-f]{2})/;$_=Cpanel::Encoder::URI::uri_decode_str($_);}
        die "Invalid field\n" unless $key =~ /\A(?:nonce|code|action|ack|target)\z/ && !exists($values{$key}) && length($value)<=256 && $value !~ /[\x00-\x1f\x7f-\xff]/;
        $values{$key}=$value;
    }
    return \%values;
}
sub headers {
    my ($status)=@_;
    my $header=($CGI?'Status: ':'HTTP/1.1 ').($status||'200 OK')."\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store, private\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'\r\nConnection: close\r\n\r\n";
    print $header;
    binmode(STDOUT,':encoding(UTF-8)');
}
sub page {
    my ($title,$body,$status)=@_;headers($status);
    my $css='';
    if(open(my $fh,'<',"$ASSETS/console.css")){local $/;$css=<$fh>;close($fh);}
    print '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.escape($title).'</title><style>'.$css.'</style></head><body><div class="topbar"><div class="topbar-inner"><a class="brand" href="'.escape(prefix()).'/"><span class="brand-mark">T<span>H</span></span><span dir="ltr">TakeYourHost <small>SECURITY CENTER</small></span></a><span class="topbar-tag">WHM / المصادقة الثنائية</span></div></div><main><div class="page-heading"><div><div class="eyebrow">حماية إضافية. تحكم أوضح.</div><h1>'.escape($title).'</h1></div><span class="version">AUTHENTICATOR <b>2.0</b></span></div>'.$body.'<footer><span>TakeYourHost Security</span><span>توليد محلي للرموز · لا يحتاج عنوان IP ثابتًا</span></footer></main></body></html>';
}
sub form {
    my ($action,$nonce,$label,$operation,$button)=@_;$operation//='confirm';$button//='تحقق وتابع';
    return '<form method="post" action="'.escape($action).'" autocomplete="off"><input type="hidden" name="nonce" value="'.escape($nonce).'"><input type="hidden" name="action" value="'.escape($operation).'"><label for="code-'.escape($operation).'">'.escape($label).'</label><input id="code-'.escape($operation).'" name="code" type="text" dir="ltr" autocomplete="one-time-code" maxlength="32" required placeholder="000 000"><button type="submit">'.escape($button).'</button></form>';
}
sub redirect {
    my $p=prefix();print "HTTP/1.1 303 See Other\r\nLocation: $p/\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
}
1;
