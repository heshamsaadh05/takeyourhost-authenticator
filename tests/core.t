use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::PP ();
use POSIX ();
use FindBin ();
use TakeMFA::Core ();
use TakeMFA::View ();

my $base=tempdir('take-mfa-tests-XXXXXXXX',TMPDIR=>1,CLEANUP=>1);
my $dir=tempdir('unit-XXXXXXXX',DIR=>$base,CLEANUP=>1);
die 'Unsafe test root' unless index($dir,$base.'/unit-')==0;
chmod(0700,$dir);
local $TakeMFA::Core::ROOT=$dir;
open(my $fh,'>',$dir.'/enabled.json') or die $!;print {$fh} '{}';close($fh);chmod(0600,$dir.'/enabled.json');
open($fh,'>',$dir.'/settings.json') or die $!;print {$fh} '{"mode":"pilot","pilot_user":"tester"}';close($fh);chmod(0600,$dir.'/settings.json');
my $clock=2_000_000_010;local $TakeMFA::Core::CLOCK=sub {$clock};
my $rfc='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
my @times=(59,1111111109,1111111111,1234567890,2000000000,20000000000);
my @codes=('287082','081804','050471','005924','279037','353130');
for my $i (0..$#times) {is(TakeMFA::Core::code_at($rfc,$times[$i]),$codes[$i],'RFC6238 SHA1 vector '.($i+1).' (6 digits)');}
ok(!TakeMFA::Core::protected('tester'),'unenrolled account unchanged');
ok(!eval{TakeMFA::Core::begin_enrollment('root','root:AAAAAAAAAAAAAAAA');1},'pilot cannot enroll production root');
for my $u ('../root','root/../../x','root:new','ROOT','') {ok(!eval{TakeMFA::Core::username($u);1},'invalid identity rejected');}
my $a='tester:AAAAAAAAAAAAAAAA';my $b='tester:BBBBBBBBBBBBBBBB';
is(TakeMFA::Core::sid('tester',$a.','.('a'x32)),TakeMFA::Core::sid('tester',$a),'native obfuscated session resolves to same server identity');
ok(!eval{TakeMFA::Core::sid('tester',$a.',invalid');1},'invalid session suffix rejected');
ok(!eval{TakeMFA::Core::sid('tester','root:AAAAAAAAAAAAAAAA');1},'cross-user session rejected');
my $p=TakeMFA::Core::begin_enrollment('tester',$a);
like($p->{secret},qr/\A[A-Z2-7]{32}\z/,'160-bit setup secret');
is(TakeMFA::Core::begin_enrollment('tester',$a)->{secret},$p->{secret},'refresh retains current pending secret');
my $code=TakeMFA::Core::code_at($p->{secret},$clock);
ok(!TakeMFA::Core::confirm_enrollment('tester',$b,$p->{nonce},$code)->{ok},'enrollment cannot move between sessions');
ok(!TakeMFA::Core::confirm_enrollment('tester',$a,'bad-nonce',$code)->{ok},'enrollment requires nonce');
my $confirmed=TakeMFA::Core::confirm_enrollment('tester',$a,$p->{nonce},$code);
ok($confirmed->{ok},'correct TOTP enables factor');
is(scalar(@{$confirmed->{recovery_codes}}),10,'ten recovery codes produced once');
ok(TakeMFA::Core::protected('tester'),'registry commits protection');
ok(TakeMFA::Core::verified('tester',$a),'enrollment session verified');
ok(!TakeMFA::Core::verified('tester',$b),'different session remains blocked');
ok(!exists(TakeMFA::Core::begin_enrollment('tester',$a)->{secret}),'enabled secret not exposed again');
my $c=TakeMFA::Core::challenge('tester',$b);
ok(!TakeMFA::Core::verify('tester',$b,$c->{nonce},$code)->{ok},'enrollment TOTP cannot be replayed');
$clock+=30;
$code=TakeMFA::Core::code_at($p->{secret},$clock);
ok(!TakeMFA::Core::verify('tester',$b,'wrong-nonce',$code)->{ok},'verification requires CSRF nonce');
ok(TakeMFA::Core::verify('tester',$b,$c->{nonce},$code)->{ok},'next TOTP grants new session');
ok(TakeMFA::Core::verified('tester',$b),'verified session accepted');
require(($ENV{TAKE_MFA_TEST_PACKAGE}//"$FindBin::Bin/..").'/TakeMFA.pm');
my $policy=Cpanel::Security::Policy::TakeMFA->new();
my $ctx={appname=>'whostmgrd',user=>'tester',authtype=>'session',session_id=>$b};
ok(!$policy->fails($ctx),'WHM verified browser session passes');
ok($policy->fails({%$ctx,session_id=>'tester:ZZZZZZZZZZZZZZZZ'}),'WHM fresh browser session challenged');
ok($policy->fails({%$ctx,authtype=>'basic'}),'Basic cannot reuse a verified browser grant');
ok(!$policy->fails({%$ctx,authtype=>'token'}),'API tokens explicitly remain independent');
ok(!$policy->fails({%$ctx,user=>'root'}),'unenrolled root unchanged');
ok(!$policy->fails({%$ctx,user=>undef}),'preauthentication login page unaffected');
ok(!$policy->fails({%$ctx,appname=>'cpaneld'}),'verified same-user session accepted on cPanel');
ok($policy->fails({%$ctx,appname=>'cpaneld',session_id=>'tester:PPPPPPPPPPPPPPPP'}),'fresh cPanel session requires same factor');
ok(!$policy->fails({%$ctx,appname=>'webmaild',session_id=>'tester:PPPPPPPPPPPPPPPP'}),'Webmail remains outside plugin scope');
my $htmlsid='tester:HHHHHHHHHHHHHHHH';my $htmlchallenge=TakeMFA::Core::challenge('tester',$htmlsid);
$clock+=30;my $htmlcode=TakeMFA::Core::code_at($p->{secret},$clock);
my $output='';my $response;
{
    local $ENV{REQUEST_METHOD}='POST';local $ENV{cp_security_token}='/cpsess1234567890';
    open(my $capture,'>',\$output) or die $!;local *STDOUT=$capture;
    $response=Cpanel::Security::Policy::TakeMFA::HTML->process({code=>$htmlcode,nonce=>$htmlchallenge->{nonce},action=>'confirm'},{%$ctx,session_id=>$htmlsid});
}
is(ref($response),'HASH','HTML verification returns framework-compatible hash');
like($output,qr/\AHTTP\/1\.1 303 See Other/,'successful HTML verification redirects');
ok(TakeMFA::Core::verified('tester',$htmlsid),'HTML handler grants only its session');
$code=$htmlcode;
my $third='tester:CCCCCCCCCCCCCCCC';my $ch=TakeMFA::Core::challenge('tester',$third);
ok(!TakeMFA::Core::verify('tester',$third,$ch->{nonce},$code)->{ok},'global per-user replay prevention');
my $recovery=$confirmed->{recovery_codes}[0];
ok(TakeMFA::Core::verify('tester',$third,$ch->{nonce},$recovery)->{ok},'recovery code grants session');
my $fourth='tester:DDDDDDDDDDDDDDDD';$ch=TakeMFA::Core::challenge('tester',$fourth);
ok(!TakeMFA::Core::verify('tester',$fourth,$ch->{nonce},$recovery)->{ok},'recovery code is single-use');
for(1..5){TakeMFA::Core::verify('tester',$fourth,$ch->{nonce},'invalid-code');}
$clock+=30;my $new=TakeMFA::Core::code_at($p->{secret},$clock);
ok(!TakeMFA::Core::verify('tester',$fourth,$ch->{nonce},$new)->{ok},'account-wide throttle blocks even correct code during cooldown');
$clock+=181;$new=TakeMFA::Core::code_at($p->{secret},$clock);
ok(TakeMFA::Core::verify('tester',$fourth,$ch->{nonce},$new)->{ok},'cooldown expires using real clock');
$clock+=28_801;
ok(!TakeMFA::Core::verified('tester',$a),'MFA grant expires after eight hours');
ok(!TakeMFA::Core::verify('tester',$third,'old-nonce',$new)->{ok},'expired nonce cannot grant session');
my $state=do{open(my $f,'<',"$dir/tester.json") or die;local $/;<$f>};
ok(index($state,$recovery)<0,'recovery plaintext absent from stored state');
is((stat("$dir/tester.json"))[2]&0777,0600,'secret state permissions 0600');
unlink("$dir/tester.json");
ok(!eval {TakeMFA::Core::verified('tester',$a);1},'missing protected secret fails closed');
ok($policy->fails($ctx),'policy fails closed when protected state is missing');
ok(TakeMFA::Core::reset('tester'),'root recovery resets only selected factor');
ok(!TakeMFA::Core::protected('tester'),'reset removes enforcement for selected identity');
ok(!eval {TakeMFA::Core::reset('../root');1},'reset rejects traversal');
is(TakeMFA::View::escape('<"&>'), '&lt;&quot;&amp;&gt;', 'HTML values escaped');
local $ENV{cp_security_token}='/cpsess1234567890';is(TakeMFA::View::prefix(),'/cpsess1234567890','trusted route recognized');
$ENV{cp_security_token}="/cpsess1\r\nInjected: yes";ok(!eval{TakeMFA::View::prefix();1},'header injection rejected');
sub parse_form {
    my ($body)=@_;local $ENV{REQUEST_METHOD}='POST';local $ENV{CONTENT_TYPE}='application/x-www-form-urlencoded';local $ENV{CONTENT_LENGTH}=length($body);
    open(my $input,'<',\$body) or die $!;local *STDIN=$input;
    return TakeMFA::View::post_fields();
}
is(parse_form('action=confirm&nonce=ABC&code=005924')->{code},'005924','POST parser preserves leading zeroes');
is(parse_form('action=confirm&nonce=A%32B&code=005924')->{nonce},'A2B','native URL decoder handles encoded form');
ok(!eval{parse_form('code=1&code=2');1},'duplicate form fields rejected');
ok(!eval{parse_form('code=%XX');1},'malformed percent escape rejected');
ok(!eval{parse_form('code=%00');1},'NUL rejected from submitted values');
ok(!eval{parse_form('user=root&code=005924');1},'client cannot select target identity');
TakeMFA::Core::_write($dir.'/settings.json',{mode=>'available'});
my $race_a='racer:AAAAAAAAAAAAAAAA';my $race_b='racer:BBBBBBBBBBBBBBBB';my $race_c='racer:CCCCCCCCCCCCCCCC';
my $race_setup=TakeMFA::Core::begin_enrollment('racer',$race_a);
my $race_confirm=TakeMFA::Core::confirm_enrollment('racer',$race_a,$race_setup->{nonce},TakeMFA::Core::code_at($race_setup->{secret},$clock));
ok($race_confirm->{ok},'isolated concurrency fixture enrolled');
my $race_nonce_b=TakeMFA::Core::challenge('racer',$race_b)->{nonce};
my $race_nonce_c=TakeMFA::Core::challenge('racer',$race_c)->{nonce};
$clock+=30;my $race_code=TakeMFA::Core::code_at($race_setup->{secret},$clock);
my @children;
for my $args ([$race_b,$race_nonce_b],[$race_c,$race_nonce_c]) {
    my $pid=fork();die 'fork failed' unless defined($pid);
    if (!$pid) {
        my $granted=eval{TakeMFA::Core::verify('racer',$args->[0],$args->[1],$race_code)->{ok}};
        POSIX::_exit($@?2:($granted?0:1));
    }
    push @children,$pid;
}
my @outcomes;for my $pid (@children){waitpid($pid,0);push @outcomes,$?>>8;}
is(scalar(grep {$_==0} @outcomes),1,'concurrent same TOTP grants exactly one session');
is(scalar(grep {$_==1} @outcomes),1,'concurrent replay rejected atomically');
TakeMFA::Core::reset('racer');
require(($ENV{TAKE_MFA_TEST_PACKAGE}//"$FindBin::Bin/..").'/take_mfa.pm');
{
    package TakeMFATestCaller;
    our @ISA=('Cpanel::Admin::Modules::Cpanel::take_mfa');
    sub get_caller_username {return 'tester';}
}
my $caller=bless {},'TakeMFATestCaller';
my @actions=sort(Cpanel::Admin::Modules::Cpanel::take_mfa::_actions());
is_deeply(\@actions,[qw(CHALLENGE CONSOLE STATUS VERIFY)],'console action is separate from narrow policy actions');
ok(!eval{$caller->STATUS('root','root:AAAAAAAAAAAAAAAA','session');1} && $@ =~ /Account mismatch/,'reseller cannot claim root through helper');
ok(!eval{$caller->CHALLENGE([],undef);1} && $@ =~ /Invalid caller/,'helper rejects reference identity');
ok(!eval{$caller->STATUS('tester',$a,'session');1} && $@ =~ /Hosting account required/,'non-hosted identity cannot use privileged helper');
my @parents=Cpanel::Admin::Modules::Cpanel::take_mfa::_allowed_parents();
ok(!(grep {$_ eq '*'} @parents),'helper does not disable parent validation');
my $rp=TakeMFA::Core::begin_enrollment('root','root:RRRRRRRRRRRRRRRR');
my $rc=TakeMFA::Core::confirm_enrollment('root','root:RRRRRRRRRRRRRRRR',$rp->{nonce},TakeMFA::Core::code_at($rp->{secret},$clock));
my $pos={appname=>'cpaneld',user=>'otheracct',is_possessed=>1,possessor=>'root',authtype=>'session',session_id=>'otheracct:SSSSSSSSSSSSSSSS'};
ok($policy->fails($pos),'root password possession of an unenrolled account still requires root factor');
my $bound=TakeMFA::Core::subject_session('root',$pos->{session_id});
my $posnonce=TakeMFA::Core::challenge('root',$bound)->{nonce};
ok(TakeMFA::Core::verify('root',$bound,$posnonce,$rc->{recovery_codes}[0])->{ok},'possessed native session can be verified for its authenticating principal');
ok(!$policy->fails($pos),'verified possessor session allowed');
ok($policy->fails({%$pos,session_id=>'otheracct:TTTTTTTTTTTTTTTT'}),'possessor grant does not carry to another session');
ok(!eval{$caller->_subject('tester',$a,'root');1},'helper rejects unproven possessor identity');
done_testing();
