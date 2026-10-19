package TakeMFA::Core;
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock O_NOFOLLOW);
use JSON::PP ();
use Digest::SHA qw(sha256_hex);
use Cpanel::Crypt::Utils ();
use Cpanel::Rand::Get ();
use Cpanel::TimeHiRes ();
use Cpanel::Security::Authn::TwoFactorAuth::Google ();

our $ROOT = '/var/cpanel/take-mfa';
our $CLOCK; # Localized only by the offline tests; never populated from a request.
my $JSON = JSON::PP->new->canonical(1)->utf8(1);
sub now { return defined($CLOCK) ? $CLOCK->() : Cpanel::TimeHiRes::time(); }
sub username {
    my ($u)=@_; die "Invalid identity\n" unless defined($u) && $u =~ /\A[a-z][a-z0-9_]{0,31}\z/; return $u;
}
sub sid {
    my ($u,$s)=@_;username($u);
    die "Invalid session\n" unless defined($s) && length($s)<=320;
    $s =~ s/,[0-9a-fA-F]{32,128}\z//;
    die "Invalid session\n" unless $s =~ /\A\Q$u\E:[A-Za-z0-9_-]{16,64}(?::[A-Za-z0-9_.:-]+)?\z/;
    return sha256_hex($s);
}
sub random { return Cpanel::Rand::Get::getranddata($_[0],['A'..'Z',2..7]); }
sub subject_session {
    my ($actor,$session)=@_;username($actor);
    my ($owner)=($session//'') =~ /\A([a-z][a-z0-9_]{0,31}):/;
    die "Invalid session\n" unless $owner;
    my $hash=sid($owner,$session);
    return $owner eq $actor ? $session : $actor.':'.substr($hash,0,63);
}
sub equal { return defined($_[0]) && defined($_[1]) && length($_[0])==length($_[1]) && Cpanel::Crypt::Utils::eq_secure($_[0],$_[1]); }
sub _rootdir {
    die "Root privilege required\n" if $> != 0;
    my @s=lstat($ROOT);
    die "Unsafe state directory\n" unless @s && -d _ && !-l _ && $s[4]==0 && ($s[2]&077)==0;
}
sub _read {
    my ($file)=@_;
    sysopen(my $fh,$file,O_RDONLY|O_NOFOLLOW) or die "State unavailable\n";
    my @s=stat($fh);
    die "Unsafe state file\n" unless -f $fh && $s[4]==0 && ($s[2]&077)==0 && $s[7]<=4_000_000;
    my $raw=do {local $/;<$fh>};close($fh);
    my $value=$JSON->decode($raw);
    die "Invalid state\n" unless ref($value) eq 'HASH';return $value;
}
sub _write {
    my ($file,$data)=@_;
    my $tmp=$file.'.'.random(24).'.tmp';
    sysopen(my $fh,$tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600) or die "State unavailable\n";
    my $raw=$JSON->encode($data);
    eval { print {$fh} $raw or die "Write failed\n";close($fh) or die "Close failed\n";rename($tmp,$file) or die "Commit failed\n";1 } or do {unlink($tmp);die "State commit failed\n";};
}
sub _locked {
    my ($cb)=@_;_rootdir();
    sysopen(my $lock,"$ROOT/global.lock",O_RDWR|O_CREAT|O_NOFOLLOW,0600) or die "State lock unavailable\n";
    my @s=stat($lock);die "Unsafe lock\n" unless -f $lock && $s[4]==0 && ($s[2]&077)==0;
    flock($lock,LOCK_EX) or die "State lock unavailable\n";
    my ($ret,$error);eval {$ret=$cb->();1} or $error=$@;
    close($lock);die $error if $error;return $ret;
}
sub _registry { return _read("$ROOT/enabled.json"); }
sub _state { my ($u)=@_;return -e "$ROOT/$u.json" ? _read("$ROOT/$u.json") : {sessions=>{}}; }
sub protected {
    my ($u,$app)=@_;username($u);_rootdir();my $r=_registry();
    return 0 if _read("$ROOT/settings.json")->{suspended};
    return 0 unless $r->{$u};
    # Missing enrolled state is an error, never a way to bypass the factor.
    my $s=_read("$ROOT/$u.json");return 0 if $s->{paused};
    return 0 if ($app//'') eq 'cpaneld' && $s->{cpanel_paused};return 1;
}
sub enrollment_allowed {
    my ($u)=@_;username($u);_rootdir();my $config=_read("$ROOT/settings.json");
    return ($config->{mode}//'') eq 'available' || (($config->{mode}//'') eq 'pilot' && ($config->{pilot_user}//'') eq $u);
}
sub _trim {
    my ($s,$t)=@_;$s->{sessions}||={};
    for my $key (keys %{$s->{sessions}}) {
        my $x=$s->{sessions}{$key};
        delete $s->{sessions}{$key} if ($x->{verified_until}//$x->{expires}//0)<$t;
    }
    my @keys=sort {($s->{sessions}{$b}{verified_until}//$s->{sessions}{$b}{expires}//0)<=>($s->{sessions}{$a}{verified_until}//$s->{sessions}{$a}{expires}//0)} keys %{$s->{sessions}};
    for my $i (64..$#keys) {delete $s->{sessions}{$keys[$i]};}
}
sub verified {
    my ($u,$session)=@_;my $key=sid($u,$session);_rootdir();
    return 0 unless _registry()->{$u};
    die "Protected account state missing\n" unless -e "$ROOT/$u.json";
    my $s=_read("$ROOT/$u.json");
    die "Protected account secret missing\n" unless $s->{secret};
    return ($s->{sessions}{$key}{verified_until}//0)>now()?1:0;
}
sub challenge {
    my ($u,$session)=@_;my $key=sid($u,$session);
    return _locked(sub {
        die "Account not enrolled\n" unless _registry()->{$u};
        die "Protected account state missing\n" unless -e "$ROOT/$u.json";
        my $s=_read("$ROOT/$u.json");my $t=now();_trim($s,$t);
        my $entry=$s->{sessions}{$key};
        return {verified=>1} if ($entry->{verified_until}//0)>$t;
        $entry={nonce=>random(40),expires=>$t+600} unless $entry && ($entry->{expires}//0)>$t;
        $s->{sessions}{$key}=$entry;_write("$ROOT/$u.json",$s);
        return {nonce=>$entry->{nonce},locked=>($s->{locked_until}//0)>$t?1:0};
    });
}
sub code_at {
    my ($secret,$t)=@_;
    my $auth=Cpanel::Security::Authn::TwoFactorAuth::Google->new({secret=>$secret,issuer=>'TakeYourHost WHM',account_name=>'test'});
    return $auth->generate_code(int($t));
}
sub _otp_step {
    my ($secret,$token,$last,$t)=@_;
    return unless defined($token) && $token =~ /\A[0-9]{6}\z/;
    my $step=int($t/30);
    for my $candidate ($step-1,$step,$step+1) {
        next if $candidate<=($last//-1);
        return $candidate if equal(code_at($secret,$candidate*30),$token);
    }
    return;
}
sub _failure {
    my ($s,$t)=@_;
    $s->{attempts}=0 if ($s->{attempt_window}//0)+300<$t;
    $s->{attempt_window}=$t unless $s->{attempts};
    ++$s->{attempts};
    if ($s->{attempts}>=5) {$s->{locked_until}=$t+180;$s->{attempts}=0;}
}
sub _grant {
    my ($s,$key,$t)=@_;$s->{sessions}{$key}={verified_until=>$t+28_800};
    $s->{attempts}=0;delete $s->{locked_until};_trim($s,$t);
}
sub verify {
    my ($u,$session,$nonce,$token)=@_;my $key=sid($u,$session);
    return _locked(sub {
        die "Account not enrolled\n" unless _registry()->{$u};
        die "Protected account state missing\n" unless -e "$ROOT/$u.json";
        my $s=_read("$ROOT/$u.json");my $t=now();my $e=$s->{sessions}{$key};
        return {ok=>0} if ($s->{locked_until}//0)>$t;
        # Require a live, session-bound form nonce even for recovery codes.
        return {ok=>0} unless $e && ($e->{expires}//0)>$t && equal($e->{nonce},$nonce);
        my $step=_otp_step($s->{secret},$token,$s->{last_step},$t);my $recovery=0;
        if (!defined($step) && defined($token)) {
            my $clean=uc($token);$clean =~ s/-//g;
            if ($clean =~ /\A[A-Z2-7]{24}\z/) {
                my $hash=sha256_hex($clean);my @remaining;
                for my $stored (@{$s->{recovery_hashes}||[]}) {
                    if (equal($stored,$hash)) {$recovery=1;} else {push @remaining,$stored;}
                }
                $s->{recovery_hashes}=\@remaining if $recovery;
            }
        }
        if (defined($step) || $recovery) {
            $s->{last_step}=$step if defined($step);_grant($s,$key,$t);
            _write("$ROOT/$u.json",$s);return {ok=>1,recovery=>$recovery};
        }
        _failure($s,$t);_write("$ROOT/$u.json",$s);return {ok=>0};
    });
}
sub begin_enrollment {
    my ($u,$session)=@_;my $key=sid($u,$session);
    die "Enrollment unavailable\n" unless enrollment_allowed($u);
    return _locked(sub {
        return {enabled=>1} if _registry()->{$u};
        my $s=_state($u);my $t=now();my $p=$s->{pending};
        if (!$p || ($p->{expires}//0)<=$t || !equal($p->{session},$key)) {
            $p={secret=>random(32),nonce=>random(40),session=>$key,expires=>$t+600};$s->{pending}=$p;
        }
        _write("$ROOT/$u.json",$s);
        return {enabled=>0,secret=>$p->{secret},nonce=>$p->{nonce}};
    });
}
sub confirm_enrollment {
    my ($u,$session,$nonce,$token)=@_;my $key=sid($u,$session);
    die "Enrollment unavailable\n" unless enrollment_allowed($u);
    return _locked(sub {
        my $r=_registry();return {ok=>0} if $r->{$u};
        my $s=_state($u);my $p=$s->{pending};my $t=now();
        return {ok=>0} if ($s->{locked_until}//0)>$t;
        return {ok=>0} unless $p && ($p->{expires}//0)>$t && equal($p->{session},$key) && equal($p->{nonce},$nonce);
        my $step=_otp_step($p->{secret},$token,-1,$t);
        if (!defined($step)) {_failure($s,$t);_write("$ROOT/$u.json",$s);return {ok=>0};}
        my @codes=map {random(24)} 1..10;
        $s={secret=>$p->{secret},last_step=>$step,recovery_hashes=>[map {sha256_hex($_)} @codes],sessions=>{},enrolled_at=>$t};
        _grant($s,$key,$t);
        # Commit the secret first. Registry commit is the enforcement boundary.
        _write("$ROOT/$u.json",$s);$r->{$u}=1;_write("$ROOT/enabled.json",$r);
        return {ok=>1,recovery_codes=>\@codes};
    });
}
sub reset {
    my ($u)=@_;username($u);
    return _locked(sub {my $r=_registry();delete $r->{$u};_write("$ROOT/enabled.json",$r);unlink("$ROOT/$u.json") if -e "$ROOT/$u.json";return 1;});
}
sub status { _rootdir();my $r=_registry();return [sort keys %$r]; }
1;
