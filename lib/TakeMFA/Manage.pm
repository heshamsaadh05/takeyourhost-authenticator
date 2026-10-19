package TakeMFA::Manage;
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use TakeMFA::Core ();
use TakeMFA::Ownership ();

sub dashboard {
    my ($u,$session)=@_;my $key=TakeMFA::Core::sid($u,$session);
    return TakeMFA::Core::_locked(sub {
        my $r=TakeMFA::Core::_registry();my $s=TakeMFA::Core::_state($u);my $t=TakeMFA::Core::now();
        my $cfg=TakeMFA::Core::_read("$TakeMFA::Core::ROOT/settings.json");
        $s->{management}||={};
        for my $k(keys %{$s->{management}}){delete $s->{management}{$k} if ($s->{management}{$k}{expires}//0)<=$t;}
        my @keys=sort {($s->{management}{$b}{expires}//0)<=>($s->{management}{$a}{expires}//0)} keys %{$s->{management}};
        for my $i(63..$#keys){delete $s->{management}{$keys[$i]};}
        my $m=$s->{management}{$key};
        $m={nonce=>TakeMFA::Core::random(40),expires=>$t+600} unless $m && $m->{expires}>$t;
        $s->{management}{$key}=$m;TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);
        my $p=$s->{rotation};
        my $pending=$p && ($p->{expires}//0)>$t && TakeMFA::Core::equal($p->{session},$key);
        my $out={enrolled=>$r->{$u}?1:0,paused=>$s->{paused}?1:0,cpanel_paused=>$s->{cpanel_paused}?1:0,global_enabled=>$cfg->{suspended}?0:1,nonce=>$m->{nonce},recovery_count=>scalar(@{$s->{recovery_hashes}||[]}),enrolled_at=>$s->{enrolled_at}//0};
        $out->{rotation}={secret=>$p->{secret},nonce=>$p->{nonce}} if $pending;
        $out->{accounts}=[map {{name=>$_,paused=>TakeMFA::Core::_state($_)->{paused}?1:0}} sort keys %$r] if $u eq 'root';
        $out->{clients}=[map {my $v=TakeMFA::Core::_state($_);{name=>$_,enrolled=>$r->{$_}?1:0,paused=>$v->{paused}?1:0,cpanel_paused=>$v->{cpanel_paused}?1:0}} @{TakeMFA::Ownership::clients($u)}];
        return $out;
    });
}
sub _credential {
    my ($s,$token,$t)=@_;
    return 0 if ($s->{locked_until}//0)>$t;
    my $step=TakeMFA::Core::_otp_step($s->{secret},$token,$s->{last_step},$t);
    if(defined($step)){$s->{last_step}=$step;return 1;}
    my $clean=uc($token//'');$clean =~ s/-//g;
    if($clean =~ /\A[A-Z2-7]{24}\z/){
        my $hash=sha256_hex($clean);my $found=0;
        my @left=grep {if(TakeMFA::Core::equal($_,$hash)){$found=1;0}else{1}} @{$s->{recovery_hashes}||[]};
        if($found){$s->{recovery_hashes}=\@left;return 1;}
    }
    TakeMFA::Core::_failure($s,$t);return 0;
}
sub action {
    my ($u,$session,$nonce,$token,$action)=@_;my $key=TakeMFA::Core::sid($u,$session);
    die "Invalid action\n" unless defined($action) && $action =~ /\A(?:pause|resume|pause_cpanel|resume_cpanel|rotate|cancel_rotation|recovery|global_off|global_on)\z/;
    die "Root only\n" if $action =~ /^global_/ && $u ne 'root';
    return TakeMFA::Core::_locked(sub {
        my $s=TakeMFA::Core::_state($u);my $r=TakeMFA::Core::_registry();my $t=TakeMFA::Core::now();
        my $m=$s->{management}{$key};
        return {ok=>0} unless $r->{$u} && $s->{secret} && $m && ($m->{expires}//0)>$t && TakeMFA::Core::equal($m->{nonce},$nonce);
        if($action eq 'cancel_rotation'){
            # Cancelling cannot lower security or disclose the active secret.
            delete $s->{rotation};delete $s->{management}{$key};TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);return {ok=>1};
        }
        unless(_credential($s,$token,$t)){TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);return {ok=>0};}
        my $result={ok=>1};
        if($action eq 'pause'){$s->{paused}=1;delete $s->{rotation};$s->{sessions}={};}
        elsif($action eq 'resume'){delete $s->{paused};$s->{sessions}={};TakeMFA::Core::_grant($s,$key,$t);}
        elsif($action eq 'pause_cpanel'){$s->{cpanel_paused}=1;$s->{sessions}={};}
        elsif($action eq 'resume_cpanel'){delete $s->{cpanel_paused};$s->{sessions}={};TakeMFA::Core::_grant($s,$key,$t);}
        elsif($action eq 'rotate'){$s->{rotation}={secret=>TakeMFA::Core::random(32),nonce=>TakeMFA::Core::random(40),session=>$key,expires=>$t+600};}
        elsif($action eq 'recovery'){
            my @codes=map {TakeMFA::Core::random(24)} 1..10;
            $s->{recovery_hashes}=[map {sha256_hex($_)} @codes];$result->{recovery_codes}=\@codes;
        }
        $s->{last_management_action}={action=>$action,at=>$t};delete $s->{management}{$key};
        TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);
        if($action =~ /^global_/){
            my $cfg=TakeMFA::Core::_read("$TakeMFA::Core::ROOT/settings.json");
            # State (including replay prevention) is committed before the toggle.
            $cfg->{suspended}=($action eq 'global_off')?1:0;$cfg->{changed_at}=$t;$cfg->{changed_by}=$u;
            TakeMFA::Core::_write("$TakeMFA::Core::ROOT/settings.json",$cfg);
        }
        return $result;
    });
}
sub confirm_rotation {
    my ($u,$session,$nonce,$token)=@_;my $key=TakeMFA::Core::sid($u,$session);
    return TakeMFA::Core::_locked(sub {
        my $s=TakeMFA::Core::_state($u);my $t=TakeMFA::Core::now();my $p=$s->{rotation};
        return {ok=>0} unless TakeMFA::Core::_registry()->{$u} && $p && ($p->{expires}//0)>$t && TakeMFA::Core::equal($p->{session},$key) && TakeMFA::Core::equal($p->{nonce},$nonce);
        return {ok=>0} if ($s->{locked_until}//0)>$t;
        my $step=TakeMFA::Core::_otp_step($p->{secret},$token,-1,$t);
        unless(defined($step)){TakeMFA::Core::_failure($s,$t);TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);return {ok=>0};}
        my @codes=map {TakeMFA::Core::random(24)} 1..10;
        $s->{secret}=$p->{secret};$s->{last_step}=$step;$s->{sessions}={};$s->{management}={};
        $s->{recovery_hashes}=[map {sha256_hex($_)} @codes];delete $s->{rotation};delete $s->{paused};
        $s->{enrolled_at}=$t;TakeMFA::Core::_grant($s,$key,$t);
        TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);
        return {ok=>1,recovery_codes=>\@codes};
    });
}
sub client_action {
    my ($u,$session,$nonce,$token,$target,$action)=@_;my $key=TakeMFA::Core::sid($u,$session);
    die "Invalid client action\n" unless defined($action) && $action =~ /\Aclient_(?:pause|resume)\z/;
    die "Account ownership required\n" unless TakeMFA::Ownership::owns($u,$target);
    return TakeMFA::Core::_locked(sub {
        # Recheck ownership while holding the same state lock used for changes.
        die "Account ownership required\n" unless TakeMFA::Ownership::owns($u,$target);
        my $s=TakeMFA::Core::_state($u);my $r=TakeMFA::Core::_registry();my $t=TakeMFA::Core::now();my $m=$s->{management}{$key};
        return {ok=>0} unless $r->{$u} && $r->{$target} && $s->{secret} && $m && ($m->{expires}//0)>$t && TakeMFA::Core::equal($m->{nonce},$nonce);
        unless(_credential($s,$token,$t)){TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);return {ok=>0};}
        my $client=TakeMFA::Core::_read("$TakeMFA::Core::ROOT/$target.json");
        $client->{cpanel_paused}=($action eq 'client_pause')?1:0;$client->{sessions}={};
        $client->{last_management_action}={action=>$action,by=>$u,at=>$t};
        delete $s->{management}{$key};
        TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$u.json",$s);
        TakeMFA::Core::_write("$TakeMFA::Core::ROOT/$target.json",$client);
        return {ok=>1};
    });
}
1;
