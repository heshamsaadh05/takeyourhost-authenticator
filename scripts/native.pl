#!/usr/local/cpanel/3rdparty/bin/perl
use strict;
use warnings;
use lib '/usr/local/cpanel';
use JSON::PP ();
my $action=shift(@ARGV)//'';
die "Root required\n" if $>!=0;
if($action eq 'preflight'){
    for my $module(qw(Cpanel::TimeHiRes Cpanel::Crypt::Utils Cpanel::Rand::Get Cpanel::Session::Restore Cpanel::Session::Load Cpanel::Security::Authn::TwoFactorAuth::Google Cpanel::SecurityPolicy::Base Cpanel::Admin::Base Cpanel::LiveAPI Cpanel::AdminBin::Call Cpanel::Config::CpConfGuard Cpanel::Config::LoadCpConf Cpanel::Config::LoadCpUserFile Cpanel::ServiceManager::Services::Cpsrvd)){
        eval "require $module;1" or die "Required module unavailable: $module\n";
    }
    die "Missing native session restore\n" unless Cpanel::Session::Restore->can('restoreSession');
    die "Missing real-time clock\n" unless Cpanel::TimeHiRes->can('time');
    my %interfaces=(
        'Cpanel::Crypt::Utils'=>[qw(eq_secure)],
        'Cpanel::Rand::Get'=>[qw(getranddata)],
        'Cpanel::Security::Authn::TwoFactorAuth::Google'=>[qw(new generate_code)],
        'Cpanel::Session::Load'=>[qw(loadSession)],
        'Cpanel::SecurityPolicy::Base'=>[qw(init)],
        'Cpanel::Admin::Base'=>[qw(_allowed_parents get_caller_username)],
        'Cpanel::AdminBin::Call'=>[qw(call)],
        'Cpanel::LiveAPI'=>[qw(new)],
        'Cpanel::Config::LoadCpUserFile'=>[qw(loadcpuserfile)],
        'Cpanel::Config::LoadCpConf'=>[qw(loadcpconf)],
        'Cpanel::Config::CpConfGuard'=>[qw(new set save release_lock)],
        'Cpanel::ServiceManager::Services::Cpsrvd'=>[qw(new restart_gracefully)],
    );
    for my $module(sort keys %interfaces){
        for my $method(@{$interfaces{$module}}){die "Missing native interface: $module\::$method\n" unless $module->can($method);}
    }
    print JSON::PP::encode_json({ok=>1,time=>Cpanel::TimeHiRes::time()});
}elsif($action eq 'get-policy'){
    require Cpanel::Config::LoadCpConf;
    my $c=Cpanel::Config::LoadCpConf::loadcpconf();
    print JSON::PP::encode_json({value=>$c->{'SecurityPolicy::TakeMFA'}});
}elsif($action eq 'set-policy'){
    my $value=shift(@ARGV)//'';die "Invalid value\n" unless $value =~ /\A(?:1|0|unset)\z/;
    require Cpanel::Config::CpConfGuard;
    my $g=Cpanel::Config::CpConfGuard->new(no_validate=>1);
    if($value eq 'unset'){delete $g->{'data'}->{'SecurityPolicy::TakeMFA'};}
    else{$g->set('SecurityPolicy::TakeMFA',int($value));}
    $g->save();$g->release_lock();
}elsif($action eq 'reload'){
    require Cpanel::ServiceManager::Services::Cpsrvd;
    my $s=Cpanel::ServiceManager::Services::Cpsrvd->new(service=>'cpsrvd',verbose=>0);
    # Direct graceful method only. No wrapper that could fall back to a hard restart.
    exit($s->restart_gracefully()?0:21);
}else{die "Unknown native operation\n";}
