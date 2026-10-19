#!/usr/bin/env python3
"""Root-only, reversible cPanel installation. No site edits or hard restarts."""
import argparse,contextlib,datetime,hashlib,json,os,re,shutil,signal,stat,subprocess,sys,uuid
from pathlib import Path

PACKAGE=Path(__file__).resolve().parents[1]
REL_FILES={
    **{f'lib/TakeMFA/{n}.pm':(f'/usr/local/cpanel/3rdparty/take-mfa/lib/TakeMFA/{n}.pm',0o644) for n in ['Core','View','QR','Manage','Ownership','Console','Controller']},
    'TakeMFA.pm':('/usr/local/cpanel/Cpanel/Security/Policy/TakeMFA.pm',0o644),
    'take_mfa.pm':('/usr/local/cpanel/Cpanel/Admin/Modules/Cpanel/take_mfa.pm',0o644),
    'cpanel-api.pm':('/usr/local/cpanel/Cpanel/API/TakeMFA.pm',0o644),
    'take-mfa.cgi':('/usr/local/cpanel/whostmgr/docroot/cgi/take-mfa.cgi',0o755),
    'take-mfa-admin':('/usr/local/sbin/take-mfa-admin',0o700),
    'console.css':('/usr/local/cpanel/3rdparty/take-mfa/console.css',0o644),
    'qr-svg.py':('/usr/local/cpanel/3rdparty/take-mfa/qr-svg.py',0o644),
    'vendor/qrcodegen.py':('/usr/local/cpanel/3rdparty/take-mfa/vendor/qrcodegen.py',0o644),
    'cpanel/index.live.pl':('/usr/local/cpanel/base/frontend/jupiter/take_mfa/index.live.pl',0o755),
}
GENERATED=['/var/cpanel/apps/take-mfa.conf','/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_take_mfa.conf','/usr/local/cpanel/base/frontend/jupiter/assets/application_icons/take_mfa.svg']

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def safe_existing(path,private=False):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_ISLNK(s.st_mode):raise RuntimeError(f'Unsafe file: {path}')
    if s.st_mode & (0o077 if private else 0o022):raise RuntimeError(f'Unsafe permissions: {path}')
def atomic_bytes(path,data,mode):
    missing=[];parent=path.parent
    while not parent.exists():missing.append(parent);parent=parent.parent
    for p in reversed(missing):p.mkdir(mode=0o755);p.chmod(0o755)
    tmp=path.with_name(path.name+'.take-mfa-'+uuid.uuid4().hex)
    try:
        fd=os.open(str(tmp),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        tmp.chmod(mode);os.replace(tmp,path)
    finally:
        if tmp.exists():tmp.unlink()
def write_json(path,value):atomic_bytes(path,json.dumps(value,indent=2,sort_keys=True).encode()+b'\n',0o600)

class Manager:
    def __init__(self,package=PACKAGE,prefix=Path('/')):
        # Prefix is a dependency-injection seam for tests, not a CLI/env option.
        self.package=Path(package);self.prefix=Path(prefix)
        self.state=self.path('/var/cpanel/take-mfa');self.record=self.state/'installation.json'
        self.perl=self.path('/usr/local/cpanel/3rdparty/bin/perl')
        self.files={self.path(dst):(self.package/src,mode) for src,(dst,mode) in REL_FILES.items()}
        self.generated=[self.path(p) for p in GENERATED]
    def path(self,value):return self.prefix/str(value).lstrip('/')
    def run(self,args,public=False):
        p=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=90,umask=0o022 if public else -1)
        if p.returncode:raise RuntimeError(f'Command failed ({p.returncode}): {Path(str(args[0])).name}. Review local cPanel logs; no forced restart attempted.')
        return p.stdout
    def native(self,action,value=None):
        args=[self.perl,self.package/'scripts/native.pl',action]
        if value is not None:args.append('unset' if value is None else str(value))
        result=self.run(args)
        return json.loads(result) if action in ['preflight','get-policy'] else None
    def policy(self,value):self.native('set-policy','unset' if value is None else str(value))
    def verify_reload(self):
        pidfile=self.path('/var/run/cpsrvd.pid')
        pid=int(pidfile.read_text().strip());text=self.path(f'/proc/{pid}/status').read_text()
        match=re.search(r'^SigCgt:\s+([0-9a-fA-F]+)',text,re.M)
        if pid<=1 or not match or not(int(match[1],16)&(1<<(signal.SIGUSR1-1))):raise RuntimeError('Graceful reload unavailable. No hard restart attempted.')
    def reload(self):
        self.verify_reload()
        self.native('reload')
    def load_record(self):
        if not self.record.exists():return None
        safe_existing(self.record,True);r=json.loads(self.record.read_text())
        if r.get('schema')!=1:raise RuntimeError('Unsupported installation record')
        return r
    def preflight(self,action):
        if os.name!='posix' or os.geteuid()!=0:raise RuntimeError('Run on Linux as root over SSH')
        if sys.version_info<(3,9):raise RuntimeError('Python 3.9 or newer required; no system packages were changed')
        version=self.path('/usr/local/cpanel/version')
        if not version.is_file() or not self.perl.is_file():raise RuntimeError('cPanel is not installed')
        m=re.fullmatch(r'\s*(?:11\.)?([1-9]\d*)\.\d+(?:\.\d+)*\s*',version.read_text())
        if not m:raise RuntimeError('Cannot identify cPanel version; native compatibility must be reviewed')
        self.cpanel_major=int(m[1])
        print(f'NOTICE: cPanel {self.cpanel_major}: checking native capabilities, not a fixed version minimum. Login-flow verification is still required. Keep root SSH open.',file=sys.stderr)
        if not self.path('/usr/local/cpanel/base/frontend/jupiter').is_dir():raise RuntimeError('Jupiter theme required')
        for name,executable in [('bin/register_appconfig',True),('bin/unregister_appconfig',True),('scripts/install_plugin',False),('scripts/uninstall_plugin',False)]:
            helper=self.path('/usr/local/cpanel/'+name)
            if not helper.is_file() or (executable and not os.access(helper,os.X_OK)):raise RuntimeError(f'Required native plugin helper unavailable: {name}')
        for f in [self.package/'VERSION',self.package/'take-mfa.conf',self.package/'cpanel/install.json',self.package/'scripts/native.pl',*(src for src,_ in self.files.values())]:
            if not f.is_file() or f.is_symlink():raise RuntimeError(f'Missing or symlinked package file: {f.name}')
        if not re.fullmatch(r'\d+\.\d+\.\d+\s*',(self.package/'VERSION').read_text()):raise RuntimeError('Invalid package version')
        for dest in [*self.files,*self.generated,self.state,self.path('/var/backups/takeyourhost-authenticator'),self.path('/run/lock/take-mfa-installer.lock')]:
            for p in [dest,*dest.parents]:
                if p==self.prefix:break
                if p.is_symlink():raise RuntimeError(f'Symlinked destination refused: {p}')
                if p.exists():
                    s=p.stat()
                    if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError(f'Untrusted destination: {p}')
        if self.state.exists():
            if not self.state.is_dir() or self.state.stat().st_mode&0o077:raise RuntimeError('State directory must be root-only mode 0700')
            for name in ['enabled.json','settings.json']:
                f=self.state/name;safe_existing(f,True)
                if not isinstance(json.loads(f.read_text()),dict):raise RuntimeError('Invalid existing factor state')
            for user,enabled in json.loads((self.state/'enabled.json').read_text()).items():
                if not re.fullmatch(r'[a-z][a-z0-9_]{0,31}',user):raise RuntimeError('Invalid enrolled identity')
                if enabled:
                    f=self.state/(user+'.json');safe_existing(f,True)
                    if not re.fullmatch(r'[A-Z2-7]{32}',json.loads(f.read_text()).get('secret','')):raise RuntimeError('Invalid enrolled secret state; restore/review via SSH first')
        metadata=self.native('preflight')
        import time
        if not metadata.get('ok') or abs(metadata['time']-time.time())>5:raise RuntimeError('Native clock is unavailable or differs from the system clock')
        self.verify_reload()
        old=self.load_record()
        if not(old and old.get('installed')) and self.native('get-policy')['value'] not in [None,0,'0','']:
            raise RuntimeError('Unmanaged existing TakeMFA policy setting; review manual/legacy installation')
        if action in ['update','uninstall'] and not(old and old.get('installed')):raise RuntimeError('No managed installation found; do not overwrite a legacy/manual installation')
        if action=='install' and old and old.get('installed'):raise RuntimeError('Already installed; use update.sh')
        tracked=old.get('files',{}) if old and old.get('installed') else {}
        for dest in self.files:
            key=str(dest.relative_to(self.prefix))
            if tracked:
                if key in tracked:
                    if not dest.is_file() or digest(dest)!=tracked[key]['sha256']:raise RuntimeError(f'Local change or missing managed file: {key}')
                elif dest.exists():raise RuntimeError(f'New destination already occupied: {key}')
            elif dest.exists():raise RuntimeError(f'Existing file refused: {dest}; review the legacy/manual installation first')
        if not tracked and any(p.exists() for p in self.generated):raise RuntimeError('Existing plugin registration found; manual migration requires review')
        return old
    @contextlib.contextmanager
    def lock(self):
        import fcntl
        path=self.path('/run/lock/take-mfa-installer.lock');path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(str(path),os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            if os.fstat(fd).st_uid!=0:raise RuntimeError('Unsafe installer lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
        finally:os.close(fd)
    def snapshot(self,old):
        stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
        base=self.path('/var/backups/takeyourhost-authenticator')
        if base.exists() and (base.is_symlink() or base.stat().st_uid!=0 or base.stat().st_mode&0o077):raise RuntimeError('Backup directory must be root-only')
        base.mkdir(parents=True,exist_ok=True,mode=0o700);base.chmod(0o700)
        backup=base/stamp;backup.mkdir(mode=0o700);before={}
        for p in [*self.files,*self.generated,self.record]:
            before[p]=None
            if p.exists():
                safe_existing(p)
                dest=backup/'files'/p.relative_to(self.prefix);atomic_bytes(dest,p.read_bytes(),0o600)
                before[p]=(dest,p.stat().st_mode&0o777)
        if self.state.exists():
            # Contains TOTP secrets: remains under a root-only backup directory.
            shutil.copytree(self.state,backup/'private-state',ignore=shutil.ignore_patterns('global.lock','*.tmp'))
        cpconf=self.path('/var/cpanel/cpanel.config')
        if cpconf.exists():atomic_bytes(backup/'cpanel.config.reference-only',cpconf.read_bytes(),0o600)
        return backup,before
    def register(self):
        self.run([self.path('/usr/local/cpanel/bin/register_appconfig'),self.package/'take-mfa.conf'])
        self.run([self.perl,self.path('/usr/local/cpanel/scripts/install_plugin'),self.package/'cpanel','--theme','jupiter'],public=True)
        for p in self.generated[1:]:
            safe_existing(p);p.chmod(0o644)
    def unregister(self):
        self.run([self.path('/usr/local/cpanel/bin/unregister_appconfig'),'take-mfa'])
        self.run([self.perl,self.path('/usr/local/cpanel/scripts/uninstall_plugin'),self.package/'cpanel','--theme','jupiter'],public=True)
    def rollback(self,before,policy_before,had_install):
        # Keep private factor data; never roll users back to an earlier secret.
        self.policy(policy_before)
        for dest,value in before.items():
            if value:atomic_bytes(dest,value[0].read_bytes(),value[1])
        self.reload()  # On failure, retain new modules so old workers can still load them.
        if had_install:self.register()
        else:self.unregister()
        for dest,value in before.items():
            if value is None and dest.exists():dest.unlink()
        self.reload()
    def apply(self,action,old):
        with self.lock():
            # Recheck under the installer lock; do not race another installer.
            current=self.load_record()
            if current!=old:raise RuntimeError('Installation state changed; rerun preflight')
            backup,before=self.snapshot(old)
            previous=self.native('get-policy')['value']
            try:
                if action=='uninstall':
                    self.policy(old.get('policy_before'));self.reload();self.unregister();self.reload()
                    for p in self.files:p.unlink()
                    record={**old,'installed':False,'last_backup':str(backup)}
                else:
                    if not self.state.exists():self.state.mkdir(mode=0o700);self.state.chmod(0o700)
                    for name,value in [('enabled.json',{}),('settings.json',{'mode':'available'})]:
                        if not(self.state/name).exists():write_json(self.state/name,value)
                    for dest,(src,mode) in self.files.items():atomic_bytes(dest,src.read_bytes(),mode)
                    for dest in self.files:
                        if dest.suffix in ['.pm','.pl','.cgi']:self.run([self.perl,'-I/usr/local/cpanel','-I'+str(self.path('/usr/local/cpanel/3rdparty/take-mfa/lib')),'-c',dest])
                    self.register();self.policy(1);self.reload()
                    record={'schema':1,'installed':True,'version':(self.package/'VERSION').read_text().strip(),'policy_before':old.get('policy_before') if old else previous,'last_backup':str(backup),'files':{str(p.relative_to(self.prefix)):{'sha256':digest(p),'mode':oct(mode)} for p,(_,mode) in self.files.items()}}
                write_json(self.record,record)
            except Exception as error:
                try:self.rollback(before,previous,bool(old and old.get('installed')))
                except Exception as rollback_error:raise RuntimeError(f'Operation failed. Automatic rollback needs manual SSH review: {rollback_error}. Protected backup: {backup}') from error
                raise RuntimeError(f'Operation failed; previous installation restored. Protected backup: {backup}') from error
            return {'operation':action,'version':record['version'],'backup':str(backup),'installed':record['installed'],'factor_data_preserved':True,'reload':'graceful-only'}

def main():
    parser=argparse.ArgumentParser(description='TakeYourHost Authenticator installer. No hard restarts; no website changes.')
    parser.add_argument('action',choices=['install','update','uninstall','status']);parser.add_argument('--yes',action='store_true');parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args();manager=Manager()
    if args.action=='status':
        if os.name!='posix' or os.geteuid()!=0:raise RuntimeError('Root required')
        r=manager.load_record();print(json.dumps({'managed_installation':bool(r and r.get('installed')),'version':r.get('version') if r else None,'factor_directory_exists':manager.state.exists()},indent=2));return
    old=manager.preflight(args.action)
    if args.dry_run:print('Preflight passed. No installation, policy change, reload, account creation or state initialization performed.');return
    if not args.yes:
        if not sys.stdin.isatty() or input(f'{args.action}: changes login security and performs graceful-only cpsrvd reload. Keep SSH open. Type YES: ')!='YES':raise RuntimeError('Cancelled; use --yes only after reviewing the documentation')
    print(json.dumps(manager.apply(args.action,old),indent=2))
if __name__=='__main__':
    os.umask(0o077)
    try:main()
    except Exception as e:print('ERROR: '+str(e),file=sys.stderr);sys.exit(1)
