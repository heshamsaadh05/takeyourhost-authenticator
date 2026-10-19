import contextlib,importlib.util,json,os,stat,tempfile,time,unittest
from pathlib import Path
from unittest import mock
PACKAGE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('installer',PACKAGE/'scripts/manage.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FakeManager(m.Manager):
    """All destinations under a temp directory; never invokes cPanel or signals."""
    def __init__(self,prefix):
        super().__init__(PACKAGE,prefix);self.events=[];self.value=None;self.fail_once=None
        self.path('/var/cpanel').mkdir(parents=True)
    def lock(self):return contextlib.nullcontext()
    def load_record(self):return json.loads(self.record.read_text()) if self.record.exists() else None
    def native(self,action,value=None):
        self.events.append((action,value))
        if action=='get-policy':return {'value':self.value}
        if action=='preflight':return {'ok':1,'time':time.time()}
        if action=='set-policy':self.value=None if value=='unset' else int(value)
    def reload(self):
        self.events.append(('reload',None))
        if self.fail_once=='reload':self.fail_once=None;raise RuntimeError('simulated graceful failure')
    def run(self,args,public=False):
        self.events.append((str(args[0]),[str(x) for x in args[1:]]))
        if 'register_appconfig'==Path(str(args[0])).name:
            if self.fail_once=='register':self.fail_once=None;raise RuntimeError('simulated registration failure')
            m.atomic_bytes(self.generated[0],b'plugin registration',0o600)
        if any('install_plugin'==Path(str(x)).name for x in args):
            for p in self.generated[1:]:m.atomic_bytes(p,b'generated public menu',0o644)
        if any('uninstall_plugin'==Path(str(x)).name for x in args):
            for p in self.generated:
                if p.exists():p.unlink()
        return ''
    def snapshot(self,old):
        # Explicit temp-only backup for cross-platform transaction contract tests.
        backup=self.prefix/'backup'/str(len(self.events));backup.mkdir(parents=True,mode=0o700)
        before={}
        for p in [*self.files,*self.generated,self.record]:
            before[p]=None
            if p.exists():
                dest=backup/'files'/p.relative_to(self.prefix);m.atomic_bytes(dest,p.read_bytes(),0o600)
                before[p]=(dest,0o600 if p==self.record else 0o644)
        return backup,before

class Transactions(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.manager=FakeManager(Path(self.tmp.name))
        # Windows cannot express Unix UID/mode semantics; Linux preflight tests below do.
        if os.name!='posix':
            patch=mock.patch.object(m,'safe_existing',lambda *a,**k:None);patch.start();self.addCleanup(patch.stop)
    def install(self):return self.manager.apply('install',None)
    def test_install_initializes_private_state_without_enrolling_anyone(self):
        r=self.install();self.assertTrue(r['installed']);self.assertEqual(json.loads((self.manager.state/'enabled.json').read_text()),{})
        self.assertEqual(json.loads((self.manager.state/'settings.json').read_text()),{'mode':'available'})
    def test_install_copies_only_declared_destinations(self):
        self.install()
        for dest,(src,_) in self.manager.files.items():self.assertEqual(dest.read_bytes(),src.read_bytes())
    def test_install_enables_exact_policy(self):
        self.install();self.assertEqual(self.manager.value,1)
        self.assertIn(('set-policy','1'),self.manager.events)
    def test_manifest_contains_only_paths_modes_and_hashes(self):
        self.install();record=self.manager.load_record();self.assertEqual(record['schema'],1)
        self.assertEqual(set(record['files']),{str(p.relative_to(self.manager.prefix)) for p in self.manager.files})
        self.assertNotIn('secret',json.dumps(record))
    def test_update_preserves_existing_keys_and_registry_bytes(self):
        self.install();u=self.manager.state/'customer.json';m.write_json(u,{'secret':'TEST-ONLY','sessions':{}})
        m.write_json(self.manager.state/'enabled.json',{'customer':1});before=u.read_bytes();reg=(self.manager.state/'enabled.json').read_bytes()
        self.manager.apply('update',self.manager.load_record())
        self.assertEqual(before,u.read_bytes());self.assertEqual(reg,(self.manager.state/'enabled.json').read_bytes())
    def test_update_preserves_global_suspension(self):
        self.install();m.write_json(self.manager.state/'settings.json',{'mode':'available','suspended':1})
        self.manager.apply('update',self.manager.load_record());self.assertEqual(json.loads((self.manager.state/'settings.json').read_text())['suspended'],1)
    def test_update_keeps_original_preinstall_policy(self):
        self.manager.value=0;self.install();self.manager.apply('update',self.manager.load_record())
        self.assertEqual(self.manager.load_record()['policy_before'],0)
    def test_uninstall_keeps_customer_keys(self):
        self.install();u=self.manager.state/'customer.json';m.write_json(u,{'secret':'TEST-ONLY'});before=u.read_bytes()
        r=self.manager.apply('uninstall',self.manager.load_record());self.assertFalse(r['installed']);self.assertEqual(before,u.read_bytes())
    def test_uninstall_restores_absent_policy_not_global_other_settings(self):
        self.install();self.manager.apply('uninstall',self.manager.load_record());self.assertIsNone(self.manager.value)
    def test_uninstall_restores_original_zero(self):
        self.manager.value=0;self.install();self.manager.apply('uninstall',self.manager.load_record());self.assertEqual(self.manager.value,0)
    def test_uninstall_removes_managed_source(self):
        self.install();self.manager.apply('uninstall',self.manager.load_record());self.assertTrue(all(not p.exists() for p in self.manager.files))
    def test_registration_failure_rolls_back_policy_and_sources(self):
        self.manager.fail_once='register'
        with self.assertRaisesRegex(RuntimeError,'previous installation restored'):self.install()
        self.assertIsNone(self.manager.value);self.assertTrue(all(not p.exists() for p in self.manager.files))
    def test_reload_failure_has_no_forced_restart_and_rolls_back(self):
        self.manager.fail_once='reload'
        with self.assertRaisesRegex(RuntimeError,'previous installation restored'):self.install()
        self.assertIsNone(self.manager.value)
        self.assertFalse(any('restartsrv' in str(e) or '--restart' in str(e) for e in self.manager.events))
    def test_failed_update_does_not_restore_an_old_secret(self):
        self.install();u=self.manager.state/'customer.json';m.write_json(u,{'secret':'CURRENT-TEST-ONLY'})
        self.manager.fail_once='reload'
        with self.assertRaises(RuntimeError):self.manager.apply('update',self.manager.load_record())
        self.assertEqual(json.loads(u.read_text())['secret'],'CURRENT-TEST-ONLY')
    def test_concurrent_record_change_is_rejected(self):
        self.install()
        with self.assertRaisesRegex(RuntimeError,'state changed'):self.manager.apply('update',None)
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Unix root mode check')
    def test_source_modes_and_private_state(self):
        self.install();self.assertEqual(stat.S_IMODE(self.manager.state.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((self.manager.state/'settings.json').stat().st_mode),0o600)
        for p,(_,mode) in self.manager.files.items():self.assertEqual(stat.S_IMODE(p.stat().st_mode),mode)

@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:1)()==0,'Linux root-only preflight contract')
class LinuxPreflight(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.manager=FakeManager(Path(self.tmp.name))
        for path in ['/usr/local/cpanel/base/frontend/jupiter','/run/lock']:
            self.manager.path(path).mkdir(parents=True)
        self.manager.path('/usr/local/cpanel/version').write_text('11.134.0.63')
        m.atomic_bytes(self.manager.perl,b'fake perl, never executed',0o755)
        for name in ['bin/register_appconfig','bin/unregister_appconfig','scripts/install_plugin','scripts/uninstall_plugin']:
            m.atomic_bytes(self.manager.path('/usr/local/cpanel/'+name),b'fake native helper, never executed',0o755)
        pid=1234;self.manager.path('/var/run').mkdir(parents=True);self.manager.path('/var/run/cpsrvd.pid').write_text(str(pid))
        self.manager.path('/proc/1234').mkdir(parents=True);self.manager.path('/proc/1234/status').write_text('SigCgt:\t'+format(1<<(signal_number()-1),'x'))
    def test_valid_preflight_creates_no_state(self):
        self.assertIsNone(self.manager.preflight('install'));self.assertFalse(self.manager.state.exists())
    def test_version_does_not_override_native_capabilities(self):
        for version in ['11.110.0.1','11.124.0.1','11.132.0.1','11.134.0.63','11.138.0.1','140.0.1']:
            with self.subTest(version=version):
                self.manager.path('/usr/local/cpanel/version').write_text(version)
                self.assertIsNone(self.manager.preflight('install'));self.assertFalse(self.manager.state.exists())
    def test_cpanel_126_native_capability_path_creates_no_state(self):
        self.manager.path('/usr/local/cpanel/version').write_text('11.126.0.78')
        self.assertIsNone(self.manager.preflight('install'));self.assertFalse(self.manager.state.exists())
    def test_malformed_version_rejected(self):
        self.manager.path('/usr/local/cpanel/version').write_text('unknown')
        with self.assertRaisesRegex(RuntimeError,'Cannot identify cPanel'):self.manager.preflight('install')
    def test_missing_native_helper_refused_without_state(self):
        self.manager.path('/usr/local/cpanel/scripts/install_plugin').unlink()
        with self.assertRaisesRegex(RuntimeError,'helper unavailable'):self.manager.preflight('install')
        self.assertFalse(self.manager.state.exists())
    def test_missing_native_interface_refused_without_state(self):
        original=self.manager.native
        def native(action,value=None):
            if action=='preflight':raise RuntimeError('Missing native interface')
            return original(action,value)
        self.manager.native=native
        with self.assertRaisesRegex(RuntimeError,'Missing native interface'):self.manager.preflight('install')
        self.assertFalse(self.manager.state.exists())
    def test_missing_supported_theme_refused_without_state(self):
        self.manager.path('/usr/local/cpanel/base/frontend/jupiter').rmdir()
        with self.assertRaisesRegex(RuntimeError,'Jupiter'):self.manager.preflight('install')
        self.assertFalse(self.manager.state.exists())
    def test_python_below_39_refused_without_state(self):
        with mock.patch.object(m.sys,'version_info',(3,8,20)):
            with self.assertRaisesRegex(RuntimeError,'Python 3.9'):self.manager.preflight('install')
        self.assertFalse(self.manager.state.exists())
    def test_legacy_install_not_overwritten(self):
        dest=next(iter(self.manager.files));m.atomic_bytes(dest,b'legacy user file',0o644)
        with self.assertRaisesRegex(RuntimeError,'Existing file refused'):self.manager.preflight('install')
        self.assertEqual(dest.read_bytes(),b'legacy user file')
    def test_symlink_destination_rejected(self):
        dest=next(iter(self.manager.files));dest.parent.mkdir(parents=True);target=self.manager.prefix/'external';target.write_text('private');dest.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,'Symlinked'):self.manager.preflight('install')
    def test_bad_clock_rejected(self):
        original=self.manager.native
        self.manager.native=lambda action,value=None: {'ok':1,'time':0} if action=='preflight' else original(action,value)
        with self.assertRaisesRegex(RuntimeError,'clock'):self.manager.preflight('install')
    def test_unknown_update_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'No managed'):self.manager.preflight('update')
    def test_missing_graceful_handler_refused(self):
        self.manager.path('/proc/1234/status').write_text('SigCgt:\t0')
        with self.assertRaisesRegex(RuntimeError,'Graceful'):m.Manager.verify_reload(self.manager)
    def test_native_guard_allows_registered_handler_without_signal(self):m.Manager.verify_reload(self.manager)
    def test_world_writable_destination_parent_rejected(self):
        self.manager.path('/usr/local/cpanel').chmod(0o777)
        with self.assertRaisesRegex(RuntimeError,'Untrusted'):self.manager.preflight('install')
    def test_unsafe_state_rejected(self):
        self.manager.state.mkdir(parents=True);self.manager.state.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError,'0700'):self.manager.preflight('install')

def signal_number():
    import signal
    return signal.SIGUSR1
if __name__=='__main__':unittest.main()
