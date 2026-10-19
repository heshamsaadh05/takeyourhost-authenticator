# Changelog

## 2.1.2

- Replace the fixed cPanel version minimum with native capability checks. No claim of universal version support: Jupiter, Python 3.9+, the required native interfaces and graceful reload remain mandatory.
- Check native registration helpers and Python version before mutation; preserve all existing permission, state, clock and legacy-installation guards.
- Add simulated-version and missing-capability regression tests. Simulated versions are not live compatibility certification.
- Correct new-install, existing-download and managed-update commands; run native isolated tests before mutation.
- Record user-confirmed successful 2.1.1 installation and 146 native checks on cPanel 126.0.78; actual login/QR flows still need confirmation on that version.

## 2.1.1

- Permit cPanel 126+ after native capability, permissions, state and graceful-reload checks. Previously the installer stopped at a fixed minimum of 134.
- Expand read-only native interface checks and add version-gate regression tests.
- Keep cPanel 126-132 support provisional: a user-supplied 126.0.78 probe confirmed module loading and clock availability, not successful login flows. No native security checks, factor state or account credentials are bypassed or reset.
- Document public HTTPS download, fail-fast command chains and support contacts.

## 2.1.0

- Initial packaged release with Arabic documentation, private local QR generation and a reversible installer.
