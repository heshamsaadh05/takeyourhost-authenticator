# Changelog

## 2.1.1

- Permit cPanel 126+ after native capability, permissions, state and graceful-reload checks. Previously the installer stopped at a fixed minimum of 134.
- Expand read-only native interface checks and add version-gate regression tests.
- Keep cPanel 126-132 support provisional: a user-supplied 126.0.78 probe confirmed module loading and clock availability, not successful login flows. No native security checks, factor state or account credentials are bypassed or reset.
- Document public HTTPS download, fail-fast command chains and support contacts.

## 2.1.0

- Initial packaged release with Arabic documentation, private local QR generation and a reversible installer.
