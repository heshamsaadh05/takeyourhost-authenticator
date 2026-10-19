# Security model and reporting

This is custom, security-sensitive software, not a cPanel-certified product or
an independently audited authentication system. Test on staging and retain an
authenticated root SSH session before changing login security.

## Protected surfaces

The policy covers enrolled users' interactive WHM and cPanel sessions. Native
browser sessions, including newly issued SSO sessions, do not inherit another
session's verification. The authenticating principal is used for administrator
possession contexts. Reseller customer controls require fresh proof from the
reseller and a server-side current-owner check. Customers enroll their own apps.

TOTP uses SHA-1, six digits and 30-second steps with a one-step tolerance.
Accepted steps cannot be replayed for that account. Session grants last eight
hours; form nonces last ten minutes. Five failed attempts trigger a three-minute
cooldown. Recovery codes are random, single-use and stored as hashes.

## Deliberate exclusions

- API tokens are a separate noninteractive mechanism. Restrict and rotate them.
- SSH, FTP, Webmail, SMTP/IMAP and website traffic are not given a factor.
- The plugin cannot protect a server already controlled by root, a privileged
  API-token holder, or an attacker holding a fully verified live session.
- The plugin does not repair a license, a tampered runtime, malware or server time.
- Native cPanel 2FA is neither disabled nor replaced. If configured, it may impose
  another challenge. This installer never resets native factors.

## Secrets and backups

`/var/cpanel/take-mfa` is root-only (0700), JSON files are 0600. TOTP secrets must
be recoverable to validate codes and are **not encrypted at rest** by this plugin.
Protect root access and disk/backups accordingly. QR generation happens locally
with stdin to the renderer; no secret-bearing external QR URL or CDN is used.

Installation backups under `/var/backups/takeyourhost-authenticator` include
private factor data. Keep them root-only and exclude them from Git and support
attachments. Update preserves current state. Uninstall retains factor data and
does not ask for a recursive deletion or silently erase recovery material.

## Safe operations

The installer rejects unsupported versions, missing native modules, unsafe
symlinks/permissions, unknown existing plugin files and modified managed files.
It backs up affected files before mutation and uses only the native direct
graceful reload method. It never invokes a restart wrapper with a hard fallback.
If graceful rollback fails, retain SSH access and review the protected backup;
do not use generic global 2FA-disable commands or restore a whole old cpanel.config.

An initial enrollment relies on the existing authenticated first-factor session.
Secure that account/device before enrollment. Never upload QR images, setup keys,
recovery codes, passwords, session cookies or server incident logs to issues.

Report vulnerabilities privately to the repository owner through GitHub. Do not
test against third-party servers. Supported/tested scope is documented in README.
