# Third-party software

`vendor/qrcodegen.py` is Project Nayuki QR Code generator, release v1.8.0.

Source: https://github.com/nayuki/QR-Code-generator/tree/v1.8.0/python

Vendored file SHA-256:
`b089855caf16185c61421ea4927c1b213cf9468940d71fa8ab11ef83662dcc84`

It is distributed under the MIT License. The complete notice and license text
remain at the beginning of the vendored file. Preserve them when redistributing.

Other runtime functionality uses the cPanel Perl modules already installed on
the server. No cPanel proprietary source files or server binaries are redistributed
in this repository. The files named under `Cpanel::...` here are custom extension
modules, not copies of bundled cPanel modules.

Pillow and zxing-cpp are optional test dependencies only, not production QR
dependencies. Their own distribution licenses apply.
