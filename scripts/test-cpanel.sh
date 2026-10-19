#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ $EUID -ne 0 || ! -x /usr/local/cpanel/3rdparty/bin/perl ]]; then
  echo 'Run as root on a compatible cPanel server. Tests use temporary state only.' >&2
  exit 1
fi
export TAKE_MFA_TEST_PACKAGE="$PWD"
perl_bin=/usr/local/cpanel/3rdparty/bin/perl
"$perl_bin" -I"$PWD/lib" -I/usr/local/cpanel tests/core.t
"$perl_bin" -I"$PWD/lib" -I/usr/local/cpanel tests/management.t
