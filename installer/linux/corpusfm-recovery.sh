#!/usr/bin/env bash
# corpusfm-recovery — create or adopt a CORPUSfm Recovery File (packet 1246-02).
#
# Installed to $INSTALL_DIR/bin/corpusfm-recovery, root-owned and root-only, the same way
# cfm-db-helper is. The PLACEMENT and its ownership are the installer's (1246-03/04).
#
# It finds the runtime RELATIVE TO ITSELF — `bin/..` — and nowhere else. An earlier version
# hard-coded /opt/CORPUSfm and honoured a CORPUSFM_INSTALL_DIR variable; both were installation
# LAYOUT policy, which belongs to 1246-03, and the variable was an environment override of exactly
# the kind this family is removing. A wrapper that only knows where it is cannot disagree with the
# installer that put it there.
#
# No SUPPORTED passphrase option exists anywhere in this chain: this wrapper defines none and
# does not prompt, and the module's parser defines none either — an unrecognised argument is
# rejected, not consumed. It DOES forward whatever arguments it is given — a pass-through
# must — so "never forwarded" was a stronger claim than the truth.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="$(dirname -- "$HERE")"
PYBIN="$INSTALL_DIR/venv/bin/python"

if [[ ! -x "$PYBIN" ]]; then
    echo "corpusfm-recovery: no CORPUSfm runtime beside this command (looked for $PYBIN)" >&2
    exit 2
fi

exec env PYTHONPATH="$INSTALL_DIR/src" "$PYBIN" -m corpusfm.lifecycle.recovery_cli "$@"
