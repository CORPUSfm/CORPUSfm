#!/bin/bash
# corpusfm-proxy - the PUBLIC administrator surface (packet 1246-06 section 8.1).
#
#   corpusfm-proxy status|add|ignore|remove|reconcile [<type>|all] [--json]
#
# It accepts NO request-file option and NO disposition option, and it never asks an administrator to
# choose a persistence mode: mutating verbs use direct_commit internally. Route facts come from the
# published manifest (`manifest.web`) and from nowhere else - not install.yaml, not the environment,
# not a default - and a missing or incomplete WebBlock REFUSES.
#
# The integrator protocol beneath this tool (`python -m corpusfm.lifecycle proxy ... --request`) is
# NOT reachable from here. Same engine, different caller, different authority.
set -euo pipefail
PY="${CORPUSFM_PYTHON:-python3}"
exec "$PY" -m corpusfm.lifecycle proxy-public "$@"
