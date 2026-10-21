#!/bin/bash
# install.sh -- deploy the PwnEscape-lab tools on L1.
#
# Run as root from the PwnEscape-lab directory:
#   sudo bash scripts/common/install.sh
#
# It copies the scripts into /opt/pwnescape/tools, creates the work directory,
# and builds the CO-RE observer. It does not start listeners, install firewall
# rules, or touch the network.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
T="/opt/pwnescape/tools"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

install -d "$T"
install -d /tmp/r6new

# Common helpers
install -m 0755 "$ROOT/scripts/common/listen_on.py" "$T/"
install -m 0755 "$ROOT/scripts/common/check_env.sh" "$T/"
install -m 0755 "$ROOT/scripts/common/r6veth_up.sh" "$T/"
install -m 0755 "$ROOT/scripts/common/r6_host_gate2.py" "$T/"
install -m 0755 "$ROOT/scripts/common/r6obs_build.sh" "$T/"
install -m 0644 "$ROOT/scripts/common/r6e.py" "$T/"
install -m 0644 "$ROOT/scripts/common/cacheid.py" "$T/"
install -m 0644 "$ROOT/scripts/common/cachename.py" "$T/"
install -m 0644 "$ROOT/scripts/common/r6obs.c" "$T/"
install -m 0644 "$ROOT/scripts/common/r6obs.bpf.c" "$T/"
install -m 0755 "$ROOT/scripts/common/setup_guest_full.sh" "$T/setup_guest_full.sh"

# r6
for f in "$ROOT/scripts/r6/"*; do install -m 0755 "$f" "$T/"; done

# r1 / R7
for f in "$ROOT/scripts/r1/"*; do install -m 0755 "$f" "$T/"; done

# Build the observer. The build script expects to run inside $T.
if command -v bpftool >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
  (cd "$T" && bash ./r6obs_build.sh) || {
    echo "r6obs build failed; install libbpf-dev/libelf-dev/zlib1g-dev and retry" >&2
    exit 2
  }
else
  echo "bpftool/clang not found; skipping r6obs build" >&2
fi

echo
echo "installed into $T"
echo "next:"
echo "  sudo bash $T/r6veth_up.sh"
echo "  sudo python3 $T/listen_on.py 7778 &"
echo "  sudo iptables -t mangle -A INPUT -p tcp --dport 7778 -j CHECKSUM --checksum-fill"
echo "  sudo python3 $T/r6_host_gate2.py 10 0x7b00"
