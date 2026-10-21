#!/bin/bash
# r6obs_build.sh -- build the CO-RE observer on the L1 (root not needed).
set -e
cd /opt/pwnescape/tools
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -c r6obs.bpf.c -o r6obs.bpf.o
gcc -O2 -o r6obs r6obs.c -lbpf -lelf -lz
echo "built: $(ls -la r6obs r6obs.bpf.o | awk '{print $5, $9}' | tr '\n' ' ')"
