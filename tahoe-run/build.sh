#!/bin/bash
# Compila tahoe-run (estático y sin PIE: así no ocupa las direcciones altas que necesita macOS).
# Uso: ./build.sh <ruta al código de xnu>      (genera sysnames.h si falta)
set -euo pipefail
cd "$(dirname "$0")"
[ -f sysnames.h ] || python3 gen_sysnames.py "${1:?indica la ruta de xnu}" > sysnames.h
clang -O1 -g -Wall -Wextra -Wno-unused-parameter -static -o tahoe-run tahoe_run.c emu_sysctl.c emu_fs.c emu_mach.c emu_proc.c emu_kqueue.c emu_port.c emu_sem.c
ls -la tahoe-run
