#!/bin/bash
# Compila tahoe-run (estático y sin PIE: así no ocupa las direcciones altas que necesita macOS).
# Uso: ./build.sh <ruta al código de xnu>      (genera sysnames.h si falta)
set -euo pipefail
cd "$(dirname "$0")"
[ -f sysnames.h ] || python3 gen_sysnames.py "${1:?indica la ruta de xnu}" > sysnames.h
clang -O1 -g -Wall -Wextra -Wno-unused-parameter -static -no-pie -o tahoe-run tahoe_run.c
ls -la tahoe-run
