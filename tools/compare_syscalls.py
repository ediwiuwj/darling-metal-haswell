#!/usr/bin/env python3
"""Compara las syscalls BSD y las trampas Mach de un XNU de Apple con las que implementa Darling.

Uso: compare_syscalls.py <xnu> <darling>
  <xnu>     fuente de apple-oss-distributions/xnu (p. ej. xnu-12377.121.6)
  <darling> clon de darlinghq/darling con submódulos

Darling implementa las syscalls en espacio de usuario (libsystem_kernel/emulation); aquí se cuentan las
entradas de sus tablas. Es una medida aproximada: una syscall puede resolverse por otra vía.
"""
import glob
import os
import re
import sys

xnu, darling = sys.argv[1:3]
emu = f'{darling}/src/external/xnu/darling/src/libsystem_kernel/emulation/src/xnu_syscall'

# --- syscalls BSD
table = open(f'{emu}/bsd/bsd_syscall_table.c').read()
have = {int(n): v for n, v in re.findall(r'^\s*\[(\d+)\]\s*=\s*([A-Za-z_0-9]+),', table, re.M)}
want = {}
for line in open(f'{xnu}/bsd/kern/syscalls.master'):
    g = re.match(r'^(\d+)\s+(\S+)\s+(\S+)\s+\{\s*(.*?)\s*\}', line)
    if not g or 'nosys' in g.group(4):
        continue
    nm = re.search(r'(\w+)\s*\(', g.group(4))
    want[int(g.group(1))] = nm.group(1) if nm else '?'
missing = sorted(n for n in want if n not in have)
newer = [n for n in missing if n > max(have)]
print(f'BSD: XNU {len(want)} reales, Darling {len(have)} -> faltan {len(missing)} '
      f'({len(newer)} con número posterior a {max(have)})')
print('  nuevas:', ', '.join(f'{n}:{want[n]}' for n in newer))

# --- trampas Mach
x = open(f'{xnu}/osfmk/kern/syscall_sw.c').read()
x = x[x.index('mach_trap_table'):]
traps = {int(n): v for n, v in re.findall(r'/\*\s*(\d+)\s*\*/\s*MACH_TRAP\(\s*(\w+)', x)}
traps = {n: v for n, v in traps.items() if 'invalid' not in v}
mach = {}
for f in glob.glob(f'{emu}/mach/**/*.c', recursive=True):
    if re.search(r'table|trap', os.path.basename(f)):
        for n, v in re.findall(r'\[(\d+)\]\s*=\s*([A-Za-z_0-9]+)', open(f, errors='ignore').read()):
            mach[int(n)] = v
mm = sorted(n for n in traps if n not in mach)
print(f'Mach: XNU {len(traps)} reales, Darling {len(mach)} -> faltan {len(mm)}')
print('  ', ', '.join(f'{n}:{traps[n]}' for n in mm))
