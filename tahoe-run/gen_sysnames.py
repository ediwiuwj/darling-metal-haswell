#!/usr/bin/env python3
"""Genera sysnames.h con los nombres de las syscalls BSD y de las trampas Mach de un XNU de Apple.

Uso: gen_sysnames.py <xnu> > sysnames.h
"""
import re
import sys

xnu = sys.argv[1]
bsd = {}
for line in open(f'{xnu}/bsd/kern/syscalls.master'):
    g = re.match(r'^(\d+)\s+\S+\s+\S+\s+\{\s*(.*?)\s*\}', line)
    if g:
        m = re.search(r'(\w+)\s*\(', g.group(2))
        if m:
            n = int(g.group(1))
            # algunas syscalls aparecen dos veces (con y sin #if): quedarse con la que no es enosys
            if n not in bsd or bsd[n] in ('enosys', 'nosys'):
                bsd[n] = m.group(1)

src = open(f'{xnu}/osfmk/kern/syscall_sw.c').read()
src = src[src.index('mach_trap_table'):]
mach = {int(n): v for n, v in re.findall(r'/\*\s*(\d+)\s*\*/\s*MACH_TRAP\(\s*(\w+)', src)}

print('// Generado por gen_sysnames.py a partir de XNU. No editar.')
print(f'#define BSD_NAMES_N {max(bsd) + 1}')
print('static const char* const bsd_names[BSD_NAMES_N] = {')
for n in sorted(bsd):
    print(f'\t[{n}] = "{bsd[n]}",')
print('};')
print(f'#define MACH_NAMES_N {max(mach) + 1}')
print('static const char* const mach_names[MACH_NAMES_N] = {')
for n in sorted(mach):
    print(f'\t[{n}] = "{mach[n]}",')
print('};')
