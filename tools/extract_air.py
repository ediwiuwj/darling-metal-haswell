#!/usr/bin/env python3
"""Extrae los módulos AIR (bitcode de LLVM) de un .metallib.

Uso: extract_air.py entrada.metallib directorio_salida
Luego: metal2vulkan modulo.air salida.spv
"""
import re, struct, sys, pathlib

data = pathlib.Path(sys.argv[1]).read_bytes()
out = pathlib.Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)

wrappers = [m.start() for m in re.finditer(b'\xde\xc0\x17\x0b', data)]
if wrappers:  # bitcode envuelto: magic, versión, offset, tamaño, cputype
    for i, off in enumerate(wrappers):
        _, _, boff, bsize, _ = struct.unpack('<5I', data[off:off + 20])
        (out / f'module{i}.air').write_bytes(data[off + boff:off + boff + bsize])
else:
    hits = [m.start() for m in re.finditer(b'BC\xc0\xde', data)]
    for i, off in enumerate(hits):
        end = hits[i + 1] if i + 1 < len(hits) else len(data)
        (out / f'module{i}.air').write_bytes(data[off:end])
print(f'{len(wrappers) or len(hits)} módulo(s) en {out}')
