#!/usr/bin/env python3
"""Mapea una dyld_shared_cache de macOS en las direcciones fijas que dyld espera.

Es la mitad que hace XNU al ejecutar un proceso ("shared region"): los mapeos salen de la cabecera de cada
archivo de la caché (el principal y sus subcachés .01, .02...). Se mapea sin slide, con MAP_PRIVATE para
que __DATA sea copy-on-write. Sirve para comprobar que el kernel de Linux lo permite; la idea es que lo
haga `mldr` antes de saltar a dyld.

Uso: map_dyld_cache.py <ruta/dyld_shared_cache_x86_64>     (comprueba y sale)
"""
import ctypes
import glob
import mmap
import os
import struct
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
MAP_FIXED_NOREPLACE = 0x100000


def mappings(path):
    with open(path, 'rb') as f:
        h = f.read(0x40)
    off, cnt = struct.unpack_from('<II', h, 0x10)
    with open(path, 'rb') as f:
        f.seek(off)
        raw = f.read(32 * cnt)
    return [struct.unpack_from('<QQQII', raw, 32 * i) for i in range(cnt)]


def map_cache(main):
    files = [main] + sorted(glob.glob(main + '.[0-9]*'))
    files = [f for f in files if not f.endswith(('.map', '.atlas')) and not f.endswith('.symbols')]
    done = []
    for path in files:
        fd = os.open(path, os.O_RDONLY)
        for addr, size, fileoff, maxprot, initprot in mappings(path):
            prot = (mmap.PROT_READ if initprot & 1 else 0) | (mmap.PROT_WRITE if initprot & 2 else 0) \
                | (mmap.PROT_EXEC if initprot & 4 else 0)
            p = libc.mmap(addr, size, prot, mmap.MAP_PRIVATE | MAP_FIXED_NOREPLACE, fd, fileoff)
            if p != addr:
                err = os.strerror(ctypes.get_errno())
                raise SystemExit(f'mmap falló en 0x{addr:x} (+0x{size:x}) de {os.path.basename(path)}: {err}')
            done.append((os.path.basename(path), addr, size, initprot))
    return done


if __name__ == '__main__':
    main = sys.argv[1]
    for name, addr, size, prot in map_cache(main):
        print(f'{name:30s} 0x{addr:012x}  {size >> 20:5d} MB  prot={prot}')
    base = 0x7FF800000000
    magic = ctypes.string_at(base, 16).rstrip(b'\0')
    n_images = struct.unpack('<I', ctypes.string_at(base + 0x1C, 4))[0]
    print(f'cabecera leída desde la memoria en 0x{base:x}: {magic.decode()!r}')
    # el contenido mapeado debe coincidir con el archivo
    with open(main, 'rb') as f:
        f.seek(0x1000)
        same = f.read(64) == ctypes.string_at(base + 0x1000, 64)
    print('contenido coincide con el archivo:', same)
    # __DATA es copy-on-write: escribir no debe tocar el archivo
    data_addr = 0x7ff842e08000
    before = ctypes.string_at(data_addr, 8)
    ctypes.memmove(data_addr, b'\xAA' * 8, 8)
    with open(main, 'rb') as f:
        f.seek(0x23504000)
        on_disk = f.read(8)
    print('__DATA escribible y privado (el archivo no cambia):', on_disk == before and ctypes.string_at(data_addr, 8) == b'\xAA' * 8)
