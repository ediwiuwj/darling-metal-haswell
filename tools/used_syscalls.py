#!/usr/bin/env python3
"""Lista las syscalls BSD y trampas Mach que un Mach-O x86_64 invoca de verdad.

Busca `mov eax, imm32` seguido de `syscall` en __TEXT,__text. El número lleva la clase en el byte
alto: 1 = trampa Mach, 2 = syscall BSD, 3 = machdep. Un stub de libsystem_kernel es de esta forma:
    mov eax, 0x02000005 ; mov r10, rcx ; syscall      (open)

Uso: used_syscalls.py binario [binario...]   -> JSON con las unión de todas
"""
import json
import re
import struct
import sys


def text_bytes(path):
    d = open(path, 'rb').read()
    magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', d, 0)
    if magic == 0xBEBAFECA or magic == 0xCAFEBABE:   # fat: coger la rebanada x86_64
        n = struct.unpack_from('>I', d, 4)[0]
        for i in range(n):
            cpu, _, off, size, _ = struct.unpack_from('>5I', d, 8 + 20 * i)
            if cpu == 0x01000007:
                d = d[off:off + size]
                break
        magic, _, _, _, ncmds, _, _, _ = struct.unpack_from('<8I', d, 0)
    assert magic == 0xFEEDFACF, 'no es un Mach-O de 64 bits'
    pos = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<2I', d, pos)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from('<I', d, pos + 64)[0]
            for s in range(nsects):
                sp = pos + 72 + 80 * s
                sect = d[sp:sp + 16].rstrip(b'\0')
                if sect == b'__text':
                    sz, off = struct.unpack_from('<Q', d, sp + 40)[0], struct.unpack_from('<I', d, sp + 48)[0]
                    return d[off:off + sz]
        pos += size
    raise SystemExit(f'{path}: sin __text')


def scan(path):
    data = text_bytes(path)
    found = {1: set(), 2: set(), 3: set()}
    for m in re.finditer(rb'\xb8(....)', data, re.S):
        v = struct.unpack('<I', m.group(1))[0]
        cls = v >> 24
        if cls in found and b'\x0f\x05' in data[m.end():m.end() + 24]:
            found[cls].add(v & 0xFFFFFF)
    return found


if __name__ == '__main__':
    union = {1: set(), 2: set(), 3: set()}
    for p in sys.argv[1:]:
        f = scan(p)
        print(f'{p.split("/")[-1]}: BSD={len(f[2])} Mach={len(f[1])} machdep={len(f[3])}', file=sys.stderr)
        for k in union:
            union[k] |= f[k]
    print(json.dumps({'bsd': sorted(union[2]), 'mach': sorted(union[1]), 'machdep': sorted(union[3])}))
