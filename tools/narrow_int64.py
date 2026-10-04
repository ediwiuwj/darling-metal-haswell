#!/usr/bin/env python3
"""Quita OpCapability Int64 de un SPIR-V cuando solo se usa para indexar.

Los shaders de Metal calculan las direcciones con un `zext i32 -> i64` antes del `getelementptr`.
`metal2vulkan` lo traduce a `OpUConvert/OpSConvert` de 32 a 64 bits seguido de `OpAccessChain`, y eso
obliga a declarar `OpCapability Int64`, que GPUs como la Intel HD 4400 (`shaderInt64 = false`) no
aceptan. Un índice de `OpAccessChain` puede ser de 32 bits, así que la conversión sobra.

El paso es conservador:
  * solo elimina una conversión 32 -> 64 si TODOS sus usos son índices de OpAccessChain /
    OpInBoundsAccessChain;
  * solo retira la capacidad Int64 si el tipo de 64 bits ya no se usa en ningún otro sitio.
Todo lo demás se deja como está. Conviene validar siempre el resultado con `spirv-val`.

Uso: narrow_int64.py entrada.spv salida.spv
"""
import struct
import sys

OP_CAPABILITY = 17
OP_TYPE_INT = 21
OP_U_CONVERT = 113
OP_S_CONVERT = 114
OP_ACCESS_CHAIN = 65
OP_IN_BOUNDS_ACCESS_CHAIN = 66
CAP_INT64 = 11

# instrucciones que NO tienen el formato [tipo_resultado, id_resultado, ...]
NO_TYPED_RESULT = set(range(19, 40)) | {3, 4, 5, 6, 7, 10, 11, 14, 15, 16, 17, 71, 72, 73, 74, 75, 248}


def parse(words):
    insts, i = [], 5
    while i < len(words):
        count, opcode = words[i] >> 16, words[i] & 0xFFFF
        if count == 0:
            sys.exit('SPIR-V corrupto: instrucción de longitud 0')
        insts.append([opcode, list(words[i + 1:i + count])])
        i += count
    return insts


def references(op, args, tid):
    """True si la instrucción usa `tid` como id (ignora literales que coincidan por casualidad)."""
    if op in (3, 4, 5, 6, 7, 14, 16, 17):          # sin ids relevantes (nombres, fuentes, literales)
        return False
    if op in (71, 72, 73, 74, 75):                   # decoraciones: el objetivo es un id, el resto literales
        return args[0] == tid
    if op in (43, 50):                               # OpConstant / OpSpecConstant: solo el tipo es un id
        return args[0] == tid
    return tid in args


def narrow(insts):
    int_types = {args[0]: args[1] for op, args in insts if op == OP_TYPE_INT}  # id -> ancho
    result_type = {}
    for op, args in insts:
        if op not in NO_TYPED_RESULT and len(args) >= 2:
            result_type.setdefault(args[1], args[0])

    candidates = {}  # id de la conversión -> id del operando de 32 bits
    for op, args in insts:
        if op in (OP_U_CONVERT, OP_S_CONVERT):
            rtype, rid, operand = args[:3]
            if int_types.get(rtype) == 64 and int_types.get(result_type.get(operand)) == 32:
                candidates[rid] = operand

    # un id solo se puede sustituir si todos sus usos son índices de un access chain
    for cid in list(candidates):
        for op, args in insts:
            is_def = op in (OP_U_CONVERT, OP_S_CONVERT) and args[1] == cid
            uses = [k for k, w in enumerate(args) if w == cid and not (is_def and k == 1)]
            if uses and not (op in (OP_ACCESS_CHAIN, OP_IN_BOUNDS_ACCESS_CHAIN) and min(uses) >= 3):
                del candidates[cid]
                break

    out = []
    for op, args in insts:
        if op in (OP_U_CONVERT, OP_S_CONVERT) and args[1] in candidates:
            continue
        if op in (OP_ACCESS_CHAIN, OP_IN_BOUNDS_ACCESS_CHAIN):
            args = args[:3] + [candidates.get(w, w) for w in args[3:]]
        out.append([op, args])

    # retirar tipos de 64 bits que ya no usa nadie, y la capacidad si no queda ninguno
    for tid in [t for t, w in int_types.items() if w == 64]:
        used = any(references(op, args, tid) and not (op == OP_TYPE_INT and args[0] == tid) for op, args in out)
        if not used:
            out = [[op, args] for op, args in out if not (op == OP_TYPE_INT and args[0] == tid)]
    if not any(op == OP_TYPE_INT and args[1] == 64 for op, args in out):
        out = [[op, args] for op, args in out if not (op == OP_CAPABILITY and args[0] == CAP_INT64)]
    return out, len(candidates)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], 'rb').read()
    words = list(struct.unpack(f'<{len(data) // 4}I', data))
    if words[0] != 0x07230203:
        sys.exit('no es un SPIR-V little-endian')
    out, n = narrow(parse(words))
    flat = words[:5]
    for op, args in out:
        flat.append(((len(args) + 1) << 16) | op)
        flat.extend(args)
    open(sys.argv[2], 'wb').write(struct.pack(f'<{len(flat)}I', *flat))
    still = any(op == OP_CAPABILITY and args[0] == CAP_INT64 for op, args in out)
    print(f'{n} conversión(es) 32->64 eliminada(s); Int64 {"sigue declarado" if still else "retirado"}')


if __name__ == '__main__':
    main()
