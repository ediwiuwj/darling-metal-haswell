#!/usr/bin/env python3
"""Ejecuta un binario de macOS 26 en Darling y, cada vez que dyld dice "Library not loaded", extrae la
librería que falta de la dyld_shared_cache de Tahoe y reintenta. Sirve para mapear la cadena de
dependencias y ver en qué punto falla de verdad.

Requisitos: `darling` con el prefijo arrancado, `ipsw` (extractor de la caché) y el sistema base de
macOS 26 ya extraído del recovery. No modifica el prefijo de Darling: usa DYLD_LIBRARY_PATH y
DYLD_FRAMEWORK_PATH apuntando a la carpeta de extracción.

Uso: dyld_iterate.py <caché> <carpeta_extracción> <ejecutable> [--max N]
"""
import os
import re
import subprocess
import sys
import tempfile
import time


def extract(cache, out, install_name):
    """Extrae `install_name` de la caché y lo deja en la ruta que dyld buscará."""
    tmp = tempfile.mkdtemp(dir=out)
    r = subprocess.run(['ipsw', 'dyld', 'extract', cache, install_name, '-o', tmp],
                       capture_output=True, text=True)
    found = [os.path.join(tmp, f) for f in os.listdir(tmp)]
    if not found:
        return None, (r.stdout + r.stderr)[-300:]
    src = found[0]
    if '.framework/' in install_name:      # /System/Library/Frameworks/X.framework/Versions/A/X
        rel = install_name.split('/Library/', 1)[1]
        dest = os.path.join(out, 'fw', *rel.split('/')[1:])   # fw/Frameworks/X.framework/...
    else:                                   # /usr/lib/libfoo.dylib  -> plano, por nombre
        dest = os.path.join(out, os.path.basename(install_name))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    os.replace(src, dest)
    os.rmdir(tmp)
    return dest, ''


def run_once(out, exe, log, timeout=25):
    script = os.path.join(out, 'run.sh')
    host = '/Volumes/SystemRoot'
    fw = f'{host}{out}/fw/Frameworks:{host}{out}/fw/PrivateFrameworks'
    with open(script, 'w') as f:
        f.write(f'''#!/bin/bash
export DYLD_LIBRARY_PATH="{host}{out}"
export DYLD_FRAMEWORK_PATH="{fw}"
export DYLD_PRINT_LIBRARIES=1
"{host}{exe}" > "{host}{log}" 2>&1
echo "salida: $?" >> "{host}{log}"
''')
    os.chmod(script, 0o755)
    if os.path.exists(log):
        os.remove(log)
    p = subprocess.Popen(['darling', 'shell', f'{host}{script}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    end = time.time() + timeout
    text = ''
    while time.time() < end:
        time.sleep(1)
        if os.path.exists(log):
            text = open(log, errors='replace').read()
            if 'salida:' in text:
                break
    else:
        text += '\n[sin terminar en %ds: el proceso sigue vivo]' % timeout
    p.kill()
    return text


def main():
    args = sys.argv[1:]
    mx = 12
    if '--max' in args:
        i = args.index('--max')
        mx = int(args[i + 1])
        del args[i:i + 2]
    cache, out, exe = args
    out = os.path.abspath(out)
    log = os.path.join(out, 'run.log')
    seen = set()
    for n in range(1, mx + 1):
        text = run_once(out, exe, log)
        loaded = len(re.findall(r'dyld: loaded', text))
        m = re.search(r'Library not loaded: (\S+)', text)
        print(f'[{n}] librerías cargadas: {loaded}', end='  ')
        if not m:
            print('-> no hay "Library not loaded". Fin de la cadena de dependencias.')
            print('\n'.join(text.strip().splitlines()[-8:]))
            return
        lib = m.group(1)
        if lib in seen:
            print(f'-> {lib} sigue sin cargar tras extraerla (el fallo es otro):')
            print('\n'.join(text.strip().splitlines()[-6:]))
            return
        seen.add(lib)
        dest, err = extract(cache, out, lib)
        if not dest:
            print(f'-> falta {lib} y NO está en la caché. {err}')
            return
        print(f'-> extraída {lib}')
    print('límite de iteraciones alcanzado')


if __name__ == '__main__':
    main()
