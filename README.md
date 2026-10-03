# Metal sobre Vulkan en Darling, con una GPU Intel Haswell

Notas, parches y pruebas de un proyecto en pausa: ejecutar software de macOS sobre Linux con
[Darling](https://github.com/darlinghq/darling) e intentar tener Metal en una GPU antigua
(Intel HD 4400, driver Mesa `hasvk`, Vulkan 1.2).

**Estado: en pausa (2 de octubre de 2026).** No hay nada que ejecute todavía un shader de Metal de
principio a fin en esta GPU. Lo que sí está probado y lo que falta se detalla abajo.

## Entorno de pruebas

- Arch Linux (Omarchy), kernel 7.2.5, Mesa 26.2.2, LLVM 22.1.8
- GPU: Intel HD 4400 (Haswell GT2). `vulkaninfo`: API **1.2.354**, `timelineSemaphore`,
  `dynamicRendering`, `synchronization2`, `VK_EXT_extended_dynamic_state` 1 y 2 presentes;
  `shaderInt64 = false`, `shaderFloat64 = false`

## Lo que se aprendió

1. **Darling ya no usa módulo de kernel.** Desde 2022 emula Mach IPC y las syscalls de XNU en
   espacio de usuario con `darlingserver`. `darling-bin` de AUR funciona tal cual: `darling shell`
   arranca y reporta macOS 11.7 (Darwin 20.6). No es macOS 26.
2. **Darling ya incluye Metal sobre Vulkan** (`src/external/metal`): *Indium* (API de Metal sobre
   Vulkan) e *Iridium* (shaders AIR → SPIR-V). Se compila con `ENABLE_METAL`.
3. **Indium rechazaba esta GPU** porque exigía `apiVersion >= 1.3` aunque el dispositivo tiene todo
   lo necesario mediante extensiones. Ver `patches/`.
4. **Iridium se cae con LLVM moderno.** `air.cpp:428` usa `LLVMGetElementType(LLVMTypeOf(fn))`, que
   supone punteros tipados (eliminados en LLVM 17). Con LLVM 22 el programa de prueba
   `basic-compute` falla con SIGSEGV en `newLibrary`.
5. **[`steelbrain/metal2vulkan`](https://github.com/steelbrain/metal2vulkan)** (Rust, LGPL-3.0,
   alpha) traduce AIR a SPIR-V para Vulkan 1.2 y maneja punteros opacos. Con él, el kernel
   `add_arrays` del test de Indium produce SPIR-V que pasa `spirv-val --target-env vulkan1.2`
   (`test/add_arrays.vulkan1.2.spv`).
6. **Ese SPIR-V pide `OpCapability Int64`**, y esta GPU no tiene `shaderInt64`. El origen es solo el
   índice del array (`zext i32 → i64` en el `getelementptr`), así que se puede estrechar a 32 bits.
   Es lo siguiente por hacer; **no está implementado**.

## Qué hay en este repositorio

| Ruta | Contenido |
|---|---|
| `patches/` | Parche para [`darlinghq/indium`](https://github.com/darlinghq/indium) (`git am`) |
| `tools/extract_air.py` | Saca los módulos AIR de un `.metallib` |
| `test/add_arrays.vulkan1.2.spv` | SPIR-V generado por `metal2vulkan` (aún con `Int64`) |

### Estado de los parches

- Compilan con `clang` y LLVM 22. Aceptan dispositivos Vulkan 1.2 con `VK_KHR_synchronization2` y
  `VK_EXT_extended_dynamic_state{,2}`, activan esas extensiones y cargan las funciones de 1.3 por su
  nombre `KHR`/`EXT` (solo las promovidas en 1.3).
- Se probaron con `basic-compute` en la GPU descrita: el dispositivo se acepta, se crea y los
  semáforos funcionan. **No se probó ningún shader**, por el punto 4.
- Añaden `#include` que faltaban en Iridium (`<cstdint>`, `<stdexcept>`, `<string>`); esos errores ya
  existían sin los parches.

## Cómo repetir la prueba de traducción

```sh
# 1. compilar metal2vulkan (Rust >= 1.87) y tener llvm-dis y spirv-val
git clone https://github.com/steelbrain/metal2vulkan
(cd metal2vulkan && cargo build --release)   # binario en target/release/metal2vulkan

# 2. extraer AIR de un .metallib (p. ej. indium/test/basic-compute/add.metallib)
python3 tools/extract_air.py add.metallib out/

# 3. traducir y validar
metal2vulkan out/module0.air add.spv     # imprime: spirv-val vulkan1.2: PASS
```

## Pasos siguientes, por orden

1. Opción `--no-int64` en `metal2vulkan` (o un paso posterior sobre el SPIR-V) que estreche el
   índice a 32 bits y retire la capacidad. Comprobar que esta GPU crea el pipeline y ejecuta el
   kernel.
2. Adaptar `Library::newLibrary` de Indium para usar `metal2vulkan` en lugar de Iridium (hay que
   traducir su reflexión de descriptores y push constants al `OutputInfo` que espera Indium).
3. Compilar Darling con `ENABLE_METAL` y probar el ejemplo `triangle`.
4. Subir la base de macOS 11 a macOS 26 (XNU 12377, `dyld` 1378, `objc4` 951): es la parte más
   grande y no se empezó.

## Qué no se incluye, a propósito

Se descargó el sistema base de macOS 26.6.2 (recovery de Apple, vía `macrecovery.py` de OpenCorePkg)
para estudiar dónde viven los frameworks (dentro de `dyld_shared_cache`). Es software de Apple con
licencia restringida: **no se redistribuye aquí** y cualquier implementación debe ser propia.
Los fuentes abiertos de Apple (`xnu-12377.121.6`, `dyld-1378`, `objc4-951.7`,
`libdispatch-1542.100.32`) están en `github.com/apple-oss-distributions`.

## Licencias

- **Notas, `tools/` y `test/`**: [MIT](LICENSE). Quien los use o redistribuya debe conservar el aviso de
  copyright y la licencia.
- **`patches/`**: trabajo derivado de [Indium](https://github.com/darlinghq/indium) y por tanto bajo su
  licencia (MPL-2.0), no bajo la MIT de arriba.
- [`metal2vulkan`](https://github.com/steelbrain/metal2vulkan) es LGPL-3.0-or-later; no se incluye
  ningún código suyo, solo un SPIR-V generado con él.
