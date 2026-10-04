# Metal sobre Vulkan en Darling, con una GPU Intel Haswell

Notas, parches y pruebas de un proyecto en pausa: ejecutar software de macOS sobre Linux con
[Darling](https://github.com/darlinghq/darling) e intentar tener Metal en una GPU antigua
(Intel HD 4400, driver Mesa `hasvk`, Vulkan 1.2).

**Estado: en marcha (retomado el 4 de octubre de 2026).** Un kernel de Metal (AIR), traducido a SPIR-V
con `metal2vulkan`, ya se ejecuta correctamente en esta GPU usando Vulkan directamente
(`test/run_add_arrays.c`). Todavía **no** pasa por Indium ni por Darling: esa integración es lo que falta.

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
6. **Ese SPIR-V pide `OpCapability Int64`**, aunque esta GPU tiene `shaderInt64 = false`. El origen es
   solo el índice del array (`zext i32 → i64` en el `getelementptr`). `tools/narrow_int64.py` lo
   estrecha a 32 bits y retira la capacidad: el resultado pasa `spirv-val --target-env vulkan1.2`.
7. **Resultado en la GPU** (Intel HD 4400, Mesa 26.2.2, `test/run_add_arrays.c`, sin activar ninguna feature):

   | SPIR-V | Pipeline | Resultado |
   |---|---|---|
   | original, con `Int64` | se crea | 64/64 correctos |
   | índice de 32 bits, sin `Int64` | se crea | 64/64 correctos |

   Es decir, `hasvk` **acepta y ejecuta bien** el shader con `Int64` aunque la feature esté desactivada.
   Eso no lo hace válido: la especificación exige activar `shaderInt64`, la capa de validación lo
   marcaría y otro driver podría rechazarlo o comportarse distinto. Por eso se mantiene la versión
   de 32 bits como la correcta. Con este kernel (solo `i32` y `float`) no se puede saber si `hasvk`
   emula de verdad aritmética de 64 bits cuando existe; no se probó.

## Ejecutar el userland de macOS 26 en Darling (medido el 4 de octubre de 2026)

Objetivo: que la interfaz del recovery de macOS 26 corra sobre el kernel de Linux, sin XNU.

| Prueba | Resultado |
|---|---|
| `bin/ls` de macOS 26 (SDK 26.6.1, `minos 10.14`) | **Funciona** en Darling: usa la parte estable de la ABI |
| `Language Chooser.app` (primera pantalla del recovery, `minos 26.6`, ~45 librerías) | Cae en la 8.ª: `libIASUnifiedProgress.dylib` (`No shared cache present`) |
| Las 7 anteriores (`AVFoundation`, `SkyLight`, `CoreWLAN`...) | Son **stubs de Darling**, no las de Apple |
| Extraer esa librería de la `dyld_shared_cache` con `ipsw` y ponerla en `DYLD_LIBRARY_PATH` | dyld la encuentra y la **rechaza** (`overlapping segments`) |

**Por qué el extractor no sirve para cargar**: las imágenes de la caché están enlazadas de antemano
a direcciones fijas de la caché. El dylib extraído conserva `LC_DYLD_INFO_ONLY`, pero sus tablas de
*rebase*, *bind* y *lazy bind* salen **vacías**, y los punteros de `__got` siguen codificados con la
información de *slide*. Sin esas tablas, ningún dyld sabe qué símbolo es cada puntero. Estas
herramientas (`ipsw`, `DyldExtractor`...) sirven para desensamblar, no para cargar. Probado con
`ipsw dyld extract` con y sin `--slide`.

**Consecuencia**: la ruta viable no es extraer librerías sueltas, sino que un dyld cargue la caché
completa, lo que exige implementar las syscalls de la región compartida (`shared_region_check_np`,
`shared_region_map_and_slide_np`) en `darlingserver`, usar el `dyld` y la `libSystem` de Tahoe y
reimplementar las syscalls y trampas Mach que XNU 12377 añadió respecto a Darwin 20.

### Distancia medida entre Darling (Darwin 20) y XNU 12377 (macOS 26)

`tools/compare_syscalls.py` compara las tablas (Darling emula las syscalls en espacio de usuario):

| Interfaz | XNU 26 | Darling | Falta |
|---|---|---|---|
| Syscalls BSD | 455 reales | 268 | **189** (156 con número antiguo, 33 posteriores al 524) |
| Trampas Mach | 60 reales | 52 | **9** |

- **Lo Mach está cerca.** Faltan 9, entre ellas `iokit_user_client_trap`,
  `host_create_mach_voucher_trap`, `mk_timer_arm_leeway_trap` y `task_dyld_process_info_notify_get_trap`;
  `_exclaves_ctl_trap` y `pfz_exit` dependen de hardware o de la zona de funciones privadas de Apple.
- **Lo BSD no.** Entre las 33 nuevas hay las que sí usan `libSystem` y `libdispatch` de Tahoe:
  `ulock_wait2` (544), `kqueue_workloop_ctl` (530), `preadv`/`pwritev` (540-543),
  `shared_region_map_and_slide_2_np` (536), `map_with_linking_np` (550), `mkfifoat`/`mknodat`,
  `os_fault_with_payload` (529) y `memorystatus_available_memory` (534). Muchas de las 156 antiguas
  (`mount`, `acct`, `quotactl`, `semsys`...) no las llaman las apps normales.
- **La región compartida es hoy un stub**: `sys_shared_region_check_np` devuelve `-EINVAL` ("no hay
  región compartida"). Las variantes `map_and_slide` no existen.
- **`mldr` tiene el `dyld` fijado en el código** (`INSTALL_PREFIX/libexec/usr/lib/dyld`). Para probar el
  `dyld` de Tahoe (Mach-O `MH_DYLINKER`, `minos 26.6`) hace falta compilar un `mldr` propio o sustituir
  un archivo del sistema. El `dyld` de Darling es de 2023 (`dyld2`/`dyld3`).
- Es una medida aproximada: una syscall puede resolverse por otra vía, y solo importan las que las
  librerías de Tahoe llaman de verdad (eso aún no está medido).

`tools/dyld_iterate.py` automatiza esta prueba: ejecuta un binario en Darling, extrae la librería que
falta de la caché y reintenta. Sirve para mapear la cadena de dependencias; se detiene en el fallo
anterior.

## Qué hay en este repositorio

| Ruta | Contenido |
|---|---|
| `patches/` | Parche para [`darlinghq/indium`](https://github.com/darlinghq/indium) (`git am`) |
| `tools/extract_air.py` | Saca los módulos AIR de un `.metallib` |
| `tools/compare_syscalls.py` | Compara las syscalls BSD y trampas Mach de un XNU con las de Darling |
| `tools/dyld_iterate.py` | Ejecuta un binario de macOS 26 en Darling extrayendo de la caché lo que falte |
| `tools/narrow_int64.py` | Quita `Int64` de un SPIR-V cuando solo se usa para indexar (conservador) |
| `test/add_arrays.vulkan1.2.spv` | SPIR-V generado por `metal2vulkan` (aún con `Int64`) |
| `test/run_add_arrays.c` | Programa mínimo de Vulkan que ejecuta el kernel y comprueba `c = a + b` |

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

# 4. (opcional) estrechar índices a 32 bits y ejecutar en la GPU
python3 tools/narrow_int64.py add.spv add32.spv && spirv-val --target-env vulkan1.2 add32.spv
clang -O1 -o run test/run_add_arrays.c -lvulkan && ./run add32.spv   # OK: 64/64 correctos
```
El programa de prueba asume la interfaz de este kernel (3 buffers en `set 0` y 48 bytes de push constants).

## Pasos siguientes, por orden

1. ~~Quitar el `Int64` y ejecutar el kernel en la GPU.~~ Hecho (puntos 6 y 7). Falta integrar el paso de
   estrechado en `metal2vulkan` como opción (`--no-int64`) en lugar de usarlo aparte.
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
