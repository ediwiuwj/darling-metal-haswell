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

### Qué necesita de verdad el `dyld` de Tahoe

`tools/used_syscalls.py` busca las instrucciones `syscall` de un Mach-O x86_64 (`mov eax, imm32` + `syscall`;
la clase va en el byte alto: 1 Mach, 2 BSD, 3 machdep). Se valida contra `libsystem_kernel` de la caché,
que da 456 syscalls BSD frente a las 455 reales de XNU 26.

- El `dyld` de Tahoe enlaza 104 syscalls BSD y 61 trampas Mach. A Darling le faltan 18 BSD y 10 Mach.
- La mayoría son ruido de enlazado (`mount`, `fmount`, `graftdmg`, `kdebug_*`). Las que están en el camino
  de arranque son: `shared_region_map_and_slide_2_np` (536), `ulock_wait2` (544),
  `terminate_with_payload` (520), `kqueue_workloop_ctl` (530), `openbyid_np` (479),
  `os_fault_with_payload` (529), `proc_info_extended_id` (545) y `map_with_linking_np` (550, solo arm64e).
- Que un stub esté enlazado no significa que se ejecute: es una cota superior, no una medida dinámica.

### Dos mecanismos que un `mldr` para Tahoe necesita, validados en este kernel (7.2.5)

1. **Interceptar `syscall` en crudo.** El `dyld` y la `libSystem` de Tahoe llaman al kernel con
   `mov eax, 0x2000000|N; syscall`, y Darling no tiene `seccomp` ni `SIGSYS` en su cargador (funciona porque
   las bibliotecas que carga son las suyas). `PR_SET_SYSCALL_USER_DISPATCH` redirige esas llamadas a un
   manejador de `SIGSYS`, como hace Wine con las de Windows. `test/sud_syscall_dispatch.c` lo comprueba: una
   syscall BSD `0x2000014` y un número inexistente llegan al manejador con `si_syscall` completo y se
   emulan (`rax = 4242` y `-ENOSYS`). Detalle que cuesta encontrar: `rt_sigreturn` debe ejecutarse desde la
   región exenta; con el restaurador de `libc` el proceso muere por recursión (violación de segmento).
2. **Mapear la caché de librerías.** `tools/map_dyld_cache.py` lee los mapeos de la cabecera de cada archivo
   de la caché (8 en total, ~1 GB, desde `0x7ff800000000`) y los mapea con `MAP_FIXED_NOREPLACE`:
   `__TEXT` ejecutable, `__DATA` privado y escribible (copy-on-write, el archivo no cambia). Sin slide.

**Lo que NO está resuelto y es lo grande**: dónde vive la emulación. Las syscalls de Darling están
implementadas como código Mach-O dentro de su `libsystem_kernel.dylib`, y con el `dyld` y la `libSystem` de
Tahoe esa biblioteca no se carga (la de la caché la sustituye). Hay que decidir entre (A) recompilar esa
emulación como ELF dentro de `mldr`, (B) cargar la emulación como una imagen Mach-O adicional desde `mldr`, o
(C) escribir una emulación nueva solo para lo que Tahoe llama. Y además `commpage` con el diseño de macOS 26,
las 18 syscalls y 10 trampas Mach que faltan y `SkyLight`.

### `tahoe-run`: programas reales de macOS 26 ejecutándose sobre Linux

Código propio en C (`tahoe-run/`), sin código de Darling. Hace de "kernel" para un programa de Tahoe:
mapea la caché de librerías (con el *slide* v2 aplicado y la región dinámica), fabrica el `commpage`,
carga el `dyld` y el programa, monta la pila `[mh][argc][argv][envp][apple]` e intercepta las syscalls con
`PR_SET_SYSCALL_USER_DISPATCH`. Las syscalls BSD, las trampas Mach y los mensajes `mach_msg2` al kernel se
emulan en módulos (`emu_fs.c`, `emu_sysctl.c`, `emu_mach.c`, `emu_proc.c`); todo lo que falta se registra
con su nombre.

**Resultado (4 de octubre de 2026): el `ls` de macOS 26 lista la raíz del recovery sobre Linux y sale con
código 0.** Es el binario auténtico de Apple con su `dyld`, su `libSystem`, `libpthread` y `libobjc`
sacados de la `dyld_shared_cache`, sin XNU ni Darling:

```
$ TAHOE_ROOT=<recovery extraído> ./tahoe-run <cache> <root>/usr/lib/dyld <root>/bin/ls /
Applications  Install macOS Tahoe.app  Library  System  Users  Volumes  [HFS+ Private Data]  bin  cores  dev ...
```

Qué hizo falta, por orden (cada paso lo señaló el registro de syscalls o un fallo):
`sysctl` (incluido `kern.bootargs`), `__mac_syscall`, `csops`, `openat`/`fstatat`/`dup`, `getattrlist` (volumen
y ruta completa), `fsgetpath`, `mach_vm_map`/`host_info`/`host_get_clock_service`/`semaphore_create`/
`task_info`/`task_get_special_port` por `mach_msg2`, `bsdthread_register`, `getdirentries64` y
`getattrlistbulk`, además de los parámetros `ptr_munge`, `stack_guard` y `malloc_entropy` en la pila.

Errores propios que costaron encontrar, por si ayudan a otros:
- `jmp *%r14` justo después de poner `r14` a cero al saltar a `dyld`.
- No crear la región dinámica de la caché (`dyld_data    v3`, que en macOS construye `launchd`) ni aplicar
  el *slide* de los punteros de datos (aparecían como `0x400003a93d0`).
- `process_vm_readv/writev` sobre el propio proceso fallaba con `EINVAL` dentro del manejador de `SIGSYS`:
  se sustituyó por `/proc/self/mem`.
- Constantes de `getattrlist` mal copiadas (`0x08000000` es `FULLPATH`, no los flags de protección).
- `libpthread` aborta con `BUG IN LIBPTHREAD: Token from the kernel is 0` si falta `ptr_munge=`.

Programas probados con éxito (`exit=0`): `ls`, `ls -l`, `echo`, `cat`, `uname -a`, `pwd` y `bash` 3.2.57 con órdenes
internas (`echo`, aritmética `$((6*7))`, variables). También funciona el `execve` (se relanza `tahoe-run` con el programa
nuevo e interpreta `#!`) cuando `bash` lanza directamente una única orden externa.

**Problema abierto: `fork`.** `bash -c 'a; b'` o una tubería hacen `fork` y el hijo aborta con `SIGABRT` justo al
terminar la reinicialización de `libSystem` en el hijo. Lo averiguado:
- El kernel de Linux **no hereda** `PR_SET_SYSCALL_USER_DISPATCH` en el hijo de un `fork`; sin reactivarlo con
  `prctl`, las syscalls del hijo se ejecutan como syscalls reales de Linux y devuelven `ENOSYS` en silencio (así es
  como `libmalloc` acababa escribiendo en una página de solo lectura). Esto está corregido (`reenable_dispatch`).
- Con eso el hijo ya ejecuta todo el reinicio (`task_self_trap`, `bsdthread_register`, `mprotect`, `host_self_trap`,
  `mach_port_construct`, `host_get_clock_service`), pero después aborta. No es `bsdthread_ctl` (ya aceptado: lo llama la
  propia `pthread_kill`), ni el tamaño de recepción, ni el valor de retorno del `fork`.
- El mensaje de aborto no está en la anotación de crash de `libpthread`, y la pila en ese instante no conserva
  direcciones de retorno útiles. Falta saber qué función decide abortar; la siguiente prueba razonable es trazar la
  ejecución del hijo instrucción a instrucción desde el retorno del `fork`.

Otros descubrimientos de esta etapa:
- `mach_msg2` con `MACH64_SEND_KOBJECT_CALL` no lleva vector: el mensaje completo está en `data` y la respuesta se
  escribe en el mismo búfer. En mensajes a puertos normales la cabecera viaja solo en registros.
- Los argumentos 7 y 8 de una syscall van en la pila en `[rsp+8]` y `[rsp+16]`, pero en la ruta de reinicio del hijo
  ese tamaño de recepción no es fiable; para llamadas a objetos del kernel se usa el tamaño de la respuesta.
- `process_vm_readv/writev` sobre el propio proceso falla con `EINVAL`: se usa `/proc/self/mem`.

Limitación conocida: 63 de los 347 programas de `/bin`, `/usr/bin`, `/sbin` y `/usr/sbin` (y 10.626 archivos en
total) están **vacíos** en el sistema extraído, porque `7z` no entiende la compresión transparente de HFS+
(`decmpfs`, cuyo contenido va en la *resource fork*). No es un fallo del lanzador: hay que re-extraer con una
herramienta que la soporte (`hfsfuse`, en AUR).

Siguiente: señales, hilos reales y `launchd`/Mach IPC con puertos de verdad; después, la parte gráfica
(`SkyLight`, `QuartzCore`), que es la que llevaría al recovery.

### Compilar Darling en un Codespace

`tools/build_darling_codespace.sh` compila `mldr` (el cargador Mach-O) y `darlingserver` en un
Codespace de 4 núcleos y 16 GB (Ubuntu 24.04): 170 pasos, sin errores, en pocos minutos. Con el árbol
de Darling en el commit `60ba801d`. Tres cosas que costaron tiempo y quedan anotadas en el script:
compilar en `/tmp` (disco aparte, ~118 GB; `/workspaces` solo deja ~12 GB), saltarse `git-lfs`
(`GIT_LFS_SKIP_SMUDGE=1`; el submódulo `swift` pide credenciales) y que un clon abortado deja los
submódulos vacíos aunque `git submodule status` diga que están bien.

Esto compila solo las piezas de Linux. Las bibliotecas del lado macOS (`libsystem_kernel` y demás) usan
el compilador cruzado de Darling y no se han construido todavía.

`tools/dyld_iterate.py` automatiza esta prueba: ejecuta un binario en Darling, extrae la librería que
falta de la caché y reintenta. Sirve para mapear la cadena de dependencias; se detiene en el fallo
anterior.

## Qué hay en este repositorio

| Ruta | Contenido |
|---|---|
| `patches/` | Parche para [`darlinghq/indium`](https://github.com/darlinghq/indium) (`git am`) |
| `tools/extract_air.py` | Saca los módulos AIR de un `.metallib` |
| `tools/compare_syscalls.py` | Compara las syscalls BSD y trampas Mach de un XNU con las de Darling |
| `tools/map_dyld_cache.py` | Mapea la `dyld_shared_cache` en sus direcciones fijas y lo verifica |
| `test/sud_syscall_dispatch.c` | Prueba de interceptación de syscalls de macOS con syscall user dispatch |
| `tools/build_darling_codespace.sh` | Compila `mldr` y `darlingserver` de Darling en un Codespace |
| `tools/used_syscalls.py` | Lista las syscalls BSD y trampas Mach que invoca un Mach-O x86_64 |
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

### `launchd` como PID 1 (4 de octubre de 2026)

`unshare --pid --fork --user --map-root-user --mount-proc ./tahoe-run <caché> <root>/usr/lib/dyld <root>/sbin/launchd`
ejecuta el `launchd` real de macOS 26 como **PID 1** de un espacio de nombres (el registro muestra `<1>`). Sin root.

Qué se vio, por orden:
1. `launchd` cierra la entrada, salida y error estándar y los reabre a `/dev/null`. Eso tapaba el registro de
   `tahoe-run` (escribía en el descriptor 2): ahora usa un descriptor privado (el 900).
2. Abre `/dev/console` (sin permiso en el espacio de nombres): se redirige a `/dev/null`.
3. `fsctl 0x40084a6a` (consulta privada de APFS del estado del dispositivo raíz, 8 bytes): se responde con ceros.
   Sin eso aborta con `failed to query root device status: 78` y llama a `reboot`.
4. Lo siguiente que pide, y que ya no es trivial:
   - **`bsdthread_create` (360)**: `launchd` crea hilos. Hace falta soporte real de hilos (con `clone`, TLS de macOS y la
     interceptación de syscalls activa en cada hilo).
   - **`fsctl 0xc1044a50`** (otra consulta de APFS, de entrada y salida, 260 bytes).
   - **`mach_msg2` id 225 al host** (rutina del subsistema `host`) y, tras ellas, Mach IPC con puertos reales.
   - `csops` operación 16 (derechos DER), la zona horaria (`/var/db/timezone/zoneinfo/posixrules`).
   Después de esto el proceso muere con `SIGILL`.

## Dónde retomar (estado al 4 de octubre de 2026)

**Funciona**: `tahoe-run` ejecuta programas reales de macOS 26 (`ls`, `echo`, `cat`, `uname`, `pwd`, `bash` 3.2.57 con
órdenes internas) sobre Linux, sin XNU ni Darling. Compilar con `tahoe-run/build.sh <xnu>` y ejecutar con
`TAHOE_ROOT=<recovery extraído> ./tahoe-run <caché> <root>/usr/lib/dyld <root>/bin/ls /`.

**Pendiente, por orden de utilidad**
1. **`fork` con continuación en el hijo**: el hijo reinicializa `libSystem` y aborta (ver "Problema abierto").
   Siguiente prueba: trazar el hijo instrucción a instrucción desde el retorno del `fork`.
2. **Re-extraer el recovery con `hfsfuse`** (AUR): 63 de 347 programas estándar y 10.626 archivos salen vacíos con `7z`.
3. **`launchd` como PID 1**: ya hay **hilos reales** (`bsdthread_create`/`bsdthread_terminate` sobre `pthread_create`
   de Linux, un selector de despacho por hilo, GS en el TSD, puerto del hilo en `tsd+mach_thread_self_offset`) y
   `bsdthread_register` devuelve la máscara de capacidades `0x4000007e` (libpthread aborta si es 0). Ahora falla en
   **`kevent_qos` (374)**: hay que emular **kqueue/kevent** (sobre epoll) y las colas de trabajo (`workq_kernreturn`
   hoy es un no-op); después `fsctl 0xc1044a50`, `map_with_linking_np` (550) y Mach IPC con puertos reales.
4. Señales reales, hilos y colas de trabajo; después la parte gráfica (`SkyLight`, `QuartzCore`, Indium/`metal2vulkan`).

**Ideas sueltas ya validadas**: `PR_SET_SYSCALL_USER_DISPATCH` no se hereda en `fork` (reactivar en el hijo);
`/proc/self/mem` en lugar de `process_vm_*`; la caché necesita *slide* v2 y región dinámica; `llvm-objdump` no
desensambla bytes sueltos, usar `objdump -D -b binary -m i386:x86-64`; `ipsw dyld a2s` simboliza direcciones de
la caché x86_64.
