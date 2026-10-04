// Interfaz común entre el núcleo de tahoe-run y los módulos de emulación (emu_*.c).
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <ucontext.h>

#define PAGE 4096UL
static inline uint64_t round_up(uint64_t v) { return (v + PAGE - 1) & ~(PAGE - 1); }

#define CACHE_BASE 0x00007ff800000000UL
#define STACK_TOP  0x00007ff7bff00000UL

// Contexto de una syscall interceptada: número y hasta 6 argumentos (registros rdi, rsi, rdx, r10, r8, r9).
struct ctx { uint64_t nr, a[6]; ucontext_t* uc; uint64_t ret2; int has_ret2; };   // ret2 -> rdx (fork, pipe)
typedef long (*emu_fn)(struct ctx*);

uint64_t ctx_arg(struct ctx* c, int i);   // argumento i (0..7); a partir del 6.º va en la pila

// BSD: devuelve >= 0, o -errno_de_Darwin. Mach: devuelve un kern_return_t.
void reg_bsd(unsigned num, emu_fn fn);
void reg_mach(unsigned num, emu_fn fn);

// Utilidades
void logf_(const char* fmt, ...);
int darwin_errno(int linux_errno);
int darwin_open_flags(int darwin_flags);
ssize_t safe_read(uint64_t addr, void* buf, size_t len);
ssize_t safe_write(uint64_t addr, const void* buf, size_t len);
int safe_string(uint64_t addr, char* out, size_t max);
#include <ucontext.h>
void diag_crash(ucontext_t* uc);
extern const char* tahoe_root;
extern char cache_guest_path[1024];   // ruta de la caché vista desde macOS (sin la raíz del host)
extern uint64_t cache_ino;
extern const char *g_cache_path, *g_dyld_path, *g_self_exe;   // para relanzar tahoe-run en execve   // raíz del sistema de archivos de macOS 26 (TAHOE_ROOT)
extern int trace_all;

// Módulos
void emu_sysctl_init(void);
void emu_fs_init(void);
void emu_mach_init(void);
void emu_proc_init(void);
void emu_kqueue_init(void);
void emu_sem_init(void);
uint32_t sem_create(int value);
uint32_t alloc_port(void);
void reenable_dispatch(void);   // el kernel no hereda la interceptación de syscalls en el hijo de un fork

// Códigos de error de Darwin
enum { D_EPERM = 1, D_ENOENT = 2, D_EBADF = 9, D_ENOMEM = 12, D_EFAULT = 14, D_EINVAL = 22, D_ENOSYS = 78 };
