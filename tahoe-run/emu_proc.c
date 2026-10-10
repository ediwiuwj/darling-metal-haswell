// Procesos, hilos y señales: bsdthread_register, sigaction, etc.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <spawn.h>
#include <poll.h>
#include <stdatomic.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <stdlib.h>
#include "tahoe.h"

// bsdthread_register(thread_start, wqthread, pthread_size, ...): libpthread registra aquí las funciones con las
// que el kernel arranca hilos nuevos. Se guardan y se devuelve la máscara de capacidades.
uint64_t thread_start_fn, wqthread_fn, pthread_size;
static uint32_t tsd_offset, mach_thread_self_offset;   // desplazamiento del TSD dentro de pthread_t (struct _pthread_registration_data, +24)
// work_interval_ctl(operación, id, arg, longitud): intervalos de trabajo del planificador (audio/gráficos en tiempo real).
// No hay planificador que informar: se crean intervalos con un puerto propio y el resto de operaciones se aceptan.
static long bsd_work_interval_ctl(struct ctx* c) {
	static uint64_t next_id = 1;
	switch ((uint32_t)c->a[0]) {
	case 4: {                                                 // CREATE2: {id (entrada/salida), puerto, banderas}
		uint8_t p[16] = { 0 };
		if (safe_read(c->a[2], p, 16) != 16) return -D_EFAULT;
		uint64_t id = next_id++; uint32_t port = alloc_port();
		memcpy(p, &id, 8); memcpy(p + 8, &port, 4);
		return safe_write(c->a[2], p, 16) == 16 ? 0 : -D_EFAULT;
	}
	case 9: { if (c->a[2] && c->a[3] >= 4) { uint32_t z = 0; safe_write(c->a[2], &z, 4); } return 0; }   // GET_FLAGS
	default: return 0;                                        // DESTROY, NOTIFY, JOIN, SET_NAME, SET_WORKLOAD_ID
	}
}
static long bsd_bsdthread_register(struct ctx* c) {
	thread_start_fn = c->a[0];
	wqthread_fn = c->a[1];
	pthread_size = c->a[2];
	if (c->a[3]) {
		safe_read(c->a[3] + 24, &tsd_offset, 4); safe_read(c->a[3] + 32, &mach_thread_self_offset, 4);
		// mutex_default_policy (+44): mutex y variables de condición basados en ulock (futex) en vez de psynch, que no se emula.
		// 0x100 = _PTHREAD_REG_DEFAULT_USE_ULOCK; los 8 bits bajos son la política (3 = primer ajuste).
		uint32_t pol = 0x100 | 3;
		safe_write(c->a[3] + 44, &pol, 4);
	}
	if (trace_all) logf_("    bsdthread_register: tsd_offset=0x%x mts_offset=0x%x\n", tsd_offset, mach_thread_self_offset);
	if (trace_all) logf_("    bsdthread_register: start=0x%lx wq=0x%lx pthread_size=0x%lx\n", thread_start_fn, wqthread_fn, pthread_size);
	// Máscara de capacidades del kernel: libpthread exige FINEPRIO|BSDTHREADCTL|SETSELF|QOS_MAINTENANCE y
	// QOS_DEFAULT; sin ella nunca marca el kernel como compatible y aborta con "has not been initialized".
	return 0x400000df;   // DISPATCHFUNC|FINEPRIO|BSDTHREADCTL|SETSELF|QOS_MAINTENANCE|KEVENT|WORKLOOP|QOS_DEFAULT
}


#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

// gettimeofday(timeval*, timezone*, mach_absolute_time*): struct timeval de Darwin = {int64 seg, int32 microseg, pad}
static long bsd_gettimeofday(struct ctx* c) {
	struct timespec ts;
	if (c->a[0]) {
		clock_gettime(CLOCK_REALTIME, &ts);
		int64_t tv[2] = { ts.tv_sec, ts.tv_nsec / 1000 };
		if (safe_write(c->a[0], tv, 16) != 16) return -D_EFAULT;
	}
	if (c->a[1]) { int32_t tz[2] = { 0, 0 }; safe_write(c->a[1], tz, 8); }
	if (c->a[2]) {                                       // tercer argumento: mach_absolute_time (ya en ns)
		clock_gettime(CLOCK_MONOTONIC, &ts);
		uint64_t t = (uint64_t)ts.tv_sec * 1000000000UL + ts.tv_nsec;
		safe_write(c->a[2], &t, 8);
	}
	return 0;
}
// shm_open: sin memoria compartida con nombre; los clientes (libnotify...) tienen ruta alternativa.
// shm_open/shm_unlink: objetos de memoria compartida POSIX como archivos de /dev/shm con prefijo propio y nombre saneado.
static int shm_host_name(uint64_t addr, char* out, size_t cap) {
	char g[256];
	(void)port_exists(0);                       // fuerza la creación/apertura de la región compartida (fija TAHOE_PORTS_OWNER)
	if (safe_string(addr, g, sizeof g) != 0) return -1;
	char* o = out + snprintf(out, cap, "/dev/shm/tahoe.%s.", getenv("TAHOE_PORTS_OWNER") ? getenv("TAHOE_PORTS_OWNER") : "x");
	for (char* s = g; *s && o < out + cap - 1; s++) *o++ = (*s == '/') ? '_' : *s;
	*o = 0;
	return 0;
}
static long bsd_shm_open(struct ctx* c) {
	char h[400];
	if (shm_host_name(c->a[0], h, sizeof h)) return -D_EFAULT;
	int fd = open(h, darwin_open_flags((int)c->a[1]) | O_CLOEXEC, (mode_t)c->a[2]);
	if (trace_all) logf_("    shm_open -> %s = %d\n", h, fd);
	return fd < 0 ? -darwin_errno(errno) : fd;
}
static long bsd_shm_unlink(struct ctx* c) {
	char h[400];
	if (shm_host_name(c->a[0], h, sizeof h)) return -D_EFAULT;
	return unlink(h) ? -darwin_errno(errno) : 0;
}
// ioctl: no se traduce ninguna petición todavía; 25 = ENOTTY ("no es un terminal"), lo correcto para isatty().
static long bsd_ioctl(struct ctx* c) {
	if (trace_all) logf_("    ioctl(fd=%d, 0x%lx)\n", (int)c->a[0], c->a[1]);
	return -25;
}

#include <sys/socket.h>
// socket(dominio, tipo, protocolo): AF_INET6 vale 30 en Darwin y 10 en Linux; el resto coincide.
static long bsd_socket(struct ctx* c) {
	int dom = (int)c->a[0];
	if (dom == 30) dom = AF_INET6;
	long r = syscall(SYS_socket, dom, (int)c->a[1], (int)c->a[2]);
	return r < 0 ? -darwin_errno(errno) : r;
}

// connect: solo sockets de dominio Unix. sockaddr_un de Darwin = {len u8, familia u8, ruta[104]}; en Linux {familia u16, ruta[108]}.
static long bsd_connect(struct ctx* c) {
	uint8_t sa[128];
	uint32_t len = (uint32_t)c->a[2];
	if (len < 2 || len > sizeof sa || safe_read(c->a[1], sa, len) != (ssize_t)len) return -D_EFAULT;
	if (sa[1] != 1) return -47;                          // solo AF_UNIX; el resto: EAFNOSUPPORT
	struct sockaddr_un_ { uint16_t fam; char path[108]; } un = { 1, { 0 } };
	size_t pl = len - 2 < sizeof un.path - 1 ? len - 2 : sizeof un.path - 1;
	memcpy(un.path, sa + 2, pl);
	long r = syscall(SYS_connect, (int)c->a[0], &un, 2 + pl + 1);
	if (trace_all || r < 0) logf_("    connect(\"%s\") -> %s\n", un.path, r < 0 ? strerror(errno) : "ok");
	return r < 0 ? -darwin_errno(errno) : 0;
}
#include <sys/resource.h>
#include <sys/stat.h>
#include <signal.h>

// ---------------------------------------------------------------- identidad de proceso
static long bsd_getppid(struct ctx* c) { (void)c; return getppid(); }
static long bsd_getpgrp(struct ctx* c) { (void)c; return getpgrp(); }
static long bsd_getpgid(struct ctx* c) { long r = syscall(SYS_getpgid, (int)c->a[0]); return r < 0 ? -darwin_errno(errno) : r; }
static long bsd_setpgid(struct ctx* c) { long r = syscall(SYS_setpgid, (int)c->a[0], (int)c->a[1]); return r < 0 ? -darwin_errno(errno) : 0; }
static long bsd_getsid(struct ctx* c)  { long r = syscall(SYS_getsid, (int)c->a[0]); return r < 0 ? -darwin_errno(errno) : r; }
static long bsd_setsid(struct ctx* c)  { (void)c; long r = syscall(SYS_setsid); return r < 0 ? -darwin_errno(errno) : r; }
static long bsd_umask(struct ctx* c)   { return (long)umask((mode_t)c->a[0]); }

// ---------------------------------------------------------------- límites de recursos
// Darwin: NOFILE=8, NPROC=7, MEMLOCK=6, RSS/AS=5 (más la marca POSIX 0x1000); Linux los numera distinto.
static int linux_rlimit(int darwin) {
	switch (darwin & 0xfff) {
	case 0: return RLIMIT_CPU;     case 1: return RLIMIT_FSIZE;  case 2: return RLIMIT_DATA;  case 3: return RLIMIT_STACK;
	case 4: return RLIMIT_CORE;    case 5: return RLIMIT_AS;     case 6: return RLIMIT_MEMLOCK;
	case 7: return RLIMIT_NPROC;   case 8: return RLIMIT_NOFILE; default: return -1;
	}
}
#define D_RLIM_INFINITY 0x7fffffffffffffffULL
static long bsd_getrlimit(struct ctx* c) {
	int r = linux_rlimit((int)c->a[0]);
	if (r < 0) return -D_EINVAL;
	struct rlimit rl;
	if (getrlimit(r, &rl) != 0) return -darwin_errno(errno);
	uint64_t out[2] = { rl.rlim_cur == RLIM_INFINITY ? D_RLIM_INFINITY : rl.rlim_cur, rl.rlim_max == RLIM_INFINITY ? D_RLIM_INFINITY : rl.rlim_max };
	if (((int)c->a[0] & 0xfff) == 8 && out[0] > 10240 && !(c->a[0] & 0x1000)) out[0] = 10240;   // sin la marca POSIX, macOS limita NOFILE
	return safe_write(c->a[1], out, 16) == 16 ? 0 : -D_EFAULT;
}
static long bsd_setrlimit(struct ctx* c) {
	int r = linux_rlimit((int)c->a[0]);
	uint64_t in[2];
	if (r < 0 || safe_read(c->a[1], in, 16) != 16) return -D_EINVAL;
	struct rlimit rl = { in[0] == D_RLIM_INFINITY ? RLIM_INFINITY : in[0], in[1] == D_RLIM_INFINITY ? RLIM_INFINITY : in[1] };
	// Los límites que fija launchd para cada servicio (NumberOfFiles, AS, DATA...) no deben bajar los del anfitrión: tahoe-run
	// necesita descriptores altos y mucho espacio de direcciones para relanzarse, y un servicio sin ellos moría con exit(111).
	if (r == RLIMIT_NOFILE) {
		if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < 4096) rl.rlim_cur = 4096;
		if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < 4096) rl.rlim_max = 4096;
	} else if (r != RLIMIT_CORE) return 0;
	return setrlimit(r, &rl) == 0 ? 0 : -darwin_errno(errno);
}

// ---------------------------------------------------------------- señales (virtuales por ahora)
// Los manejadores se registran, pero no se entregan señales asíncronas: hace falta construir marcos de señal de macOS.
static int darwin_to_linux_sig(int s) {
	static const int m[32] = { 0, SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, 0, SIGFPE, SIGKILL, SIGBUS, SIGSEGV, SIGSYS, SIGPIPE,
		SIGALRM, SIGTERM, SIGURG, SIGSTOP, SIGTSTP, SIGCONT, SIGCHLD, SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		SIGWINCH, 0, SIGUSR1, SIGUSR2 };
	return s > 0 && s < 32 ? m[s] : -1;
}
static struct { uint64_t handler, tramp; uint32_t mask, flags; } sigtab[32];
static long bsd_sigaction(struct ctx* c) {
	int s = (int)c->a[0];
	if (s <= 0 || s >= 32 || s == 9 || s == 17) return -D_EINVAL;           // KILL y STOP no se pueden capturar
	if (c->a[2]) {                                                           // struct sigaction anterior: {handler, mask(4), flags(4)}
		uint8_t old[16] = { 0 };
		memcpy(old, &sigtab[s].handler, 8);
		memcpy(old + 8, &sigtab[s].mask, 4);
		memcpy(old + 12, &sigtab[s].flags, 4);
		if (safe_write(c->a[2], old, 16) != 16) return -D_EFAULT;
	}
	if (c->a[1]) {                                                           // struct __sigaction: {handler, tramp, mask(4), flags(4)}
		uint8_t nw[24];
		if (safe_read(c->a[1], nw, 24) != 24) return -D_EFAULT;
		memcpy(&sigtab[s].handler, nw, 8);
		memcpy(&sigtab[s].tramp, nw + 8, 8);
		memcpy(&sigtab[s].mask, nw + 16, 4);
		memcpy(&sigtab[s].flags, nw + 20, 4);
	}
	return 0;
}
static uint64_t alt_sp, alt_size;
static int alt_flags = 4;                                                    // SS_DISABLE
static long bsd_sigaltstack(struct ctx* c) {
	if (c->a[1]) {
		uint8_t old[24] = { 0 };
		memcpy(old, &alt_sp, 8); memcpy(old + 8, &alt_size, 8); memcpy(old + 16, &alt_flags, 4);
		if (safe_write(c->a[1], old, 24) != 24) return -D_EFAULT;
	}
	if (c->a[0]) {
		uint8_t nw[24];
		if (safe_read(c->a[0], nw, 24) != 24) return -D_EFAULT;
		memcpy(&alt_sp, nw, 8); memcpy(&alt_size, nw + 8, 8); memcpy(&alt_flags, nw + 16, 4);
	}
	return 0;
}
static uint32_t pthread_mask;
static long bsd_pthread_sigmask(struct ctx* c) {                             // (how, set*, oset*) por valor en Darwin: how, set, oset
	uint32_t old = pthread_mask;
	if (c->a[1]) {
		uint32_t set;
		if (safe_read(c->a[1], &set, 4) != 4) return -D_EFAULT;
		if (c->a[0] == 1) pthread_mask |= set; else if (c->a[0] == 2) pthread_mask &= ~set; else if (c->a[0] == 3) pthread_mask = set; else return -D_EINVAL;
	}
	if (c->a[2] && safe_write(c->a[2], &old, 4) != 4) return -D_EFAULT;
	return 0;
}
static long bsd_sigpending(struct ctx* c) { uint32_t z = 0; return safe_write(c->a[0], &z, 4) == 4 ? 0 : -D_EFAULT; }

// kill(pid, señal) y __pthread_kill(hilo, señal): señales dirigidas al propio proceso se envían de verdad.
static long bsd_kill(struct ctx* c) {
	int s = (int)c->a[1];
	if (s == 0) { long r = syscall(SYS_kill, (int)c->a[0], 0); return r < 0 ? -darwin_errno(errno) : 0; }
	int ls = darwin_to_linux_sig(s);
	if (ls <= 0) return -D_EINVAL;
	long r = syscall(SYS_kill, (int)c->a[0], ls);
	return r < 0 ? -darwin_errno(errno) : 0;
}
// Diagnóstico dirigido: 1 si este proceso es el indicado en /dev/shm/tahoe-stacks (subcadena de su línea de órdenes).
int diag_target(void) {
	static int want = -1;
	if (want < 0) {
		char nm[64] = "", cl[512] = "";
		FILE* f = fopen("/dev/shm/tahoe-stacks", "r"); if (f) { if (fgets(nm, sizeof nm, f)) nm[strcspn(nm, "\n")] = 0; fclose(f); }
		f = fopen("/proc/self/cmdline", "r"); if (f) { size_t n = fread(cl, 1, 511, f); for (size_t i = 0; i < n; i++) if (!cl[i]) cl[i] = ' '; fclose(f); }
		want = nm[0] && strstr(cl, nm) != NULL;
	}
	return want;
}
// Lee los mensajes de aborto de todas las imágenes de la caché compartida (mapeada en 0x7ff800000000, sin slide).
static void crash_messages(void) {
	const uint64_t cache = 0x7ff800000000UL;
	uint32_t io = 0, ic = 0;
	if (safe_read(cache + 0x1c0, &io, 4) != 4 || safe_read(cache + 0x1c4, &ic, 4) != 4 || !ic || ic > 10000) return;
	for (uint32_t i = 0; i < ic; i++) {
		uint64_t mh = 0; uint32_t pathoff = 0;
		if (safe_read(cache + io + i * 32ULL, &mh, 8) != 8 || safe_read(cache + io + i * 32ULL + 24, &pathoff, 4) != 4) continue;
		uint32_t hdr[8];
		if (safe_read(mh, hdr, 32) != 32 || hdr[0] != 0xfeedfacf) continue;
		uint64_t lc = mh + 32;
		for (uint32_t c = 0; c < hdr[4] && c < 128; c++) {
			uint32_t cmd[2];
			if (safe_read(lc, cmd, 8) != 8 || cmd[1] < 8) break;
			if (cmd[0] == 0x19) {                                        // LC_SEGMENT_64
				uint32_t nsect = 0; safe_read(lc + 64, &nsect, 4);
				for (uint32_t s = 0; s < nsect && s < 64; s++) {
					char sname[17] = { 0 }; uint64_t addr = 0;
					uint64_t so = lc + 72 + s * 80ULL;
					safe_read(so, sname, 16); safe_read(so + 32, &addr, 8);
					if (strcmp(sname, "__crash_info") != 0) continue;
					uint64_t m1 = 0, m2 = 0; char t1[300] = "", t2[300] = "", path[160] = "";
					safe_read(addr + 8, &m1, 8); safe_read(addr + 32, &m2, 8);
					if (m1) safe_string(m1, t1, sizeof t1);
					if (m2) safe_string(m2, t2, sizeof t2);
					if (t1[0] || t2[0]) {
						safe_string(cache + pathoff, path, sizeof path);
						const char* b = strrchr(path, '/');
						logf_("    abort <%d>: [%s] \"%s\"%s%s\n", (int)getpid(), b ? b + 1 : path, t1, t2[0] ? " / " : "", t2);
					}
				}
			}
			lc += cmd[1];
		}
	}
}
void diag_crash(ucontext_t* uc) {
		// Motivo del aborto: cada librería que llama a abort/CRASH deja su texto en gCRAnnotations, en su sección
		// __DATA*,__crash_info (message en +8, message2 en +32). Se recorren las imágenes de la caché compartida.
		crash_messages();
		{
			// Retornos plausibles: valores de la pila dentro de la caché cuya instrucción anterior es un "call".
			uint64_t sk[512] = { 0 };
			ssize_t got = safe_read((uint64_t)uc->uc_mcontext.gregs[REG_RSP], sk, sizeof sk);
			logf_("    abort <%d>: rip=0x%llx rsp=0x%llx rbp=0x%llx pila:", (int)getpid(), (unsigned long long)uc->uc_mcontext.gregs[REG_RIP], (unsigned long long)uc->uc_mcontext.gregs[REG_RSP], (unsigned long long)uc->uc_mcontext.gregs[REG_RBP]);
			for (int k = 0; k < 14 && k < (int)(got / 8); k++) logf_(" %lx", sk[k]);
			logf_("\n    abort: llamadas plausibles:");
			int shown = 0;
			for (int k = 0; k < (int)(got / 8) && shown < 12; k++) {
				uint64_t a = sk[k];
				if (a < 0x7ff800000000UL || a >= 0x7ff820000000UL) continue;
				uint8_t pre[6];
				if (safe_read(a - 6, pre, 6) != 6) continue;
				if (pre[1] == 0xe8 || pre[3] == 0xff || pre[4] == 0xff || pre[2] == 0xff) { logf_(" 0x%lx", a); shown++; }
			}
			logf_("\n");
		}
	}

static long bsd_pthread_kill(struct ctx* c) {
	int s = (int)c->a[1];
	if (s == 0) return 0;
	if (s == 6) {
		diag_crash(c->uc);
	}
	int ls = darwin_to_linux_sig(s);
	if (ls <= 0) return -D_EINVAL;
	long r = syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), ls);
	return r < 0 ? -darwin_errno(errno) : 0;
}

// ---------------------------------------------------------------- procesos: fork, execve, wait4, pipe
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>

static int linux_to_darwin_sig(int s) {
	for (int d = 1; d < 32; d++) if (darwin_to_linux_sig(d) == s) return d;
	return s;
}
// Estado de wait4: salida normal = código << 8; terminado por señal = nº de señal de Darwin (+0x80 si volcó core).
static int darwin_wait_status(int st) {
	if (WIFEXITED(st)) return WEXITSTATUS(st) << 8;
	if (WIFSIGNALED(st)) return linux_to_darwin_sig(WTERMSIG(st)) | (WCOREDUMP(st) ? 0x80 : 0);
	if (WIFSTOPPED(st)) return 0x7f | (linux_to_darwin_sig(WSTOPSIG(st)) << 8);
	return st;
}

// fork: se usa el de Linux. La interceptación y la memoria se heredan. Convenio de Darwin: padre rax=pid hijo, rdx=0;
// hijo rax=pid del padre, rdx=1 (libsyscall devuelve 0 al hijo al ver rdx != 0).
static long bsd_fork(struct ctx* c) {
	long p = syscall(SYS_fork);
	if (p < 0) return -darwin_errno(errno);
	if (p == 0) reenable_dispatch();                     // el hijo empieza sin interceptación
	// Convenio de Darwin: hijo rax=pid del padre, rdx=1; padre rax=pid del hijo, rdx=0. libsyscall devuelve 0 al hijo
	// al ver rdx != 0, y libc ejecuta entonces los manejadores de hijo (reinicio de puertos Mach, hilo principal...).
	c->has_ret2 = 1;
	c->ret2 = (p == 0);
	return p == 0 ? getppid() : p;
}
static long bsd_wait4(struct ctx* c) {
	int st = 0;
	long r = syscall(SYS_wait4, (int)c->a[0], &st, (int)c->a[2], NULL);
	if (r < 0) return -darwin_errno(errno);
	if (c->a[1] && r > 0) { int ds = darwin_wait_status(st); if (safe_write(c->a[1], &ds, 4) != 4) return -D_EFAULT; }
	return r;
}
static long bsd_pipe(struct ctx* c) {
	int fds[2];
	if (pipe(fds) != 0) return -darwin_errno(errno);
	c->has_ret2 = 1;
	c->ret2 = (uint64_t)fds[1];
	return fds[0];
}
static long bsd_getpeername(struct ctx* c) { (void)c; return -38; }                // ENOTSOCK

// Lee un array de punteros a cadena del programa (argv o envp).
static int read_strv(uint64_t addr, char*** out, int max) {
	char** v = calloc(max + 1, sizeof(char*));
	int n = 0;
	for (; addr && n < max; n++) {
		uint64_t ptr;
		if (safe_read(addr + 8 * n, &ptr, 8) != 8 || !ptr) break;
		char tmp[131072];
		if (safe_string(ptr, tmp, sizeof tmp) != 0) break;
		v[n] = strdup(tmp);
	}
	*out = v;
	return n;
}

// Ruta del programa (vista de macOS) -> ruta real en el host.
static void host_path(const char* guest, char* out, size_t cap) {
	if (tahoe_root && guest[0] == '/') {
		snprintf(out, cap, "%s%s", tahoe_root, guest);
		if (access(out, F_OK) == 0) return;
	}
	snprintf(out, cap, "%s", guest);
}

// execve: se relanza tahoe-run con el programa nuevo. Soporta "#!" (hasta 4 niveles).
static char spawn_special_env[8][32];   // TAHOE_SP<n>=<puerto>: puertos especiales para el hijo (acciones de puerto de posix_spawn)
static int spawn_special_n;
static long exec_common(uint64_t pathp, uint64_t argvp, uint64_t envp, int spawn, pid_t* pidout) {
	char gpath[4096], hpath[4200];
	if (safe_string(pathp, gpath, sizeof gpath) != 0) return -D_EFAULT;
	char **av, **ev;
	int ac = read_strv(argvp, &av, 4096), ec = read_strv(envp, &ev, 4096);
	if (ac == 0) { av[0] = strdup(gpath); ac = 1; }
	for (int depth = 0; depth < 4; depth++) {
		host_path(gpath, hpath, sizeof hpath);
		if (access(hpath, X_OK) != 0) return -darwin_errno(errno);
		int fd = open(hpath, O_RDONLY);
		if (fd < 0) return -darwin_errno(errno);
		char head[256];
		ssize_t hn = read(fd, head, sizeof head - 1);
		close(fd);
		if (hn >= 2 && head[0] == '#' && head[1] == '!') {                   // script: ejecutar el intérprete
			head[hn] = 0;
			char* nl = strchr(head, '\n');
			if (nl) *nl = 0;
			char* interp = head + 2;
			while (*interp == ' ' || *interp == '\t') interp++;
			char* arg = interp;
			while (*arg && *arg != ' ' && *arg != '\t') arg++;
			if (*arg) { *arg++ = 0; while (*arg == ' ' || *arg == '\t') arg++; }
			char** nv = calloc(ac + 4, sizeof(char*));
			int k = 0;
			nv[k++] = strdup(interp);
			if (*arg) nv[k++] = strdup(arg);
			nv[k++] = strdup(gpath);
			for (int i = 1; i < ac; i++) nv[k++] = av[i];
			av = nv; ac = k;
			snprintf(gpath, sizeof gpath, "%s", interp);
			continue;
		}
		break;
	}
	// Programas que dependen de hardware/IOKit de verdad (montaje de volúmenes, fsck...) se sustituyen por un
	// proceso que sale con éxito. Lista configurable en TAHOE_STUB_EXEC (rutas separadas por comas).
	{
		const char* stubs = getenv("TAHOE_STUB_EXEC");
		if (!stubs) stubs = "/sbin/mount";
		size_t gl = strlen(gpath);
		for (const char* p = stubs; *p;) {
			const char* q = strchr(p, ',');
			size_t l = q ? (size_t)(q - p) : strlen(p);
			if (l == gl && !strncmp(p, gpath, l)) {
				logf_("    exec \"%s\" sustituido por un proceso que sale con 0\n", gpath);
				char* targv[] = { (char*)"true", NULL };
				if (spawn) { int pe = posix_spawnp(pidout, "true", NULL, NULL, targv, environ); return pe ? -darwin_errno(pe) : 0; }
				_exit(0);
			}
			p += l + (q ? 1 : 0);
		}
	}
	// argv de tahoe-run: [self, caché, dyld, programa(host), argumentos del programa...]
	char** nargv = calloc(ac + 5, sizeof(char*));
	int k = 0;
	nargv[k++] = (char*)g_self_exe;
	nargv[k++] = (char*)g_cache_path;
	nargv[k++] = (char*)g_dyld_path;
	nargv[k++] = hpath;
	for (int i = 1; i < ac; i++) nargv[k++] = av[i];
	char** nenv = calloc(ec + 10 + 8, sizeof(char*));
	int e = 0;
	for (int i = 0; i < ec; i++) nenv[e++] = ev[i];
	char b1[4300], b2[4300];
	if (tahoe_root) { snprintf(b1, sizeof b1, "TAHOE_ROOT=%s", tahoe_root); nenv[e++] = b1; }
	snprintf(b2, sizeof b2, "TAHOE_ARGV0=%s", av[0]);
	nenv[e++] = b2;
	static char b3[4300];
	static char b4[200], b5[40];
	if (getenv("TAHOE_PORTS")) { snprintf(b4, sizeof b4, "TAHOE_PORTS=%s", getenv("TAHOE_PORTS")); nenv[e++] = b4; }
	if (getenv("TAHOE_PORTS_OWNER")) { snprintf(b5, sizeof b5, "TAHOE_PORTS_OWNER=%s", getenv("TAHOE_PORTS_OWNER")); nenv[e++] = b5; }
	if (getenv("TAHOE_LOGFILE")) { snprintf(b3, sizeof b3, "TAHOE_LOGFILE=%s", getenv("TAHOE_LOGFILE")); nenv[e++] = b3; }
	static char b6[600];
	if (getenv("TAHOE_CACHE_DIR")) { snprintf(b6, sizeof b6, "TAHOE_CACHE_DIR=%s", getenv("TAHOE_CACHE_DIR")); nenv[e++] = b6; }
	if (getenv("TAHOE_FD2LOG")) nenv[e++] = (char*)"TAHOE_FD2LOG=1";
	if (trace_all) nenv[e++] = (char*)"TAHOE_TRACE=1";
	for (int i = 0; i < spawn_special_n; i++) nenv[e++] = spawn_special_env[i];
	if (trace_all) logf_("    execve(\"%s\") -> relanzando tahoe-run\n", gpath);
	if (spawn) {
		int pe = posix_spawn(pidout, g_self_exe, NULL, NULL, nargv, nenv);
		return pe ? -darwin_errno(pe) : 0;
	}
	execve(g_self_exe, nargv, nenv);
	return -darwin_errno(errno);
}

static long bsd_execve(struct ctx* c) { return exec_common(c->a[0], c->a[1], c->a[2], 0, NULL); }

// posix_spawn(pid*, ruta, adesc*, argv, envp): crea un proceso nuevo de tahoe-run. De momento se ignoran los
// atributos y las acciones sobre archivos (se avisa en el registro); POSIX_SPAWN_SETEXEC se trata como execve.
static long bsd_posix_spawn(struct ctx* c) {
	uint64_t ad[6] = { 0 };
	uint16_t psa_flags = 0;
	if (c->a[2]) {
		safe_read(c->a[2], ad, sizeof ad);                          // attr_size, attrp, file_actions_size, file_actions
		if (ad[1]) safe_read(ad[1], &psa_flags, 2);
	}
	char gp[256] = "?";
	safe_string(c->a[1], gp, sizeof gp);
	spawn_special_n = 0;
	if (ad[5] && ad[4] >= 8) {                                      // acciones de puerto: PSPA_SPECIAL (1) fija un puerto especial del hijo
		int hdr[2] = { 0, 0 };
		safe_read(ad[5], hdr, 8);
		for (int i = 0; i < hdr[1] && i < 8; i++) {
			uint32_t act[6] = { 0 };                                // port_type, mask, new_port, behavior, flavor, which
			if (safe_read(ad[5] + 8 + i * 24, act, 24) != 24) break;
			if (act[0] == 1 && spawn_special_n < 8) snprintf(spawn_special_env[spawn_special_n++], 32, "TAHOE_SP%u=%u", act[5], act[2]);
			logf_("    posix_spawn: acción de puerto tipo=%u which=%u puerto=0x%x\n", act[0], act[5], act[2]);
		}
	}
	logf_("    posix_spawn(\"%s\") attr_flags=0x%x ad=%lx,%lx,%lx,%lx,%lx,%lx\n", gp, psa_flags, ad[0], ad[1], ad[2], ad[3], ad[4], ad[5]);
	if (psa_flags & 0x40) return exec_common(c->a[1], c->a[3], c->a[4], 0, NULL);
	pid_t pid = 0;
	long r = exec_common(c->a[1], c->a[3], c->a[4], 1, &pid);
	if (r == 0 && c->a[0]) { uint32_t p = (uint32_t)pid; safe_write(c->a[0], &p, 4); }
	return r;
}

// bsdthread_ctl(comando, arg1, arg2, arg3): QoS, sobrescrituras de prioridad y permisos de las colas de trabajo.
// libdispatch llama a BSDTHREAD_CTL_WORKQ_ALLOW_KILL (0x1000) tras un fork y ABORTA si falla; sin colas de trabajo
// reales todos los comandos pueden aceptarse sin efecto.
static long bsd_bsdthread_ctl(struct ctx* c) {
	if (trace_all) logf_("    bsdthread_ctl(cmd=0x%lx, 0x%lx) -> sin efecto\n", c->a[0], c->a[1]);
	return 0;
}

// bsdthread_create(func, arg, stack, pthread, flags): crea un hilo de Linux que arranca en thread_start (el
// punto de entrada que libpthread registró en bsdthread_register) con la pila que eligió libpthread.
// Salidas de los hilos del invitado: al terminar (bsdthread_terminate) o aparcarse (workq_kernreturn) se vuelve con
// siglongjmp a la función del anfitrión que los lanzó, para que el pthread de Linux termine normalmente y libere su pila.
static __thread sigjmp_buf thr_exit, wq_park;
static __thread int thr_exit_ok, wq_park_ok, wq_terminated;
extern void guest_thread_done(void);
struct new_thread { uint64_t pthread, func, arg, stack, flags; };
extern void enter_guest_thread(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) __attribute__((noreturn));
static void* thread_main(void* p) {
	struct new_thread t = *(struct new_thread*)p;
	free(p);
	// Como XNU: base de GS en el TSD del hilo, se avisa con TSD_BASE_SET y se retira SUSPENDED (libpthread lo exige).
	{ FILE* f = fopen("/dev/shm/tahoe-watch-func", "r"); unsigned long fn = 0; if (f) { if (fscanf(f, "%lx", &fn) != 1) fn = 0; fclose(f); } g_watch = fn && fn == t.func; }
	uint64_t flags = t.flags & ~0x20000000u;
	uint32_t kport = alloc_port();
	if (mach_trace()) logf_("    THR <%d:%ld> puerto de hilo 0x%x func=0x%lx\n", (int)getpid(), (long)syscall(SYS_gettid), kport, t.func);
	// cada hilo tiene su propio nombre de puerto (os_unfair_lock lo usa como dueño)
	if (mach_thread_self_offset) *(uint32_t*)(t.pthread + tsd_offset + mach_thread_self_offset) = kport;   // el kernel deja aquí el puerto del hilo (relativo al TSD)
	if (tsd_offset) { syscall(SYS_arch_prctl, 0x1001 /*ARCH_SET_GS*/, t.pthread + tsd_offset); flags |= 0x10000000u; }
	if (sigsetjmp(thr_exit, 1) == 0) {
		thr_exit_ok = 1;
		enter_guest_thread(thread_start_fn, t.stack, t.pthread, kport, t.func, t.arg, t.stack, flags);
	}
	guest_thread_done();                                             // pthread de Linux termina y libera su pila
	return NULL;
}
static long bsd_bsdthread_create(struct ctx* c) {
	struct new_thread* t = malloc(sizeof *t);
	if (!t) return -D_ENOMEM;
	*t = (struct new_thread){ .pthread = c->a[3], .func = c->a[0], .arg = c->a[1], .stack = c->a[2], .flags = c->a[4] };
	pthread_attr_t at; pthread_attr_init(&at);
	pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&at, 1 << 20);
	pthread_t th;
	int e = pthread_create(&th, &at, thread_main, t);
	if (e) { free(t); return -35 /* EAGAIN de Darwin */; }
	if (mach_trace()) { uint64_t w[8] = { 0 }; safe_read(c->a[3] + 0, w, 0); safe_read(c->a[1], w, 64);   // arg de thread_fun: estructura con la rutina real
		logf_("    THR <%d> crea hilo func=0x%lx arg=0x%lx [%lx %lx %lx %lx]\n", (int)getpid(), c->a[0], c->a[1], w[0], w[1], w[2], w[3]); }
	if (trace_all) logf_("    bsdthread_create: pthread=0x%lx stack=0x%lx flags=0x%lx\n", c->a[3], c->a[2], c->a[4]);
	return (long)c->a[3];
}
// bsdthread_terminate(stackaddr, freesize, port, sem): libera la pila del hilo y termina solo este hilo.
static long bsd_bsdthread_terminate(struct ctx* c) {
	if (mach_trace()) logf_("    THR <%d> termina hilo\n", (int)getpid());
	// Hilo del grupo: su pila la reservó este emulador (wq_main la libera). libpthread calcula el rango a liberar con su
	// propia idea de la pila del núcleo y podría alcanzar memoria vecina (la pila del anfitrión), así que se ignora.
	if (wq_park_ok) { wq_terminated = 1; siglongjmp(wq_park, 1); }
	if (c->a[0] && c->a[1]) munmap((void*)c->a[0], c->a[1]);
	if (thr_exit_ok) siglongjmp(thr_exit, 1);                        // hilo de bsdthread_create: termina su función normalmente
	syscall(SYS_exit, 0);
	return 0;
}

// ---------------------------------------------------------------- colas de trabajo (workqueue)
// Sin kernel, los hilos de las colas de trabajo los lanza este emulador: cada petición (hilos de un nivel de QoS o
// un workloop de libdispatch) crea un hilo de Linux con su propia pila y pthread_t, y entra en wqthread con los
// mismos registros y banderas que usa XNU: rdi=pthread, rsi=puerto, rdx=pila baja, rcx=lista de eventos, r8=banderas,
// r9=nº de eventos. El hilo termina cuando libpthread llama a workq_kernreturn para "aparcarse".
#define WQ_PRIO_QOS   0x00004000u
#define WQ_NEWSPI     0x00040000u
#define WQ_KEVENT     0x00080000u
#define WQ_TSD_SET    0x00200000u
#define WQ_WORKLOOP   0x00400000u
#define WQ_REUSE      0x00020000u   // el hilo ya pasó por libpthread: su pthread_t sigue en la lista y no se reinicia
#define WQ_STACK      (1u << 20)
static __thread uint64_t my_workloop;   // workloop que atiende este hilo
#define WQ_DATA_SIZE 32768
// npre/pre/pdata: eventos que el vigilante ya recogió del kqueue (y el búfer donde quedaron los mensajes Mach recibidos).
struct wq_job { uint64_t kqid; int workloop, has_req, npre; uint8_t req[72]; uint8_t pre[16 * 72]; uint8_t* pdata; struct wq_job* next; };
struct wl_state { uint64_t kqid; int running, pending, watching, has_req; uint8_t req[72]; struct wl_state* next; };   // watching: ya tiene vigilante
extern int kq_workloop_fd(uint64_t);
extern long kq_drain(uint64_t, uint64_t, int, uint64_t, uint64_t);
static void wl_arm(uint64_t kqid);
// El kernel solo lanza el hilo si el estado de la cola sigue siendo el que esperaba libdispatch:
// (*ext[ADDR] & ext[MASK]) == ext[VALUE]; si cambió, la petición está obsoleta y se descarta.
static int req_still_valid(const uint8_t* req) {
	uint64_t ext[4];
	memcpy(ext, req + 40, 32);
	if (!ext[1] || !ext[2]) return 1;
	uint64_t cur;
	if (safe_read(ext[1], &cur, 8) != 8) return 1;
	return (cur & ext[2]) == (ext[3] & ext[2]);
}
static struct wl_state* wl_states;
static pthread_mutex_t wl_lock = PTHREAD_MUTEX_INITIALIZER;

// Hilos de las colas de trabajo: un grupo reutilizable. Cuando libpthread "aparca" un hilo (workq_kernreturn) no se
// termina: se vuelve a la función del anfitrión con siglongjmp y el hilo espera la siguiente petición. Así las pilas
// (la del anfitrión, la del invitado y la alterna de SIGSYS) se crean una vez y no se fugan, y un bucle de peticiones
// no puede crear hilos sin límite: pasado WQ_MAX_HILOS las peticiones esperan en cola.
#define WQ_MAX_HILOS 48
#define WQ_IDLE_MS   4000
static pthread_mutex_t wq_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wq_pool_cv = PTHREAD_COND_INITIALIZER;
static struct wq_job* wq_queue_head; static struct wq_job** wq_queue_tail = &wq_queue_head;
static int wq_live, wq_idle;

// first: primer servicio de este hilo (libpthread inicializa su pthread_t). exit_thread: en vez de trabajo, la llamada de
// salida de XNU (nkevents = -1, WORKQ_EXIT_THREAD_NKEVENT) para que libpthread retire el hilo de su lista y lo termine.
static void wq_run_job(const struct wq_job* jp, uint8_t* base, size_t psize, int first, int exit_thread) {
	struct { uint64_t kqid; int workloop, has_req; uint8_t req[72]; } j = { jp->kqid, jp->workloop, jp->has_req, { 0 } };
	memcpy(j.req, jp->req, 72);
	uint64_t self = (uint64_t)base + WQ_STACK;
	if (first) memset(base + WQ_STACK - 0x3000, 0, 0x3000 + psize);   // pthread_t limpio solo la primera vez
	uint64_t kqid_slot = self - 0x2000, events = kqid_slot + 8;
	uint64_t flags = WQ_NEWSPI | WQ_PRIO_QOS | 5 /* THREAD_QOS_DEFAULT */;
	if (tsd_offset) { syscall(SYS_arch_prctl, 0x1001 /*ARCH_SET_GS*/, self + tsd_offset); flags |= WQ_TSD_SET; }
	if (!first) flags |= WQ_REUSE;
	int nev = 0;
	my_workloop = j.workloop ? j.kqid : 0;
	static __thread uint8_t* data;                                   // búfer de datos (32 KB) de los mensajes Mach, uno por hilo
	if (exit_thread) { j.workloop = 0; nev = -1; }
	if (j.workloop) { *(uint64_t*)kqid_slot = j.kqid; flags |= (j.kqid == ~0ULL ? 0 : WQ_WORKLOOP) | WQ_KEVENT; if (j.has_req) { memcpy((void*)events, j.req, 72); nev = 1; }
		if (jp->npre) { memcpy((void*)(events + nev * 72), jp->pre, (size_t)jp->npre * 72); nev += jp->npre; }   // ya recogidos por el vigilante
		else {
			if (!data) data = mmap(NULL, WQ_DATA_SIZE + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			uint64_t* avail = (uint64_t*)(data + WQ_DATA_SIZE);
			*avail = WQ_DATA_SIZE;
			long d = kq_drain(j.kqid, events + nev * 72, 16 - nev, (uint64_t)data, (uint64_t)avail);
			if (d > 0) nev += (int)d;
		} }
	if (trace_all) logf_("    wqthread: %s kqid=0x%lx pthread=0x%lx flags=0x%lx\n", j.workloop ? "workloop" : "worker", j.kqid, self, flags);
	if (sigsetjmp(wq_park, 1) == 0) {
		wq_park_ok = 1;
		static __thread uint32_t kp_cache; if (!kp_cache) kp_cache = alloc_port();
		uint32_t kp = kp_cache;
		if (mach_trace()) logf_("    THR <%d:%ld> hilo de cola puerto 0x%x\n", (int)getpid(), (long)syscall(SYS_gettid), kp);
		enter_guest_thread(wqthread_fn, self - 0x3000, self, kp, (uint64_t)base, j.workloop ? events : 0, flags, (uint64_t)(int64_t)nev);
	}
	wq_park_ok = 0;                                                  // volvió el hilo aparcado
}

static void* wq_main(void* p) {
	struct wq_job* first = p;
	size_t psize = pthread_size ? pthread_size : 0x2000;
	uint8_t* base = mmap(NULL, WQ_STACK + psize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	struct wq_job* job = first;
	if (base == MAP_FAILED) { free(first); pthread_mutex_lock(&wq_pool_lock); wq_live--; pthread_mutex_unlock(&wq_pool_lock); return NULL; }
	int first_use = 1;
	for (;;) {
		wq_run_job(job, base, psize, first_use, 0);
		first_use = 0;
		if (job->pdata) munmap(job->pdata, WQ_DATA_SIZE + 4096);
		free(job);
		if (wq_terminated) { pthread_mutex_lock(&wq_pool_lock); wq_live--; pthread_mutex_unlock(&wq_pool_lock); guest_thread_done(); munmap(base, WQ_STACK + psize); return NULL; }   // pthread_exit dentro de un trabajo
		pthread_mutex_lock(&wq_pool_lock);
		job = NULL;
		for (;;) {
			if (wq_queue_head) { job = wq_queue_head; wq_queue_head = job->next; if (!wq_queue_head) wq_queue_tail = &wq_queue_head; break; }
			struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl);
			dl.tv_sec += WQ_IDLE_MS / 1000; dl.tv_nsec += (WQ_IDLE_MS % 1000) * 1000000L; if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
			wq_idle++;
			int rc = pthread_cond_timedwait(&wq_pool_cv, &wq_pool_lock, &dl);
			wq_idle--;
			if (rc && !wq_queue_head) break;                         // sin trabajo tras esperar: el hilo termina
		}
		if (!job) { wq_live--; pthread_mutex_unlock(&wq_pool_lock); break; }
		pthread_mutex_unlock(&wq_pool_lock);
	}
	// Inactivo: como XNU, se devuelve el hilo a libpthread con la llamada de salida; libpthread lo quita de su lista y
	// llama a bsdthread_terminate, que libera la pila del invitado y vuelve aquí.
	struct wq_job bye = { 0 };
	wq_run_job(&bye, base, psize, 0, 1);
	guest_thread_done();
	munmap(base, WQ_STACK + psize);
	return NULL;
}

static void wq_spawn_job(struct wq_job* j) {
	pthread_mutex_lock(&wq_pool_lock);
	if (wq_idle > 0 || wq_live >= WQ_MAX_HILOS) {                  // un hilo libre la atiende, o espera turno
		*wq_queue_tail = j; wq_queue_tail = &j->next;
		pthread_cond_signal(&wq_pool_cv);
		pthread_mutex_unlock(&wq_pool_lock);
		return;
	}
	wq_live++;
	pthread_mutex_unlock(&wq_pool_lock);
	pthread_attr_t at; pthread_attr_init(&at);
	pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&at, 1 << 20);
	pthread_t th;
	if (pthread_create(&th, &at, wq_main, j)) { if (j->pdata) munmap(j->pdata, WQ_DATA_SIZE + 4096); free(j); pthread_mutex_lock(&wq_pool_lock); wq_live--; pthread_mutex_unlock(&wq_pool_lock); }
}
static void wq_spawn(uint64_t kqid, int workloop, const uint8_t* req) {
	struct wq_job* j = calloc(1, sizeof *j);
	if (!j) return;
	j->kqid = kqid; j->workloop = workloop;
	if (req) { j->has_req = 1; memcpy(j->req, req, 72); }
	wq_spawn_job(j);
}

// Petición de hilo para un workloop (EVFILT_WORKLOOP con NOTE_WL_THREAD_REQUEST). Un solo hilo por workloop a la vez.
void wq_request_workloop(uint64_t kqid, const void* req) {
	pthread_mutex_lock(&wl_lock);
	struct wl_state* w = wl_states;
	while (w && w->kqid != kqid) w = w->next;
	if (!w) { w = calloc(1, sizeof *w); w->kqid = kqid; w->next = wl_states; wl_states = w; }
	int valid = req_still_valid(req);
	int start = !w->running && valid;
	memcpy(w->req, req, 72); w->has_req = 1;
	uint8_t copy[72]; memcpy(copy, req, 72);
	if (start) w->running = 1; else if (valid) w->pending = 1;
	pthread_mutex_unlock(&wl_lock);
	if (start) wq_spawn(kqid, 1, copy);
}

static pthread_cond_t wl_cv = PTHREAD_COND_INITIALIZER;     // avisa a los vigilantes de que su workloop quedó libre

static void wl_finished(uint64_t kqid) {
	pthread_mutex_lock(&wl_lock);
	struct wl_state* w = wl_states;
	while (w && w->kqid != kqid) w = w->next;
	int again = w && w->pending && req_still_valid(w->req);
	uint8_t copy[72];
	if (w) { w->pending = 0; w->running = again; memcpy(copy, w->req, 72); }
	pthread_cond_broadcast(&wl_cv);
	pthread_mutex_unlock(&wl_lock);
	if (again) wq_spawn(kqid, 1, copy); else wl_arm(kqid);
}

// Vigilante de un workloop: un hilo fijo por workloop. Mientras el workloop no tiene hilo, espera a que su kqueue esté
// listo, recoge él mismo los eventos y solo entonces lanza un hilo con ellos. poll() sobre un epoll puede avisar en
// falso (el aviso de un puerto ya se consumió por otra vía); en ese caso no se lanza nada y se vuelve a esperar.
static void* wl_watch(void* p) {
	uint64_t kqid = (uint64_t)p;
	int fd = kq_workloop_fd(kqid);
	pthread_mutex_lock(&wl_lock);
	struct wl_state* w = wl_states;
	while (w && w->kqid != kqid) w = w->next;
	pthread_mutex_unlock(&wl_lock);
	if (mach_trace()) logf_("    wl_watch <%d> kqid=0x%lx fd=%d inicia (w=%p)\n", (int)getpid(), (unsigned long)kqid, fd, (void*)w);
	if (!w || fd < 0) return NULL;
	for (;;) {
		pthread_mutex_lock(&wl_lock);
		while (w->running) pthread_cond_wait(&wl_cv, &wl_lock);
		pthread_mutex_unlock(&wl_lock);
		struct pollfd pf = { .fd = fd, .events = POLLIN };
		if (poll(&pf, 1, -1) < 0) { if (errno == EINTR) continue; logf_("    wl_watch <%d>: poll falló: %s\n", (int)getpid(), strerror(errno)); break; }
		if (!(pf.revents & POLLIN)) continue;
		pthread_mutex_lock(&wl_lock);
		if (w->running) { pthread_mutex_unlock(&wl_lock); continue; }   // otra petición ya lanzó el hilo
		w->running = 1;
		pthread_mutex_unlock(&wl_lock);
		struct wq_job* j = calloc(1, sizeof *j);
		uint8_t* data = mmap(NULL, WQ_DATA_SIZE + 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		long d = 0;
		if (j && data != MAP_FAILED) {
			uint64_t* avail = (uint64_t*)(data + WQ_DATA_SIZE);
			*avail = WQ_DATA_SIZE;
			d = kq_drain(kqid, (uint64_t)j->pre, 16, (uint64_t)data, (uint64_t)avail);
		}
		if (mach_trace()) logf_("    wl_watch <%d> kqid=0x%lx recogió %ld\n", (int)getpid(), (unsigned long)kqid, d);
		if (d > 0) {
			j->kqid = kqid; j->workloop = 1; j->npre = (int)d; j->pdata = data;
			wq_spawn_job(j);
			continue;
		}
		free(j);
		if (data != MAP_FAILED) munmap(data, WQ_DATA_SIZE + 4096);
		static __thread int fails; static __thread int dumped;
		if (++fails == 2000 && !dumped && mach_trace()) {             // diagnóstico: qué descriptor mantiene listo el epoll sin dar eventos
			dumped = 1;
			char pth[64], ln[256]; snprintf(pth, sizeof pth, "/proc/self/fdinfo/%d", fd);
			FILE* f = fopen(pth, "r");
			while (f && fgets(ln, sizeof ln, f)) {
				int tfd = -1; unsigned ev = 0; unsigned long long dat = 0;
				if (sscanf(ln, "tfd: %d events: %x data: %llx", &tfd, &ev, &dat) >= 2) {
					char lk[128] = "", fp[64]; snprintf(fp, sizeof fp, "/proc/self/fd/%d", tfd); ssize_t n = readlink(fp, lk, sizeof lk - 1); if (n > 0) lk[n] = 0;
					struct pollfd q = { .fd = tfd, .events = POLLIN | POLLOUT }; poll(&q, 1, 0);
					logf_("    wl_watch <%d> fd %d en epoll %d: eventos=0x%x listo=0x%x knote=0x%llx %s\n", (int)getpid(), tfd, fd, ev, q.revents, dat, lk);
				}
			}
			if (f) fclose(f);
		}
		pthread_mutex_lock(&wl_lock);                               // aviso falso: liberar, salvo que entretanto llegara una petición
		int again = w->pending && req_still_valid(w->req);
		uint8_t copy[72]; memcpy(copy, w->req, 72);
		w->pending = 0; w->running = again;
		pthread_mutex_unlock(&wl_lock);
		if (again) wq_spawn(kqid, 1, copy);
	}
	return NULL;
}
static void wl_arm(uint64_t kqid) {
	pthread_mutex_lock(&wl_lock);
	struct wl_state* w = wl_states;
	while (w && w->kqid != kqid) w = w->next;
	if (!w) { w = calloc(1, sizeof *w); w->kqid = kqid; w->next = wl_states; wl_states = w; }
	int start = !w->watching;
	if (start) w->watching = 1;
	if (mach_trace()) logf_("    wl_arm <%d> kqid=0x%lx start=%d running=%d\n", (int)getpid(), (unsigned long)kqid, start, w->running);
	pthread_cond_broadcast(&wl_cv);
	pthread_mutex_unlock(&wl_lock);
	if (!start) return;
	pthread_attr_t at; pthread_attr_init(&at);
	pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&at, 1 << 21);   // el TLS estático del emulador (búferes de mach_msg) vive en esta pila
	pthread_t th;
	if (pthread_create(&th, &at, wl_watch, (void*)kqid)) { pthread_mutex_lock(&wl_lock); w->watching = 0; pthread_mutex_unlock(&wl_lock); }
}

static long bsd_workq_open(struct ctx* c) { (void)c; return 0; }
void wq_note_workloop(uint64_t kqid) { (void)kqid; }
void wq_arm_workloop(uint64_t kqid) { wl_arm(kqid); }   // vigilar los eventos de este workloop aunque aún no tenga hilo
extern long kq_apply_changes(int layout, uint64_t chg, long n, uint64_t workloop);

static long bsd_workq_kernreturn(struct ctx* c) {
	uint64_t op = c->a[0];
	if (trace_all) logf_("    workq_kernreturn(op=0x%lx, 0x%lx, %ld, 0x%lx)\n", op, c->a[1], (long)c->a[2], c->a[3]);
	switch (op) {
	case 0x400: case 0x10: return 0;                                   // SETUP_DISPATCH, NEWSPISUPP
	case 0x20: case 0x30: {                                            // REQTHREADS(n): hilos de trabajo normales
		long n = op == 0x20 ? (long)(int)c->a[2] : 1;
		for (long i = 0; i < n && i < 8; i++) wq_spawn(0, 0, NULL);
		return 0;
	}
	case 0x200: return 0;                                              // SHOULD_NARROW: no
	case 0x80: return 0;                                               // SET_EVENT_MANAGER_PRIORITY
	case 0x100: case 0x40: case 0x04: {                                // retorno de hilo: se aparca = termina
		if (trace_all && op == 0x100) for (long i = 0; i < (long)(int)c->a[2] && i < 4; i++) {
			uint8_t kv[72]; uint64_t id, ud, ext[4]; int16_t f; uint16_t fl; uint32_t ff;
			if (safe_read(c->a[1] + i * 72, kv, 72) != 72) break;
			memcpy(&id, kv, 8); memcpy(&f, kv + 8, 2); memcpy(&fl, kv + 10, 2); memcpy(&ud, kv + 16, 8); memcpy(&ff, kv + 24, 4); memcpy(ext, kv + 40, 32);
			logf_("      retorno: ident=0x%lx filter=%d flags=0x%x fflags=0x%x udata=0x%lx ext=%lx,%lx,%lx,%lx\n", id, f, fl, ff, ud, ext[0], ext[1], ext[2], ext[3]);
		}
		if ((op == 0x100 || op == 0x40) && (long)(int)c->a[2] > 0) kq_apply_changes(2, c->a[1], (long)(int)c->a[2], my_workloop);   // 0x40: THREAD_KEVENT_RETURN
		if ((op == 0x100 || op == 0x40) && my_workloop) wl_finished(my_workloop);
		if (wq_park_ok) siglongjmp(wq_park, 1);                    // aparcar = volver al grupo de hilos
		syscall(SYS_exit, 0);
		return 0;
	}
	}
	return 0;
}


static long bsd_proc_rlimit_control(struct ctx* c) { (void)c; return 0; }   // límites de monitorización: sin efecto

static long bsd_audit_session_self(struct ctx* c) { (void)c; return 0x1503; }   // puerto ficticio de la sesión de auditoría

// getaudit_addr(auditinfo_addr_t*, tamaño 0x30): auid=-1 (sin sesión de inicio), máscara 0, terminal vacío y
// un identificador de sesión de auditoría no nulo.
static long bsd_getaudit_addr(struct ctx* c) {
	uint8_t a[0x30] = { 0 };
	uint32_t auid = (uint32_t)-1, asid = (uint32_t)getpid();
	memcpy(a, &auid, 4);
	memcpy(a + 36, &asid, 4);
	return safe_write(c->a[0], a, c->a[1] < sizeof a ? c->a[1] : sizeof a) < 0 ? -D_EFAULT : 0;
}

// sigsuspend(mask): aquí no hay señales de Darwin reales todavía; el hilo se duerme hasta que Linux lo interrumpa.
static long bsd_sigsuspend(struct ctx* c) { (void)c; syscall(SYS_pause); return -4; /* EINTR */ }

// map_with_linking_np (dyld): sin soporte; dyld aplica los fixups por su cuenta cuando devuelve error.
static long bsd_map_with_linking(struct ctx* c) { (void)c; return -D_ENOSYS; }

// ulock (os_unfair_lock, dispatch_once, libpthread): ulock_wait/ulock_wake sobre futex de Linux. Con ULF_NO_ERRNO
// (0x1000000) los errores vuelven como valor negativo en lugar de por errno; aquí se devuelven siempre como errno.
#include <linux/futex.h>
// Diagnóstico: tabla de los hilos que esperan en un ulock; un hilo vigilante la vuelca pasados unos segundos.
static struct { volatile long tid; volatile uint32_t* addr; volatile uint32_t expect; volatile uint64_t op; volatile uint64_t spin; } wait_tab[256];
static void* wait_dump_thread(void* a) {
	(void)a;
	sleep(12);
	for (int i = 0; i < 256; i++) if (wait_tab[i].tid) logf_("    WAITTAB tid=%ld addr=%p esperado=0x%x op=0x%lx valor_actual=0x%x (%lx)\n", wait_tab[i].tid, (void*)wait_tab[i].addr, wait_tab[i].expect, (unsigned long)wait_tab[i].op, *wait_tab[i].addr, (unsigned long)((uint64_t*)wait_tab[i].addr)[0]);
	return NULL;
}
// XNU devuelve de ulock_wait cuántos hilos más siguen esperando en esa dirección (también cuando el valor ya no
// coincidía). libplatform lo usa para no marcar un os_unfair_lock "sin esperadores" al adquirirlo tras despertar; y
// libdispatch aborta si una espera de la que es el único dueño devuelve > 0. Por eso la cuenta es exacta por dirección.
struct uwait { uintptr_t addr; int n; struct uwait* next; };
static struct uwait* uwait_tab[1024];
static pthread_mutex_t uwait_lock = PTHREAD_MUTEX_INITIALIZER;
static void uwait_enter(uintptr_t a) {
	pthread_mutex_lock(&uwait_lock);
	struct uwait** b = &uwait_tab[(a >> 2) & 1023], *w = *b;
	while (w && w->addr != a) w = w->next;
	if (!w) { w = calloc(1, sizeof *w); w->addr = a; w->next = *b; *b = w; }
	w->n++;
	pthread_mutex_unlock(&uwait_lock);
}
static int uwait_leave(uintptr_t a) {                // devuelve cuántos quedan esperando
	pthread_mutex_lock(&uwait_lock);
	struct uwait** pp = &uwait_tab[(a >> 2) & 1023];
	while (*pp && (*pp)->addr != a) pp = &(*pp)->next;
	int left = 0;
	if (*pp) { left = --(*pp)->n; if (left <= 0) { struct uwait* d = *pp; *pp = d->next; free(d); left = 0; } }
	pthread_mutex_unlock(&uwait_lock);
	return left;
}
static long ulock_wait_impl(struct ctx* c, uint64_t timeout_ns) {
	uint32_t* addr = (uint32_t*)c->a[1];
	uint32_t expect = (uint32_t)c->a[2];
	struct timespec ts, *tp = NULL;
	if (timeout_ns) { ts.tv_sec = timeout_ns / 1000000000ULL; ts.tv_nsec = timeout_ns % 1000000000ULL; tp = &ts; }
	if (c->a[0] & 0x1000000) c->raw_ret = 1;     // ULF_NO_ERRNO
	if (mach_trace()) {                          // diagnóstico: pila de cada hilo que se bloquea sin plazo en el proceso indicado por /dev/shm/tahoe-stacks
		int want = diag_target();
		if (want && (!timeout_ns || syscall(SYS_gettid) == getpid())) { logf_("    ULW <%d:%ld> %p esperado=0x%x plazo=%lu op=0x%lx\n", (int)getpid(), (long)syscall(SYS_gettid), (void*)addr, expect, (unsigned long)timeout_ns, c->a[0]); { uint64_t m[8] = { 0 }; safe_read((uint64_t)addr - 24, m, 64); logf_("    ULW mem[-24..+40]: %lx %lx %lx %lx %lx %lx %lx %lx\n", m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]); } diag_crash(c->uc); }
	}
	if (trace_all) logf_("    ulock_wait(op=0x%lx, %p, esperado=0x%x, plazo=%luns)\n", c->a[0], (void*)addr, expect, (unsigned long)timeout_ns);
	int wslot = -1;
	if (mach_trace() && access("/dev/shm/tahoe-waittab", F_OK) == 0) {
		static pthread_once_t once = PTHREAD_ONCE_INIT; static int started;
		if (!started) { started = 1; pthread_t th; pthread_create(&th, NULL, wait_dump_thread, NULL); pthread_detach(th); }
		(void)once;
		for (int i = 0; i < 256; i++) { long z = 0; if (__atomic_compare_exchange_n(&wait_tab[i].tid, &z, (long)syscall(SYS_gettid), 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { wslot = i; wait_tab[i].addr = addr; wait_tab[i].expect = expect; wait_tab[i].op = c->a[0]; break; } }
	}
	uwait_enter((uintptr_t)addr);
	long r = syscall(SYS_futex, addr, FUTEX_WAIT_PRIVATE, expect, tp, NULL, 0);
	int e = errno;
	int others = uwait_leave((uintptr_t)addr);
	if (wslot >= 0) wait_tab[wslot].tid = 0;
	if (r == 0) return others;
	switch (e) {
	case EAGAIN: return others;                  // el valor ya cambió: no hay que esperar
	case ETIMEDOUT: return -60;                  // ETIMEDOUT de Darwin
	case EINTR: return -4;
	default: return -darwin_errno(e);
	}
}
static long bsd_ulock_wait(struct ctx* c)  { return ulock_wait_impl(c, (uint64_t)(uint32_t)c->a[3] * 1000ULL); }   // plazo en microsegundos
static long bsd_ulock_wait2(struct ctx* c) { return ulock_wait_impl(c, c->a[3]); }                                 // plazo en nanosegundos
static long bsd_ulock_wake(struct ctx* c) {
	if (g_watch) { uint64_t m[8] = { 0 }; safe_read(c->a[1] - 24, m, 64); logf_("    WATCH ulock_wake op=0x%lx %p mem[-24..+40]: %lx %lx %lx %lx %lx %lx %lx %lx\n", c->a[0], (void*)c->a[1], m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]); }
	if (c->a[0] & 0x1000000) c->raw_ret = 1;
	long n = syscall(SYS_futex, (uint32_t*)c->a[1], FUTEX_WAKE_PRIVATE, (c->a[0] & 0x100) ? 0x7fffffff : 1, NULL, NULL, 0);
	return n > 0 ? 0 : -D_ENOENT;
}

void emu_proc_init(void) {
	reg_bsd(515, bsd_ulock_wait); reg_bsd(516, bsd_ulock_wake); reg_bsd(544, bsd_ulock_wait2);
	reg_bsd(550, bsd_map_with_linking);
	reg_bsd(322, bsd_proc_rlimit_control);   // iopolicysys: sin efecto
	reg_bsd(331, bsd_proc_rlimit_control);   // __disable_threadsignal: sin efecto
	reg_bsd(111, bsd_sigsuspend); reg_bsd(410, bsd_sigsuspend);
	reg_bsd(357, bsd_getaudit_addr);
	reg_bsd(428, bsd_audit_session_self);
	reg_bsd(446, bsd_proc_rlimit_control);
	reg_bsd(243, bsd_proc_rlimit_control);   // initgroups: sin efecto
	reg_bsd(499, bsd_work_interval_ctl);
	reg_bsd(440, bsd_proc_rlimit_control);   // memorystatus_control: sin efecto reg_bsd(444, bsd_proc_rlimit_control);   // change_fdguard_np
	reg_bsd(552, bsd_proc_rlimit_control);   // record_system_event: sin efecto
	reg_bsd(358, bsd_proc_rlimit_control);   // setaudit_addr: sin efecto
	reg_bsd(50, bsd_proc_rlimit_control);   // setlogin: sin efecto
	reg_bsd(367, bsd_workq_open); reg_bsd(368, bsd_workq_kernreturn);
	reg_bsd(360, bsd_bsdthread_create); reg_bsd(361, bsd_bsdthread_terminate);
	reg_bsd(478, bsd_bsdthread_ctl);
	reg_bsd(244, bsd_posix_spawn);
	reg_bsd(2, bsd_fork); reg_bsd(66, bsd_fork); reg_bsd(7, bsd_wait4); reg_bsd(42, bsd_pipe);
	reg_bsd(31, bsd_getpeername); reg_bsd(59, bsd_execve);
	reg_bsd(39, bsd_getppid); reg_bsd(81, bsd_getpgrp); reg_bsd(151, bsd_getpgid); reg_bsd(82, bsd_setpgid);
	reg_bsd(310, bsd_getsid); reg_bsd(147, bsd_setsid); reg_bsd(60, bsd_umask);
	reg_bsd(194, bsd_getrlimit); reg_bsd(195, bsd_setrlimit);
	reg_bsd(46, bsd_sigaction); reg_bsd(53, bsd_sigaltstack); reg_bsd(329, bsd_pthread_sigmask); reg_bsd(52, bsd_sigpending);
	reg_bsd(37, bsd_kill); reg_bsd(328, bsd_pthread_kill);
	reg_bsd(98, bsd_connect);
	reg_bsd(97, bsd_socket);
	reg_bsd(267, bsd_shm_unlink);
	reg_bsd(116, bsd_gettimeofday); reg_bsd(266, bsd_shm_open); reg_bsd(54, bsd_ioctl);
	reg_bsd(366, bsd_bsdthread_register);
}

