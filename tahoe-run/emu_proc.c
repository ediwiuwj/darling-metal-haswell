// Procesos, hilos y señales: bsdthread_register, sigaction, etc.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "tahoe.h"

// bsdthread_register(thread_start, wqthread, pthread_size, ...): libpthread registra aquí las funciones con las
// que el kernel arranca hilos nuevos. Se guardan y se devuelve 0 = ninguna capacidad opcional del kernel
// (sin cola de trabajo, sin QoS, sin bsdthread_ctl).
uint64_t thread_start_fn, wqthread_fn, pthread_size;
static long bsd_bsdthread_register(struct ctx* c) {
	thread_start_fn = c->a[0];
	wqthread_fn = c->a[1];
	pthread_size = c->a[2];
	if (trace_all) logf_("    bsdthread_register: start=0x%lx wq=0x%lx pthread_size=0x%lx\n", thread_start_fn, wqthread_fn, pthread_size);
	return 0;
}


#include <errno.h>
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
static long bsd_shm_open(struct ctx* c) { (void)c; return -D_ENOENT; }
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
// csops_audittoken(pid, operación, búfer, tamaño, token*): sin firma de código, sin derechos (entitlements).
static long bsd_csops_audittoken(struct ctx* c) {
	uint32_t zero = 0;
	if ((int)c->a[1] == 0 && c->a[3] >= 4) return safe_write(c->a[2], &zero, 4) == 4 ? 0 : -D_EFAULT;
	return -D_ENOENT;
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
static long bsd_pthread_kill(struct ctx* c) {
	int s = (int)c->a[1];
	if (s == 0) return 0;
	if (s == 6) {
		// SIGABRT: libpthread/libsystem dejan el motivo en su anotación de crash. Esta dirección es de la caché
		// concreta de macOS 26.6.2 (gCRAnnotations.message de libsystem_pthread); sirve solo para diagnosticar.
		uint64_t msgp = 0;
		char msg[256] = "";
		if (safe_read(0x7ff8430937b0UL, &msgp, 8) == 8 && msgp && safe_string(msgp, msg, sizeof msg) == 0 && msg[0])
			logf_("    abort <%d>: \"%s\"\n", (int)getpid(), msg);
		else {
			// Retornos plausibles: valores de la pila dentro de la caché cuya instrucción anterior es un "call".
			uint64_t sk[512] = { 0 };
			ssize_t got = safe_read((uint64_t)c->uc->uc_mcontext.gregs[REG_RSP], sk, sizeof sk);
			logf_("    abort <%d>: rip=0x%llx rsp=0x%llx rbp=0x%llx pila:", (int)getpid(), (unsigned long long)c->uc->uc_mcontext.gregs[REG_RIP], (unsigned long long)c->uc->uc_mcontext.gregs[REG_RSP], (unsigned long long)c->uc->uc_mcontext.gregs[REG_RBP]);
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
static long bsd_execve(struct ctx* c) {
	char gpath[4096], hpath[4200];
	if (safe_string(c->a[0], gpath, sizeof gpath) != 0) return -D_EFAULT;
	char **av, **ev;
	int ac = read_strv(c->a[1], &av, 4096), ec = read_strv(c->a[2], &ev, 4096);
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
	// argv de tahoe-run: [self, caché, dyld, programa(host), argumentos del programa...]
	char** nargv = calloc(ac + 5, sizeof(char*));
	int k = 0;
	nargv[k++] = (char*)g_self_exe;
	nargv[k++] = (char*)g_cache_path;
	nargv[k++] = (char*)g_dyld_path;
	nargv[k++] = hpath;
	for (int i = 1; i < ac; i++) nargv[k++] = av[i];
	char** nenv = calloc(ec + 4, sizeof(char*));
	int e = 0;
	for (int i = 0; i < ec; i++) nenv[e++] = ev[i];
	char b1[4300], b2[4300];
	if (tahoe_root) { snprintf(b1, sizeof b1, "TAHOE_ROOT=%s", tahoe_root); nenv[e++] = b1; }
	snprintf(b2, sizeof b2, "TAHOE_ARGV0=%s", av[0]);
	nenv[e++] = b2;
	if (trace_all) logf_("    execve(\"%s\") -> relanzando tahoe-run\n", gpath);
	execve(g_self_exe, nargv, nenv);
	return -darwin_errno(errno);
}

// bsdthread_ctl(comando, arg1, arg2, arg3): QoS, sobrescrituras de prioridad y permisos de las colas de trabajo.
// libdispatch llama a BSDTHREAD_CTL_WORKQ_ALLOW_KILL (0x1000) tras un fork y ABORTA si falla; sin colas de trabajo
// reales todos los comandos pueden aceptarse sin efecto.
static long bsd_bsdthread_ctl(struct ctx* c) {
	if (trace_all) logf_("    bsdthread_ctl(cmd=0x%lx, 0x%lx) -> sin efecto\n", c->a[0], c->a[1]);
	return 0;
}

void emu_proc_init(void) {
	reg_bsd(478, bsd_bsdthread_ctl);
	reg_bsd(2, bsd_fork); reg_bsd(66, bsd_fork); reg_bsd(7, bsd_wait4); reg_bsd(42, bsd_pipe);
	reg_bsd(31, bsd_getpeername); reg_bsd(59, bsd_execve);
	reg_bsd(39, bsd_getppid); reg_bsd(81, bsd_getpgrp); reg_bsd(151, bsd_getpgid); reg_bsd(82, bsd_setpgid);
	reg_bsd(310, bsd_getsid); reg_bsd(147, bsd_setsid); reg_bsd(60, bsd_umask);
	reg_bsd(194, bsd_getrlimit); reg_bsd(195, bsd_setrlimit);
	reg_bsd(46, bsd_sigaction); reg_bsd(53, bsd_sigaltstack); reg_bsd(329, bsd_pthread_sigmask); reg_bsd(52, bsd_sigpending);
	reg_bsd(37, bsd_kill); reg_bsd(328, bsd_pthread_kill);
	reg_bsd(98, bsd_connect); reg_bsd(170, bsd_csops_audittoken);
	reg_bsd(97, bsd_socket);
	reg_bsd(116, bsd_gettimeofday); reg_bsd(266, bsd_shm_open); reg_bsd(54, bsd_ioctl);
	reg_bsd(366, bsd_bsdthread_register);
}
