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

void emu_proc_init(void) {
	reg_bsd(98, bsd_connect); reg_bsd(170, bsd_csops_audittoken);
	reg_bsd(97, bsd_socket);
	reg_bsd(116, bsd_gettimeofday); reg_bsd(266, bsd_shm_open); reg_bsd(54, bsd_ioctl);
	reg_bsd(366, bsd_bsdthread_register);
}
