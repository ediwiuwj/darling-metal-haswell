// kqueue/kevent de macOS sobre epoll, timerfd y eventfd.
//
// Un kqueue es un descriptor epoll; los "knotes" (filtro registrado) viven en una tabla de este proceso. Filtros
// con efecto real: READ, WRITE, TIMER, USER. El resto (SIGNAL, PROC, MACHPORT, WORKLOOP...) se aceptan sin que
// lleguen a disparar; se registran para saber cuáles hacen falta.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include "tahoe.h"

extern void wq_request_workloop(uint64_t, const void* req72);
extern void wq_note_workloop(uint64_t);
extern void wq_arm_workloop(uint64_t);

enum { EVFILT_READ = -1, EVFILT_WRITE = -2, EVFILT_SIGNAL = -6, EVFILT_TIMER = -7, EVFILT_MACHPORT = -8, EVFILT_USER = -10, EVFILT_WORKLOOP = -17, EVFILT_PROC = -5 };
static __thread uint64_t g_dout, g_davail;   // búfer de datos del kevent_qos en curso (mensajes Mach recibidos directamente)
enum { EV_ADD = 1, EV_DELETE = 2, EV_ENABLE = 4, EV_DISABLE = 8, EV_ONESHOT = 0x10, EV_CLEAR = 0x20, EV_RECEIPT = 0x40, EV_ERROR = 0x4000 };
#define NOTE_TRIGGER 0x01000000u
#define NOTE_FFCTRLMASK 0xc0000000u
#define NOTE_FFAND 0x40000000u
#define NOTE_FFOR 0x80000000u
#define NOTE_FFCOPY 0xc0000000u
#define NOTE_FFLAGSMASK 0x00ffffffu

static int linux_to_darwin_signal(int s) {
	switch (s) {
	case SIGHUP: return 1; case SIGINT: return 2; case SIGQUIT: return 3; case SIGILL: return 4; case SIGTRAP: return 5; case SIGABRT: return 6;
	case SIGBUS: return 10; case SIGFPE: return 8; case SIGKILL: return 9; case SIGSEGV: return 11; case SIGSYS: return 12; case SIGPIPE: return 13;
	case SIGALRM: return 14; case SIGTERM: return 15; case SIGURG: return 16; case SIGSTOP: return 17; case SIGTSTP: return 18; case SIGCONT: return 19;
	case SIGCHLD: return 20; case SIGTTIN: return 21; case SIGTTOU: return 22; case SIGIO: return 23; case SIGXCPU: return 24; case SIGXFSZ: return 25;
	case SIGVTALRM: return 26; case SIGPROF: return 27; case SIGWINCH: return 28; case SIGUSR1: return 30; case SIGUSR2: return 31;
	default: return s;
	}
}
// ---- señales: un eventfd por señal de Linux, alimentado por un manejador del anfitrión
static int sig_efd[65];
static pthread_mutex_t sig_lock = PTHREAD_MUTEX_INITIALIZER;
extern char tahoe_selector_get(void);
extern void tahoe_selector_set(char);
extern void* tahoe_restorer_addr(void);
// Se ejecuta en cualquier hilo, también mientras corre código de macOS (con el despacho activo): hay que permitir las
// syscalls reales dentro del manejador y devolver con el restaurador exento.
static void sig_forward(int sig) {
	char prev = tahoe_selector_get();
	tahoe_selector_set(0 /*SYSCALL_DISPATCH_FILTER_ALLOW*/);
	int e = errno; uint64_t one = 1;
	if (sig_efd[sig] > 0 && write(sig_efd[sig], &one, 8) < 0) {}
	errno = e;
	tahoe_selector_set(prev);
}
static int signal_source(int ls) {
	pthread_mutex_lock(&sig_lock);
	if (!sig_efd[ls]) {
		sig_efd[ls] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		struct { void* h; unsigned long flags; void* restorer; unsigned long mask; } ks = { (void*)sig_forward, SA_RESTART | SA_ONSTACK | 0x04000000 /*SA_RESTORER*/, tahoe_restorer_addr(), ~0UL };
		syscall(SYS_rt_sigaction, ls, &ks, NULL, 8);
	}
	int fd = sig_efd[ls];
	pthread_mutex_unlock(&sig_lock);
	return fd;
}
static int darwin_to_linux_sig_k(int d) {
	switch (d) {
	case 1: return SIGHUP; case 2: return SIGINT; case 3: return SIGQUIT; case 6: return SIGABRT; case 13: return SIGPIPE; case 14: return SIGALRM;
	case 15: return SIGTERM; case 16: return SIGURG; case 20: return SIGCHLD; case 21: return SIGTTIN; case 22: return SIGTTOU; case 23: return SIGIO;
	case 24: return SIGXCPU; case 25: return SIGXFSZ; case 26: return SIGVTALRM; case 27: return SIGPROF; case 28: return SIGWINCH; case 30: return SIGUSR1;
	case 31: return SIGUSR2; case 18: return SIGTSTP; case 19: return SIGCONT;
	default: return -1;
	}
}
struct kev { uint64_t ident; int16_t filter; uint16_t flags; uint32_t fflags; int64_t data; uint64_t udata; uint64_t ext[4]; uint32_t qos; };
struct knote { struct kev k; int kq, fd; int enabled; struct knote* next; };
static struct knote* notes;
// Los hilos de las colas de trabajo llaman a kevent a la vez: sin este cerrojo, un hilo liberaba un knote (drop) mientras otro
// acababa de recibirlo de epoll_wait y lo leía ya liberado (udata = 0 -> SIGSEGV en _dispatch_kevent_merge, que mataba a launchd
// según el reparto de tiempos). También protege la lista y la tabla de workloops.
static pthread_mutex_t kq_lock = PTHREAD_MUTEX_INITIALIZER;
static int knote_alive(const struct knote* n) { for (const struct knote* q = notes; q; q = q->next) if (q == n) return 1; return 0; }
static int workq_kq = -1;

static struct knote* find(int kq, uint64_t ident, int filter) {
	for (struct knote* n = notes; n; n = n->next)
		if (n->kq == kq && n->k.ident == ident && n->k.filter == filter) return n;
	return NULL;
}
static void drop(struct knote* dead) {
	for (struct knote** p = &notes; *p; p = &(*p)->next)
		if (*p == dead) { *p = dead->next; break; }
	if (dead->fd >= 0 && (dead->k.filter == EVFILT_TIMER || dead->k.filter == EVFILT_USER)) close(dead->fd);
	else if (dead->fd >= 0 && dead->k.filter == EVFILT_MACHPORT) epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL);
	else if (dead->fd >= 0 && dead->k.filter == EVFILT_SIGNAL) epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL);
	else if (dead->fd >= 0 && dead->k.filter == EVFILT_PROC) { epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL); close(dead->fd); }
	else if (dead->fd >= 0) epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL);
	free(dead);
}

static int kq_for(int guest) {
	if (guest != -1) return guest;
	if (workq_kq < 0) workq_kq = epoll_create1(EPOLL_CLOEXEC);
	return workq_kq;
}

static int workq_kq_get(void) { return kq_for(-1); }

static void kev_out(int layout, uint8_t* b, const struct kev* k);

static long timer_ns(const struct kev* k) {
	uint32_t f = k->fflags;
	long v = (long)k->data;
	if (f & 1) return v * 1000000000L;     // NOTE_SECONDS
	if (f & 2) return v * 1000L;           // NOTE_USECONDS
	if (f & 4) return v;                   // NOTE_NSECONDS
	return v * 1000000L;                   // por omisión, milisegundos
}

// Un knote deshabilitado no puede seguir en epoll (un descriptor legible lo despertaría sin parar).
static int knote_epoll_events(const struct knote* n) {
	switch (n->k.filter) {
	case EVFILT_SIGNAL: return EPOLLIN;
	case EVFILT_WRITE: return EPOLLOUT | ((n->k.flags & EV_CLEAR) ? EPOLLET : 0);
	case EVFILT_READ: return EPOLLIN | ((n->k.flags & EV_CLEAR) ? EPOLLET : 0);
	case EVFILT_MACHPORT: return EPOLLIN;
	default: return 0;
	}
}
static void knote_set_enabled(struct knote* n, int en) {
	if (n->enabled == en) return;
	n->enabled = en;
	int ev = knote_epoll_events(n);
	if (n->fd < 0 || !ev) return;
	struct epoll_event e = { .events = (uint32_t)ev, .data.ptr = n };
	if (en) epoll_ctl(n->kq, EPOLL_CTL_ADD, n->fd, &e); else epoll_ctl(n->kq, EPOLL_CTL_DEL, n->fd, NULL);
}

// Aplica un cambio; devuelve 0 o un errno de Darwin.
static int apply(int kq, const struct kev* c) {
	if (trace_all && c->filter == EVFILT_MACHPORT) logf_("    kevent: <%d> cambio MACHPORT 0x%lx flags=0x%x fflags=0x%x kq=%d\n", (int)getpid(), c->ident, c->flags, c->fflags, kq);
	struct knote* n = find(kq, c->ident, c->filter);
	if (c->flags & EV_DELETE) { if (!n) return D_ENOENT; drop(n); return 0; }
	if (!n) {
		if (!(c->flags & EV_ADD)) return D_ENOENT;
		n = calloc(1, sizeof *n);
		n->kq = kq; n->fd = -1; n->enabled = 1; n->k = *c;
		n->next = notes; notes = n;
		struct epoll_event ev = { .data.ptr = n };
		switch (c->filter) {
		case EVFILT_READ: case EVFILT_WRITE:
			ev.events = (c->filter == EVFILT_READ ? EPOLLIN : EPOLLOUT) | ((c->flags & EV_CLEAR) ? EPOLLET : 0);
			n->fd = (int)c->ident;
			if (epoll_ctl(kq, EPOLL_CTL_ADD, n->fd, &ev) != 0) { int e = darwin_errno(errno); drop(n); return e; }
			break;
		case EVFILT_TIMER: {
			n->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
			long ns = timer_ns(c);
			struct itimerspec it = { .it_value = { ns / 1000000000L, ns % 1000000000L } };
			if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) it.it_value.tv_nsec = 1;
			if (!(c->flags & EV_ONESHOT)) it.it_interval = it.it_value;
			timerfd_settime(n->fd, 0, &it, NULL);
			ev.events = EPOLLIN;
			epoll_ctl(kq, EPOLL_CTL_ADD, n->fd, &ev);
			break;
		}
		case EVFILT_USER:
			n->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
			ev.events = EPOLLIN | EPOLLET;
			epoll_ctl(kq, EPOLL_CTL_ADD, n->fd, &ev);
			n->k.fflags &= NOTE_FFLAGSMASK;
			break;
		case EVFILT_PROC: {
			// pidfd: legible cuando el proceso termina. NOTE_EXIT con el estado de espera de Darwin en data.
			int pfd = (int)syscall(SYS_pidfd_open, (pid_t)c->ident, 0);
			if (pfd < 0) { int e = darwin_errno(errno); drop(n); return e == D_ENOENT ? 3 /* ESRCH */ : e; }
			n->fd = pfd;
			ev.events = EPOLLIN;
			epoll_ctl(kq, EPOLL_CTL_ADD, pfd, &ev);
			break;
		}
		case EVFILT_SIGNAL: {
			// Señales de Darwin como eventos: un manejador del anfitrión suma al eventfd de esa señal, y el knote lo lee.
			int ls = darwin_to_linux_sig_k((int)c->ident);
			if (ls <= 0 || ls >= 65) { drop(n); return D_EINVAL; }
			n->fd = signal_source(ls);
			ev.events = EPOLLIN;
			epoll_ctl(kq, EPOLL_CTL_ADD, n->fd, &ev);
			break;
		}
		case EVFILT_MACHPORT: {
			int pfd = port_eventfd((uint32_t)c->ident);
			if (pfd < 0) { logf_("    kevent: EVFILT_MACHPORT 0x%lx: puerto desconocido o de otro proceso\n", c->ident); break; }
			n->fd = pfd;
			if (trace_all) logf_("    kevent: EVFILT_MACHPORT puerto=0x%lx flags=0x%x fflags=0x%x udata=0x%lx kq=%d\n", c->ident, c->flags, c->fflags, c->udata, kq);
			ev.events = EPOLLIN;
			epoll_ctl(kq, EPOLL_CTL_ADD, pfd, &ev);
			break;
		}
		case EVFILT_WORKLOOP:
			if (c->fflags & 1 /*NOTE_WL_THREAD_REQUEST*/) { uint8_t r[72]; kev_out(2, r, c); wq_request_workloop(c->ident, r); }
			break;
		default:
			logf_("    kevent: filtro %d (ident=0x%lx flags=0x%x fflags=0x%x data=%ld ext=%lx,%lx,%lx,%lx) registrado sin efecto\n", c->filter, c->ident, c->flags, c->fflags, (long)c->data, c->ext[0], c->ext[1], c->ext[2], c->ext[3]);
		}
	} else {
		if (trace_all && c->filter == EVFILT_MACHPORT) logf_("    kevent: actualiza MACHPORT 0x%lx flags=0x%x fflags=0x%x (activo antes=%d)\n", c->ident, c->flags, c->fflags, n->enabled);
		n->k.udata = c->udata;
		if (c->filter == EVFILT_WORKLOOP && (c->fflags & 1)) { uint8_t r[72]; kev_out(2, r, c); wq_request_workloop(c->ident, r); }
	}
	if (c->flags & EV_DISABLE) knote_set_enabled(n, 0);
	if (c->flags & EV_ENABLE) knote_set_enabled(n, 1);
	if (c->filter == EVFILT_USER) {
		uint32_t op = c->fflags & NOTE_FFCTRLMASK, v = c->fflags & NOTE_FFLAGSMASK;
		if (op == NOTE_FFAND) n->k.fflags &= v; else if (op == NOTE_FFOR) n->k.fflags |= v; else if (op == NOTE_FFCOPY) n->k.fflags = v;
		if ((c->fflags & NOTE_TRIGGER) && n->enabled) { uint64_t one = 1; if (write(n->fd, &one, 8) < 0) {} }
	}
	return 0;
}

// Diseños de struct kevent: 0 = kevent (32 bytes), 1 = kevent64 (48), 2 = kevent_qos (72).
static const size_t kev_size[3] = { 32, 48, 72 };

static void kev_in(int layout, const uint8_t* b, struct kev* k) {
	memset(k, 0, sizeof *k);
	memcpy(&k->ident, b, 8); memcpy(&k->filter, b + 8, 2); memcpy(&k->flags, b + 10, 2);
	if (layout == 0) { memcpy(&k->fflags, b + 12, 4); memcpy(&k->data, b + 16, 8); memcpy(&k->udata, b + 24, 8); }
	else if (layout == 1) { memcpy(&k->fflags, b + 12, 4); memcpy(&k->data, b + 16, 8); memcpy(&k->udata, b + 24, 8); memcpy(k->ext, b + 32, 16); }
	else { memcpy(&k->qos, b + 12, 4); memcpy(&k->udata, b + 16, 8); memcpy(&k->fflags, b + 24, 4); memcpy(&k->data, b + 32, 8); memcpy(k->ext, b + 40, 32); }
}
static void kev_out(int layout, uint8_t* b, const struct kev* k) {
	memset(b, 0, kev_size[layout]);
	memcpy(b, &k->ident, 8); memcpy(b + 8, &k->filter, 2); memcpy(b + 10, &k->flags, 2);
	if (layout == 0) { memcpy(b + 12, &k->fflags, 4); memcpy(b + 16, &k->data, 8); memcpy(b + 24, &k->udata, 8); }
	else if (layout == 1) { memcpy(b + 12, &k->fflags, 4); memcpy(b + 16, &k->data, 8); memcpy(b + 24, &k->udata, 8); memcpy(b + 32, k->ext, 16); }
	else { memcpy(b + 12, &k->qos, 4); memcpy(b + 16, &k->udata, 8); memcpy(b + 24, &k->fflags, 4); memcpy(b + 32, &k->data, 8); memcpy(b + 40, k->ext, 32); }
}

// Núcleo común. timeout_ms: -1 = esperar, 0 = no esperar.
static __thread int g_no_poll;   // KEVENT_FLAG_ERROR_EVENTS: solo se devuelven errores de los cambios, no eventos
static long do_kevent(int guest_kq, int layout, uint64_t chg, long nchg, uint64_t evp, long nev, int timeout_ms) {
	int kq = kq_for(guest_kq);
	uint8_t raw[72];
	long nout = 0;
	for (long i = 0; i < nchg; i++) {
		struct kev k;
		if (safe_read(chg + i * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) return -D_EFAULT;
		kev_in(layout, raw, &k);
		pthread_mutex_lock(&kq_lock);
		int e = apply(kq, &k);
		pthread_mutex_unlock(&kq_lock);
		if (e || (k.flags & EV_RECEIPT)) {
			if (nout < nev) {
				k.flags |= EV_ERROR; k.data = e;
				kev_out(layout, raw, &k);
				if (safe_write(evp + nout * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) return -D_EFAULT;
				nout++;
			} else if (e) return -e;
		}
	}
	if (nout >= nev || g_no_poll) return nout;
	struct epoll_event es[32];
	int max = (int)(nev - nout) < 32 ? (int)(nev - nout) : 32;
	if (nout) timeout_ms = 0;
	int r = epoll_wait(kq, es, max, timeout_ms);
	if (r < 0) return errno == EINTR ? -4 /* EINTR */ : -darwin_errno(errno);
	pthread_mutex_lock(&kq_lock);
	for (int i = 0; i < r; i++) {
		struct knote* n = es[i].data.ptr;
		if (!knote_alive(n)) continue;                                   // lo eliminó otro hilo tras epoll_wait
		if (trace_all && n->k.filter == EVFILT_MACHPORT) logf_("    kevent: epoll avisa del puerto 0x%lx (activo=%d, dout=%d)\n", n->k.ident, n->enabled, g_dout != 0);
		if (!n->enabled) continue;
		struct kev k = n->k;
		k.flags &= (uint16_t)~(EV_ADD | EV_ENABLE | EV_DISABLE | EV_DELETE | EV_RECEIPT | 0x200 /*EV_VANISHED*/);   // el kernel no repite las banderas de registro
		k.data = 1;
		if (n->k.filter == EVFILT_READ) { int avail = 0; ioctl(n->fd, FIONREAD, &avail); k.data = avail; if (es[i].events & EPOLLHUP) k.flags |= 0x8000 /*EV_EOF*/; }
		else if (n->k.filter == EVFILT_MACHPORT) {
			// recepción directa: el mensaje se entrega en el búfer de datos y el evento apunta a él
			if ((n->k.fflags & 2 /*MACH_RCV_MSG*/) && g_dout && g_davail) {
				uint64_t avail = 0;
				safe_read(g_davail, &avail, 8);
				uint32_t total = 0;
				long rr = avail ? mach_rx_message((uint32_t)n->k.ident, 0, n->k.fflags, g_dout, (uint32_t)avail, &total) : 0x10004004;
				if (rr) { if (trace_all || (rr & 0xffffc000) != 0x10004000) logf_("    kevent: recepción directa en 0x%lx devolvió 0x%lx\n", n->k.ident, rr); if (rr == 0x10004003) continue; k.fflags = (uint32_t)rr; }
				else {
					k.fflags = 0;                                  // resultado de mach_msg: éxito (no las banderas pedidas)
					k.ext[0] = g_dout; k.ext[1] = total;
					g_dout += (total + 15) & ~15u; avail -= (total + 15) & ~15u;
					safe_write(g_davail, &avail, 8);
				}
			}
			else k.fflags = 0;                                  // sin recepción directa no hay resultado de mach_msg que informar
			if (n->k.flags & 0x80 /*EV_DISPATCH*/) knote_set_enabled(n, 0);
		}
		else if (n->k.filter == EVFILT_PROC) {
			siginfo_t si = { 0 };
			int st = 0;
			if (waitid(P_PID, (id_t)n->k.ident, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid) {
				if (si.si_code == CLD_EXITED) st = (si.si_status & 0xff) << 8;                // WEXITSTATUS de Darwin
				else st = linux_to_darwin_signal(si.si_status) | ((si.si_code == CLD_DUMPED) ? 0x80 : 0);
			}
			k.fflags = (n->k.fflags & 0x80000000u) | (n->k.fflags & 0x04000000u);              // NOTE_EXIT / NOTE_EXITSTATUS
			k.data = (n->k.fflags & 0x04000000u) ? st : 0;
			k.flags |= 0x8000 | EV_ONESHOT;                                                     // EV_EOF; el kernel elimina el knote y lo avisa con EV_ONESHOT
			n->k.flags |= EV_ONESHOT;                                                           // un proceso solo sale una vez
		}
		else if (n->k.filter == EVFILT_SIGNAL) {
			uint64_t cnt = 0;
			if (read(n->fd, &cnt, 8) != 8) continue;                          // otro hilo ya lo recogió
			k.data = (int64_t)cnt; k.fflags = 0;
		}
		else if (n->k.filter == EVFILT_TIMER || n->k.filter == EVFILT_USER) { uint64_t cnt = 0; if (read(n->fd, &cnt, 8) == 8) k.data = (int64_t)cnt; }
		kev_out(layout, raw, &k);
		if (safe_write(evp + nout * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) { pthread_mutex_unlock(&kq_lock); return -D_EFAULT; }
		nout++;
		if (n->k.flags & EV_ONESHOT) drop(n);
	}
	pthread_mutex_unlock(&kq_lock);
	return nout;
}

static int ts_ms(uint64_t p) {
	if (!p) return -1;
	int64_t t[2];
	if (safe_read(p, t, 16) != 16) return -1;
	return (int)(t[0] * 1000 + t[1] / 1000000);
}

static long bsd_kqueue(struct ctx* c) { (void)c; int fd = epoll_create1(0); return fd < 0 ? -darwin_errno(errno) : fd; }
// kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
static long bsd_kevent(struct ctx* c) { g_dout = 0; g_no_poll = 0; return do_kevent((int)c->a[0], 0, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], ts_ms(c->a[5])); }
// kevent64(kq, changelist, nchanges, eventlist, nevents, flags, timeout)
static long bsd_kevent64(struct ctx* c) { g_dout = 0; g_no_poll = 0; return do_kevent((int)c->a[0], 1, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], ts_ms(ctx_arg(c, 6))); }
// kevent_qos(kq, changelist, nchanges, eventlist, nevents, data_out, data_available, flags)
static long bsd_kevent_qos(struct ctx* c) {
	uint64_t flags = ctx_arg(c, 7);
	g_dout = c->a[5]; g_davail = ctx_arg(c, 6); g_no_poll = (flags & 2) != 0;
	return do_kevent((int)c->a[0], 2, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], (flags & 1) ? 0 : -1);
}

// kevent_id(id, changelist, nchanges, eventlist, nevents, data_out, data_available, flags): cola de trabajo de
// libdispatch (workloop); cada identificador tiene su propio kqueue.
static struct { uint64_t id; int kq; } workloops[64];
int kq_workloop_fd(uint64_t id) {
	static pthread_mutex_t wl_lock = PTHREAD_MUTEX_INITIALIZER;
	int r = -1;
	pthread_mutex_lock(&wl_lock);
	for (int i = 0; i < 64; i++) {
		if (workloops[i].kq > 0 && workloops[i].id == id) { r = workloops[i].kq; break; }
		if (workloops[i].kq == 0) { workloops[i].kq = epoll_create1(EPOLL_CLOEXEC); workloops[i].id = id; r = workloops[i].kq; break; }
	}
	pthread_mutex_unlock(&wl_lock);
	if (r >= 0) return r;
	return -1;
}
// Recoge sin esperar los eventos pendientes de un workloop (kevent_qos_s de 72 bytes). Devuelve cuántos.
long kq_drain(uint64_t id, uint64_t evp, int max, uint64_t dout, uint64_t davail) {
	g_dout = dout; g_davail = davail; g_no_poll = 0;
	int kq = kq_workloop_fd(id);
	return kq < 0 ? 0 : do_kevent(kq, 2, 0, 0, evp, max, 0);
}
static long bsd_kevent_id(struct ctx* c) {
	uint64_t flags = ctx_arg(c, 7);
	int kq = kq_workloop_fd(c->a[0]);
	if (kq < 0) return -D_ENOMEM;
	wq_note_workloop(c->a[0]);
	g_dout = c->a[5]; g_davail = ctx_arg(c, 6); g_no_poll = (flags & 2) != 0;
	long r = do_kevent(kq, 2, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], (flags & 1) ? 0 : -1);
	wq_arm_workloop(c->a[0]);
	return r;
}

void emu_kqueue_init(void) {
	reg_bsd(375, bsd_kevent_id); reg_bsd(443, bsd_kqueue);   // guarded_kqueue_np(guard*, flags) = kqueue
	reg_bsd(362, bsd_kqueue); reg_bsd(363, bsd_kevent); reg_bsd(369, bsd_kevent64); reg_bsd(374, bsd_kevent_qos);
}

// Aplica una lista de cambios sin recoger eventos (retorno de hilo de workloop).
long kq_apply_changes(int layout, uint64_t chg, long n, uint64_t workloop) { g_no_poll = 1; return do_kevent(workloop ? kq_workloop_fd(workloop) : workq_kq_get(), layout, chg, n, 0, 0, 0); }
