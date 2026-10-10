// kqueue/kevent de macOS sobre epoll, timerfd y eventfd.
//
// Un kqueue es un descriptor epoll; los "knotes" (filtro registrado) viven en una lista de este proceso. Cada knote
// tiene un descriptor de Linux que avisa: el propio fd (READ/WRITE), un timerfd (TIMER), un eventfd (USER, SIGNAL),
// un pidfd (PROC) o el socket de aviso del puerto (MACHPORT).
//
// epoll solo admite un registro por descriptor, y varios knotes pueden compartirlo (READ y WRITE del mismo socket, o
// varios knotes EV_UDATA_SPECIFIC del mismo puerto). Por eso el registro es por (kq, fd): su interés es la unión del de
// los knotes activos que lo usan, el dato del registro es el fd (nunca un puntero a un knote, que podría liberarse) y al
// llegar un evento se reparte entre todos los knotes activos de ese descriptor.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
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
#define SIG_MAX_FDS 16
static int sig_fds[65][SIG_MAX_FDS];           // un eventfd por knote EVFILT_SIGNAL (cada uno cuenta sus propias llegadas)
static int sig_installed[65];
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
	for (int i = 0; i < SIG_MAX_FDS; i++) { int f = __atomic_load_n(&sig_fds[sig][i], __ATOMIC_RELAXED); if (f > 0 && write(f, &one, 8) < 0) {} }
	errno = e;
	tahoe_selector_set(prev);
}
static int signal_source(int ls) {
	int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (fd < 0) return -1;
	pthread_mutex_lock(&sig_lock);
	int ok = 0;
	for (int i = 0; i < SIG_MAX_FDS && !ok; i++) if (sig_fds[ls][i] <= 0) { __atomic_store_n(&sig_fds[ls][i], fd, __ATOMIC_RELEASE); ok = 1; }
	if (ok && !sig_installed[ls]) {
		sig_installed[ls] = 1;
		struct { void* h; unsigned long flags; void* restorer; unsigned long mask; } ks = { (void*)sig_forward, SA_RESTART | SA_ONSTACK | 0x04000000 /*SA_RESTORER*/, tahoe_restorer_addr(), ~0UL };
		syscall(SYS_rt_sigaction, ls, &ks, NULL, 8);
	}
	pthread_mutex_unlock(&sig_lock);
	if (!ok) { close(fd); return -1; }
	return fd;
}
static void signal_release(int fd) {
	pthread_mutex_lock(&sig_lock);
	for (int s = 0; s < 65; s++) for (int i = 0; i < SIG_MAX_FDS; i++) if (sig_fds[s][i] == fd) __atomic_store_n(&sig_fds[s][i], 0, __ATOMIC_RELEASE);
	pthread_mutex_unlock(&sig_lock);
	close(fd);
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
struct knote { struct kev k; int kq, fd; int enabled, owns_fd; struct knote* next; };   // owns_fd: el fd es solo de este knote
static struct knote* notes;
// Los hilos de las colas de trabajo llaman a kevent a la vez: sin este cerrojo, un hilo liberaba un knote (drop) mientras otro
// acababa de recibirlo de epoll_wait y lo leía ya liberado (udata = 0 -> SIGSEGV en _dispatch_kevent_merge, que mataba a launchd
// según el reparto de tiempos). También protege la lista y la tabla de workloops.
static pthread_mutex_t kq_lock = PTHREAD_MUTEX_INITIALIZER;
#define WQ_KQID_WORKQ (~0ULL)   // identificador interno del kqueue de la cola de trabajo (kevent_qos con kq = -1)
static int workq_kq = -1;

// EV_UDATA_SPECIFIC (0x100): el knote se identifica también por udata, así que puede haber varios por (ident, filtro).
static struct knote* find(int kq, uint64_t ident, int filter, uint16_t flags, uint64_t udata) {
	for (struct knote* n = notes; n; n = n->next)
		if (n->kq == kq && n->k.ident == ident && n->k.filter == filter && (!(flags & 0x100) || n->k.udata == udata)) return n;
	return NULL;
}
static uint32_t knote_want(const struct knote* n) {
	switch (n->k.filter) {
	case EVFILT_WRITE: return EPOLLOUT;
	case EVFILT_READ: return EPOLLIN | EPOLLRDHUP;
	case EVFILT_WORKLOOP: return 0;
	default: return EPOLLIN;
	}
}
// Ajusta el registro epoll de (kq, fd) a la unión del interés de sus knotes activos.
static void sync_fd(int kq, int fd) {
	if (kq < 0 || fd < 0) return;
	uint32_t ev = 0; int any = 0, all_clear = 1;
	for (struct knote* n = notes; n; n = n->next) {
		if (n->kq != kq || n->fd != fd || !n->enabled) continue;
		uint32_t w = knote_want(n);
		if (!w) continue;
		ev |= w; any = 1;
		if (!((n->k.filter == EVFILT_READ || n->k.filter == EVFILT_WRITE) && (n->k.flags & EV_CLEAR))) all_clear = 0;
	}
	if (!any) { epoll_ctl(kq, EPOLL_CTL_DEL, fd, NULL); return; }
	struct epoll_event e = { .events = ev | (all_clear ? EPOLLET : 0), .data.u64 = (uint64_t)(uint32_t)fd };
	if (epoll_ctl(kq, EPOLL_CTL_MOD, fd, &e) != 0 && errno == ENOENT) epoll_ctl(kq, EPOLL_CTL_ADD, fd, &e);
}
static void drop(struct knote* dead) {
	for (struct knote** p = &notes; *p; p = &(*p)->next)
		if (*p == dead) { *p = dead->next; break; }
	if (dead->fd >= 0) {
		if (dead->owns_fd) {
			epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL);
			if (dead->k.filter == EVFILT_SIGNAL) signal_release(dead->fd); else close(dead->fd);
		} else sync_fd(dead->kq, dead->fd);                      // el descriptor es compartido: quitar solo su interés
	}
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

// Un knote deshabilitado deja de contar en el registro de su descriptor (si no, un fd legible despertaría sin parar).
static void knote_set_enabled(struct knote* n, int en) {
	if (n->enabled == en) return;
	n->enabled = en;
	if (en && n->k.filter == EVFILT_MACHPORT) { int pfd = port_eventfd((uint32_t)n->k.ident); if (pfd >= 0 && pfd != n->fd) { int old = n->fd; n->fd = pfd; sync_fd(n->kq, old); } }   // el socket de aviso cambia si el derecho de recepción se movió
	sync_fd(n->kq, n->fd);
}

// Aplica un cambio; devuelve 0 o un errno de Darwin.
static int apply(int kq, const struct kev* c) {
	if ((trace_all || mach_trace()) && c->filter == EVFILT_MACHPORT) logf_("    kevent: <%d> cambio MACHPORT 0x%lx flags=0x%x fflags=0x%x kq=%d\n", (int)getpid(), c->ident, c->flags, c->fflags, kq);
	struct knote* n = find(kq, c->ident, c->filter, c->flags, c->udata);
	if (c->flags & EV_DELETE) { if (!n) return D_ENOENT; drop(n); return 0; }
	if (!n) {
		if (!(c->flags & EV_ADD)) return D_ENOENT;
		n = calloc(1, sizeof *n);
		n->kq = kq; n->fd = -1; n->enabled = 1; n->k = *c;
		n->next = notes; notes = n;
		switch (c->filter) {
		case EVFILT_READ: case EVFILT_WRITE: {
			int fd = (int)c->ident;
			struct epoll_event probe = { .events = EPOLLIN, .data.u64 = (uint64_t)(uint32_t)fd };
			int pr = epoll_ctl(kq, EPOLL_CTL_ADD, fd, &probe);            // ¿admite epoll este descriptor?
			if (pr != 0 && errno == EPERM) {
				// archivo normal o directorio: kqueue los da siempre listos; epoll no los admite. Un eventfd con valor 1 lo imita.
				n->fd = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC); n->owns_fd = 1;
			} else if (pr != 0 && errno != EEXIST) { int e = darwin_errno(errno); n->fd = -1; drop(n); return e; }
			else n->fd = fd;
			break;
		}
		case EVFILT_TIMER: {
			n->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
			long ns = timer_ns(c);
			struct itimerspec it = { .it_value = { ns / 1000000000L, ns % 1000000000L } };
			if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) it.it_value.tv_nsec = 1;
			if (!(c->flags & EV_ONESHOT)) it.it_interval = it.it_value;
			timerfd_settime(n->fd, 0, &it, NULL);
			n->owns_fd = 1;
			break;
		}
		case EVFILT_USER:
			n->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
			n->owns_fd = 1;
			n->k.fflags &= NOTE_FFLAGSMASK;
			break;
		case EVFILT_PROC: {
			// pidfd: legible cuando el proceso termina. NOTE_EXIT con el estado de espera de Darwin en data.
			int pfd = (int)syscall(SYS_pidfd_open, (pid_t)c->ident, 0);
			if (pfd < 0) { int e = darwin_errno(errno); drop(n); return e == D_ENOENT ? 3 /* ESRCH */ : e; }
			n->fd = pfd; n->owns_fd = 1;
			break;
		}
		case EVFILT_SIGNAL: {
			// Señales de Darwin como eventos: un manejador del anfitrión suma al eventfd de esa señal, y el knote lo lee.
			int ls = darwin_to_linux_sig_k((int)c->ident);
			if (ls <= 0 || ls >= 65) { drop(n); return D_EINVAL; }
			n->fd = signal_source(ls); n->owns_fd = n->fd >= 0;
			break;
		}
		case EVFILT_MACHPORT: {
			int pfd = port_eventfd((uint32_t)c->ident);
			if (pfd < 0) { logf_("    kevent: EVFILT_MACHPORT 0x%lx: puerto desconocido o de otro proceso\n", c->ident); break; }
			n->fd = pfd;
			if (trace_all || mach_trace()) logf_("    kevent: EVFILT_MACHPORT puerto=0x%lx flags=0x%x fflags=0x%x udata=0x%lx kq=%d\n", c->ident, c->flags, c->fflags, c->udata, kq);
			break;
		}
		case EVFILT_WORKLOOP:
			if (c->fflags & 1 /*NOTE_WL_THREAD_REQUEST*/) { uint8_t r[72]; kev_out(2, r, c); wq_request_workloop(c->ident, r); }
			break;
		default:
			logf_("    kevent: filtro %d (ident=0x%lx flags=0x%x fflags=0x%x data=%ld ext=%lx,%lx,%lx,%lx) registrado sin efecto\n", c->filter, c->ident, c->flags, c->fflags, (long)c->data, c->ext[0], c->ext[1], c->ext[2], c->ext[3]);
		}
		if (c->flags & EV_DISABLE) n->enabled = 0;
		sync_fd(kq, n->fd);
	} else {
		if ((trace_all || mach_trace()) && c->filter == EVFILT_MACHPORT) logf_("    kevent: actualiza MACHPORT 0x%lx flags=0x%x fflags=0x%x (activo antes=%d)\n", c->ident, c->flags, c->fflags, n->enabled);
		// EV_ADD sobre un knote existente: como f_touch de XNU, los parámetros nuevos sustituyen a los anteriores (libdispatch
		// rearma así sus temporizadores y fuentes con EV_ONESHOT / EV_DISPATCH).
		n->k.udata = c->udata;
		if (c->flags & EV_ADD) {
			uint16_t keep = n->k.flags & 0x8000;
			if (c->filter != EVFILT_USER) n->k.fflags = c->fflags;
			n->k.data = c->data; n->k.qos = c->qos; memcpy(n->k.ext, c->ext, sizeof n->k.ext);
			n->k.flags = (uint16_t)((c->flags & ~(EV_ADD | EV_DELETE | EV_RECEIPT)) | keep);
			if (c->filter == EVFILT_TIMER && n->fd >= 0) {
				long ns = timer_ns(c);
				struct itimerspec it = { .it_value = { ns / 1000000000L, ns % 1000000000L } };
				if (it.it_value.tv_sec == 0 && it.it_value.tv_nsec == 0) it.it_value.tv_nsec = 1;
				if (!(c->flags & EV_ONESHOT)) it.it_interval = it.it_value;
				uint64_t junk; while (read(n->fd, &junk, 8) == 8) {}   // vencimientos viejos fuera
				timerfd_settime(n->fd, 0, &it, NULL);
			}
			if (!(c->flags & EV_DISABLE)) knote_set_enabled(n, 1);   // EV_ADD implica activar salvo EV_DISABLE
		}
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
	for (int i = 0; i < r && nout < nev; i++) {
		int fd = (int)(uint32_t)es[i].data.u64;
		uint32_t evs = es[i].events;
		struct knote* next;
		for (struct knote* n = notes; n && nout < nev; n = next) {
			next = n->next;
			if (n->kq != kq || n->fd != fd || !n->enabled) continue;
			if (n->k.filter == EVFILT_READ && !(evs & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))) continue;
			if (n->k.filter == EVFILT_WRITE && !(evs & (EPOLLOUT | EPOLLHUP | EPOLLERR))) continue;
			if ((trace_all || mach_trace()) && n->k.filter == EVFILT_MACHPORT) logf_("    kevent: epoll avisa del puerto 0x%lx (dout=%d)\n", n->k.ident, g_dout != 0);
			struct kev k = n->k;
			k.flags &= (uint16_t)~(EV_ADD | EV_ENABLE | EV_DISABLE | EV_DELETE | EV_RECEIPT | 0x200 /*EV_VANISHED*/);   // el kernel no repite las banderas de registro
			k.data = 1;
			if (n->k.filter == EVFILT_READ) {
				int avail = 0;
				if (!n->owns_fd) ioctl(n->fd, FIONREAD, &avail); else avail = 1;
				k.data = avail;
				if (evs & (EPOLLHUP | EPOLLRDHUP)) k.flags |= 0x8000 /*EV_EOF*/;
			}
			else if (n->k.filter == EVFILT_WRITE) { if (evs & EPOLLHUP) k.flags |= 0x8000; }
			else if (n->k.filter == EVFILT_MACHPORT) {
				// recepción directa: el mensaje se entrega en el búfer de datos y el evento apunta a él
				if ((n->k.fflags & 2 /*MACH_RCV_MSG*/) && g_dout && g_davail) {
					uint64_t avail = 0;
					safe_read(g_davail, &avail, 8);
					uint32_t total = 0;
					long rr = avail ? mach_rx_message((uint32_t)n->k.ident, 0, n->k.fflags, g_dout, (uint32_t)avail, &total) : 0x10004004;
					if (rr == MACH_RCV_TIMED_OUT_ || rr == MACH_RCV_INVALID_NAME_ || rr == MACH_RCV_PORT_DIED_) {   // sin mensaje (el aviso sobraba) o puerto inexistente/muerto
						if (port_drain_idle((uint32_t)n->k.ident)) { int old = n->fd; n->fd = -1; sync_fd(n->kq, old); }
						continue;
					}
					if (rr) { if (trace_all || mach_trace() || (rr & 0xffffc000) != 0x10004000) logf_("    kevent: recepción directa en 0x%lx devolvió 0x%lx\n", n->k.ident, rr); k.fflags = (uint32_t)rr; }
					else {
						k.fflags = 0;                                  // resultado de mach_msg: éxito (no las banderas pedidas)
						k.ext[0] = g_dout; k.ext[1] = total;
						g_dout += (total + 15) & ~15u; avail -= (total + 15) & ~15u;
						safe_write(g_davail, &avail, 8);
					}
				}
				else k.fflags = 0;                                  // sin recepción directa no hay resultado de mach_msg que informar
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
			else if (n->k.filter == EVFILT_TIMER || n->k.filter == EVFILT_USER) {
				uint64_t cnt = 0;
				if (read(n->fd, &cnt, 8) != 8) continue;                          // otro hilo ya lo recogió
				k.data = (int64_t)cnt;
			}
			kev_out(layout, raw, &k);
			if (safe_write(evp + nout * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) { pthread_mutex_unlock(&kq_lock); return -D_EFAULT; }
			nout++;
			// EV_ONESHOT: sin EV_UDATA_SPECIFIC el knote desaparece al entregarse; con él, libdispatch lo borrará después con
			// EV_DELETE (lo marca "needs delete"), así que se queda desactivado hasta entonces.
			if ((n->k.flags & EV_ONESHOT) && !(n->k.flags & 0x100)) drop(n);
			else if (n->k.flags & (EV_ONESHOT | 0x80 /*EV_DISPATCH*/)) knote_set_enabled(n, 0);   // EV_DISPATCH: se desactiva tras entregar
		}
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
	long r = do_kevent((int)c->a[0], 2, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], (flags & 1) ? 0 : -1);
	if ((int)c->a[0] == -1) wq_arm_workloop(WQ_KQID_WORKQ);   // los eventos de la cola de trabajo piden un hilo cuando haya alguno listo
	return r;
}

// kevent_id(id, changelist, nchanges, eventlist, nevents, data_out, data_available, flags): cola de trabajo de
// libdispatch (workloop); cada identificador tiene su propio kqueue.
#define MAX_WORKLOOPS 1024
static struct { uint64_t id; int kq; } workloops[MAX_WORKLOOPS];
int kq_workloop_fd(uint64_t id) {
	if (id == WQ_KQID_WORKQ) return workq_kq_get();
	static pthread_mutex_t wl_lock = PTHREAD_MUTEX_INITIALIZER;
	int r = -1;
	pthread_mutex_lock(&wl_lock);
	for (int i = 0; i < MAX_WORKLOOPS; i++) {
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
