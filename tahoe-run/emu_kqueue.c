// kqueue/kevent de macOS sobre epoll, timerfd y eventfd.
//
// Un kqueue es un descriptor epoll; los "knotes" (filtro registrado) viven en una tabla de este proceso. Filtros
// con efecto real: READ, WRITE, TIMER, USER. El resto (SIGNAL, PROC, MACHPORT, WORKLOOP...) se aceptan sin que
// lleguen a disparar; se registran para saber cuáles hacen falta.
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>

#include "tahoe.h"

extern void wq_request_workloop(uint64_t);
extern void wq_note_workloop(uint64_t);

enum { EVFILT_READ = -1, EVFILT_WRITE = -2, EVFILT_SIGNAL = -6, EVFILT_TIMER = -7, EVFILT_MACHPORT = -8, EVFILT_USER = -10, EVFILT_WORKLOOP = -17 };
enum { EV_ADD = 1, EV_DELETE = 2, EV_ENABLE = 4, EV_DISABLE = 8, EV_ONESHOT = 0x10, EV_CLEAR = 0x20, EV_RECEIPT = 0x40, EV_ERROR = 0x4000 };
#define NOTE_TRIGGER 0x01000000u
#define NOTE_FFCTRLMASK 0xc0000000u
#define NOTE_FFAND 0x40000000u
#define NOTE_FFOR 0x80000000u
#define NOTE_FFCOPY 0xc0000000u
#define NOTE_FFLAGSMASK 0x00ffffffu

struct kev { uint64_t ident; int16_t filter; uint16_t flags; uint32_t fflags; int64_t data; uint64_t udata; uint64_t ext[4]; uint32_t qos; };
struct knote { struct kev k; int kq, fd; int enabled; struct knote* next; };
static struct knote* notes;
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
	else if (dead->fd >= 0) epoll_ctl(dead->kq, EPOLL_CTL_DEL, dead->fd, NULL);
	free(dead);
}

static int kq_for(int guest) {
	if (guest != -1) return guest;
	if (workq_kq < 0) workq_kq = epoll_create1(EPOLL_CLOEXEC);
	return workq_kq;
}

static int workq_kq_get(void) { return kq_for(-1); }

static long timer_ns(const struct kev* k) {
	uint32_t f = k->fflags;
	long v = (long)k->data;
	if (f & 1) return v * 1000000000L;     // NOTE_SECONDS
	if (f & 2) return v * 1000L;           // NOTE_USECONDS
	if (f & 4) return v;                   // NOTE_NSECONDS
	return v * 1000000L;                   // por omisión, milisegundos
}

// Aplica un cambio; devuelve 0 o un errno de Darwin.
static int apply(int kq, const struct kev* c) {
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
		case EVFILT_WORKLOOP:
			if (c->fflags & 1 /*NOTE_WL_THREAD_REQUEST*/) wq_request_workloop(c->ident);
			break;
		default:
			logf_("    kevent: filtro %d (ident=0x%lx flags=0x%x fflags=0x%x data=%ld ext=%lx,%lx,%lx,%lx) registrado sin efecto\n", c->filter, c->ident, c->flags, c->fflags, (long)c->data, c->ext[0], c->ext[1], c->ext[2], c->ext[3]);
		}
	} else {
		n->k.udata = c->udata;
		if (c->filter == EVFILT_WORKLOOP && (c->fflags & 1)) wq_request_workloop(c->ident);
	}
	if (c->flags & EV_DISABLE) n->enabled = 0;
	if (c->flags & EV_ENABLE) n->enabled = 1;
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
static long do_kevent(int guest_kq, int layout, uint64_t chg, long nchg, uint64_t evp, long nev, int timeout_ms) {
	int kq = kq_for(guest_kq);
	uint8_t raw[72];
	long nout = 0;
	for (long i = 0; i < nchg; i++) {
		struct kev k;
		if (safe_read(chg + i * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) return -D_EFAULT;
		kev_in(layout, raw, &k);
		int e = apply(kq, &k);
		if (e || (k.flags & EV_RECEIPT)) {
			if (nout < nev) {
				k.flags |= EV_ERROR; k.data = e;
				kev_out(layout, raw, &k);
				if (safe_write(evp + nout * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) return -D_EFAULT;
				nout++;
			} else if (e) return -e;
		}
	}
	if (nout >= nev) return nout;
	struct epoll_event es[32];
	int max = (int)(nev - nout) < 32 ? (int)(nev - nout) : 32;
	if (nout) timeout_ms = 0;
	int r = epoll_wait(kq, es, max, timeout_ms);
	if (r < 0) return errno == EINTR ? -4 /* EINTR */ : -darwin_errno(errno);
	for (int i = 0; i < r; i++) {
		struct knote* n = es[i].data.ptr;
		if (!n->enabled) continue;
		struct kev k = n->k;
		k.data = 1;
		if (n->k.filter == EVFILT_READ) { int avail = 0; ioctl(n->fd, FIONREAD, &avail); k.data = avail; if (es[i].events & EPOLLHUP) k.flags |= 0x8000 /*EV_EOF*/; }
		else if (n->k.filter == EVFILT_TIMER || n->k.filter == EVFILT_USER) { uint64_t cnt = 0; if (read(n->fd, &cnt, 8) == 8) k.data = (int64_t)cnt; }
		kev_out(layout, raw, &k);
		if (safe_write(evp + nout * kev_size[layout], raw, kev_size[layout]) != (ssize_t)kev_size[layout]) return -D_EFAULT;
		nout++;
		if (n->k.flags & EV_ONESHOT) drop(n);
	}
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
static long bsd_kevent(struct ctx* c) { return do_kevent((int)c->a[0], 0, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], ts_ms(c->a[5])); }
// kevent64(kq, changelist, nchanges, eventlist, nevents, flags, timeout)
static long bsd_kevent64(struct ctx* c) { return do_kevent((int)c->a[0], 1, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], ts_ms(ctx_arg(c, 6))); }
// kevent_qos(kq, changelist, nchanges, eventlist, nevents, data_out, data_available, flags)
static long bsd_kevent_qos(struct ctx* c) {
	uint64_t flags = ctx_arg(c, 7);
	return do_kevent((int)c->a[0], 2, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], (flags & 1) ? 0 : -1);
}

// kevent_id(id, changelist, nchanges, eventlist, nevents, data_out, data_available, flags): cola de trabajo de
// libdispatch (workloop); cada identificador tiene su propio kqueue.
static struct { uint64_t id; int kq; } workloops[64];
static long bsd_kevent_id(struct ctx* c) {
	uint64_t flags = ctx_arg(c, 7);
	int kq = -1;
	for (int i = 0; i < 64; i++) {
		if (workloops[i].kq > 0 && workloops[i].id == c->a[0]) { kq = workloops[i].kq; break; }
		if (workloops[i].kq == 0) { kq = workloops[i].kq = epoll_create1(EPOLL_CLOEXEC); workloops[i].id = c->a[0]; break; }
	}
	if (kq < 0) return -D_ENOMEM;
	wq_note_workloop(c->a[0]);
	return do_kevent(kq, 2, c->a[1], (long)(int)c->a[2], c->a[3], (long)(int)c->a[4], (flags & 1) ? 0 : -1);
}

void emu_kqueue_init(void) {
	reg_bsd(375, bsd_kevent_id);
	reg_bsd(362, bsd_kqueue); reg_bsd(363, bsd_kevent); reg_bsd(369, bsd_kevent64); reg_bsd(374, bsd_kevent_qos);
}

// Aplica una lista de cambios sin recoger eventos (retorno de hilo de workloop).
long kq_apply_changes(int layout, uint64_t chg, long n) { return do_kevent(workq_kq_get(), layout, chg, n, 0, 0, 0); }
