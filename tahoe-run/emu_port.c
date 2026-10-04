// Puertos Mach dentro de un proceso: derechos de recepción con cola de mensajes, conjuntos de puertos, envío y
// recepción con mach_msg2. Los nombres son locales a cada proceso de tahoe-run; la comunicación entre procesos
// (launchd <-> sus hijos) todavía no existe.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include "tahoe.h"

struct qmsg { uint32_t size; uint8_t* data; struct qmsg* next; };
struct port { uint32_t name, set; int is_set, efd, count; struct qmsg *head, *tail; struct port* next; };

static struct port* ports;
static pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static void init_cv(void) { pthread_condattr_t a; pthread_condattr_init(&a); pthread_condattr_setclock(&a, CLOCK_MONOTONIC); pthread_cond_init(&cv, &a); }

enum { KERN_OK = 0, KERN_INVALID_NAME_ = 15, KERN_INVALID_RIGHT_ = 17, KERN_INVALID_VALUE_ = 18 };
#define MACH_RCV_TIMED_OUT 0x10004003
#define MACH_RCV_TOO_LARGE_ 0x10004004

static struct port* find_locked(uint32_t name) {
	for (struct port* p = ports; p; p = p->next) if (p->name == name) return p;
	return NULL;
}

uint32_t port_create(int is_set) {
	pthread_once(&once, init_cv);
	struct port* p = calloc(1, sizeof *p);
	p->is_set = is_set;
	p->efd = eventfd(0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
	p->name = alloc_port();
	pthread_mutex_lock(&lk);
	p->next = ports; ports = p;
	pthread_mutex_unlock(&lk);
	return p->name;
}

int port_exists(uint32_t name) { pthread_mutex_lock(&lk); int r = find_locked(name) != NULL; pthread_mutex_unlock(&lk); return r; }

// eventfd que está legible mientras haya mensajes (para EVFILT_MACHPORT). -1 si el puerto no existe.
int port_eventfd(uint32_t name) { pthread_mutex_lock(&lk); struct port* p = find_locked(name); int r = p ? p->efd : -1; pthread_mutex_unlock(&lk); return r; }

static void destroy(uint32_t name) {
	pthread_mutex_lock(&lk);
	for (struct port** pp = &ports; *pp; pp = &(*pp)->next) {
		struct port* p = *pp;
		if (p->name != name) continue;
		*pp = p->next;
		for (struct port* m = ports; m; m = m->next) if (m->set == name) m->set = 0;
		while (p->head) { struct qmsg* q = p->head; p->head = q->next; free(q->data); free(q); }
		close(p->efd); free(p);
		break;
	}
	pthread_mutex_unlock(&lk);
}

// Encola un mensaje completo (cabecera ya con los campos reales). 0 si el puerto existe.
int port_send(uint32_t dest, const uint8_t* msg, uint32_t size) {
	pthread_once(&once, init_cv);
	pthread_mutex_lock(&lk);
	struct port* p = find_locked(dest);
	if (!p || p->is_set) { pthread_mutex_unlock(&lk); return -1; }
	struct qmsg* q = malloc(sizeof *q);
	q->size = size; q->data = malloc(size); memcpy(q->data, msg, size); q->next = NULL;
	if (p->tail) p->tail->next = q; else p->head = q;
	p->tail = q; p->count++;
	uint64_t one = 1;
	if (write(p->efd, &one, 8) < 0) {}
	if (p->set) { struct port* s = find_locked(p->set); if (s) { s->count++; if (write(s->efd, &one, 8) < 0) {} } }
	pthread_cond_broadcast(&cv);
	pthread_mutex_unlock(&lk);
	return 0;
}

// Saca un mensaje de un puerto o de cualquier miembro de un conjunto. timeout_ms < 0: sin plazo.
// Devuelve 0 con *out/*size (a liberar con free), o un código mach_msg de error.
int port_receive(uint32_t name, int timeout_ms, uint8_t** out, uint32_t* size) {
	pthread_once(&once, init_cv);
	struct timespec dl;
	if (timeout_ms >= 0) { clock_gettime(CLOCK_MONOTONIC, &dl); dl.tv_sec += timeout_ms / 1000; dl.tv_nsec += (timeout_ms % 1000) * 1000000L; if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; } }
	pthread_mutex_lock(&lk);
	for (;;) {
		struct port* p = find_locked(name);
		if (!p) { pthread_mutex_unlock(&lk); return 0x10004008; /* MACH_RCV_INVALID_NAME */ }
		struct port* src = NULL;
		if (!p->is_set) src = p->count ? p : NULL;
		else for (struct port* m = ports; m; m = m->next) if (m->set == name && m->count) { src = m; break; }
		if (src) {
			struct qmsg* q = src->head;
			src->head = q->next; if (!src->head) src->tail = NULL;
			src->count--;
			uint64_t v;
			if (read(src->efd, &v, 8) < 0) {}
			if (src->set) { struct port* s = find_locked(src->set); if (s) { s->count--; if (read(s->efd, &v, 8) < 0) {} } }
			*out = q->data; *size = q->size; free(q);
			pthread_mutex_unlock(&lk);
			return 0;
		}
		int r = timeout_ms >= 0 ? pthread_cond_timedwait(&cv, &lk, &dl) : pthread_cond_wait(&cv, &lk);
		if (r) { pthread_mutex_unlock(&lk); return MACH_RCV_TIMED_OUT; }
	}
}

// ---------------------------------------------------------------- trampas Mach
// mach_port_allocate_trap(task, right, *name): 1 = derecho de recepción, 3 = conjunto de puertos
static long t_allocate(struct ctx* c) {
	if (c->a[1] != 1 && c->a[1] != 3) return KERN_INVALID_VALUE_;
	uint32_t n = port_create(c->a[1] == 3);
	return safe_write(c->a[2], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
// mach_port_construct_trap(task, options*, context, *name): options.flags & 2 = con derecho de envío
static long t_construct(struct ctx* c) {
	uint32_t flags = 0;
	if (c->a[1]) safe_read(c->a[1], &flags, 4);
	uint32_t n = port_create(flags & 8 /* MPO_PORTSET */);
	return safe_write(c->a[3], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
static long t_destruct(struct ctx* c) {
	if (port_exists((uint32_t)c->a[1])) destroy((uint32_t)c->a[1]);
	return KERN_OK;
}
// mach_port_mod_refs_trap(task, name, right, delta): quitar la última referencia de recepción destruye el puerto
static long t_mod_refs(struct ctx* c) {
	int32_t delta = (int32_t)c->a[3];
	if (c->a[2] == 1 /* RECEIVE */ && delta < 0 && port_exists((uint32_t)c->a[1])) destroy((uint32_t)c->a[1]);
	return KERN_OK;
}
static long t_nop(struct ctx* c) { (void)c; return KERN_OK; }
// mach_port_insert_member_trap(task, name, pset) / move_member(task, member, after)
static long t_insert_member(struct ctx* c) {
	pthread_mutex_lock(&lk);
	struct port *p = find_locked((uint32_t)c->a[1]), *s = find_locked((uint32_t)c->a[2]);
	long r = KERN_INVALID_NAME_;
	if (p && s && s->is_set) { p->set = s->name; r = KERN_OK; }
	pthread_mutex_unlock(&lk);
	return r;
}
// mach_port_type_trap(task, name, *tipo): bits de MACH_PORT_TYPE_* del nombre
static long t_type(struct ctx* c) {
	uint32_t name = (uint32_t)c->a[1], t;
	pthread_mutex_lock(&lk);
	struct port* p = find_locked(name);
	t = p ? (p->is_set ? 1u << 19 : (1u << 17) | (1u << 16)) : (name >> 8) < 0x25 ? (1u << 16) : 0;   // nombres bajos = objetos del kernel
	pthread_mutex_unlock(&lk);
	if (!t) return KERN_INVALID_NAME_;
	return safe_write(c->a[2], &t, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
static long t_reply_port(struct ctx* c) { (void)c; return port_create(0); }

void emu_port_init(void) {
	reg_mach(16, t_allocate); reg_mach(24, t_construct); reg_mach(25, t_destruct); reg_mach(19, t_mod_refs);
	reg_mach(18, t_nop); reg_mach(21, t_nop); reg_mach(22, t_insert_member); reg_mach(20, t_insert_member);
	reg_mach(26, t_reply_port); reg_mach(76, t_type);
}
