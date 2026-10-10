// Semáforos Mach (semaphore_create y las trampas semaphore_*) y __semwait_signal, sobre pthread.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "tahoe.h"

#define KERN_OK 0
#define KERN_BAD_ARG 4
#define KERN_TIMED_OUT 49
#define KERN_ABORTED_ 14

struct sem { uint32_t name; int count; pthread_mutex_t m; pthread_cond_t cv; struct sem* next; };
static struct sem* sems;
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

uint32_t sem_create(int value) {
	struct sem* s = calloc(1, sizeof *s);
	pthread_condattr_t ca; pthread_condattr_init(&ca); pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_mutex_init(&s->m, NULL); pthread_cond_init(&s->cv, &ca);
	s->count = value;
	s->name = alloc_port();
	pthread_mutex_lock(&table_lock);
	s->next = sems; sems = s;
	pthread_mutex_unlock(&table_lock);
	return s->name;
}

static struct sem* find(uint32_t name) {
	pthread_mutex_lock(&table_lock);
	struct sem* s = sems;
	while (s && s->name != name) s = s->next;
	pthread_mutex_unlock(&table_lock);
	return s;
}

static void signal_one(struct sem* s) { pthread_mutex_lock(&s->m); s->count++; pthread_cond_signal(&s->cv); pthread_mutex_unlock(&s->m); }

// Espera con plazo opcional (ns relativos; <0 = sin plazo). 0 = obtenido, 1 = plazo vencido.
static int wait_sem(struct sem* s, long long rel_ns) {
	struct timespec dl;
	if (rel_ns >= 0) { clock_gettime(CLOCK_MONOTONIC, &dl); dl.tv_sec += rel_ns / 1000000000LL; dl.tv_nsec += rel_ns % 1000000000LL; if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; } }
	int r = 0;
	pthread_mutex_lock(&s->m);
	while (s->count <= 0 && !r) r = rel_ns >= 0 ? pthread_cond_timedwait(&s->cv, &s->m, &dl) : pthread_cond_wait(&s->cv, &s->m);
	if (s->count > 0) { s->count--; r = 0; }
	pthread_mutex_unlock(&s->m);
	return r ? 1 : 0;
}

static long t_signal(struct ctx* c)     { struct sem* s = find((uint32_t)c->a[0]); if (!s) return KERN_BAD_ARG; signal_one(s); return KERN_OK; }
static long t_signal_all(struct ctx* c) { struct sem* s = find((uint32_t)c->a[0]); if (!s) return KERN_BAD_ARG; pthread_mutex_lock(&s->m); s->count += 1000; pthread_cond_broadcast(&s->cv); pthread_mutex_unlock(&s->m); return KERN_OK; }
static long t_wait(struct ctx* c)       { struct sem* s = find((uint32_t)c->a[0]); if (!s) return KERN_BAD_ARG; wait_sem(s, -1); return KERN_OK; }
static long t_wait_signal(struct ctx* c) {
	struct sem *w = find((uint32_t)c->a[0]), *g = find((uint32_t)c->a[1]);
	if (!w || !g) return KERN_BAD_ARG;
	signal_one(g); wait_sem(w, -1); return KERN_OK;
}
static long t_timedwait(struct ctx* c) {
	struct sem* s = find((uint32_t)c->a[0]); if (!s) return KERN_BAD_ARG;
	return wait_sem(s, (long long)(uint32_t)c->a[1] * 1000000000LL + (int32_t)c->a[2]) ? KERN_TIMED_OUT : KERN_OK;
}
static long t_timedwait_signal(struct ctx* c) {
	struct sem *w = find((uint32_t)c->a[0]), *g = find((uint32_t)c->a[1]);
	if (!w || !g) return KERN_BAD_ARG;
	signal_one(g);
	return wait_sem(w, (long long)(uint32_t)c->a[2] * 1000000000LL + (int32_t)c->a[3]) ? KERN_TIMED_OUT : KERN_OK;
}

// __semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec, tv_nsec): usado por pthread_cond/join.
static long bsd_semwait_signal(struct ctx* c) {
	struct sem* w = find((uint32_t)c->a[0]);
	if (!w) return -D_EINVAL;
	if (c->a[1]) { struct sem* g = find((uint32_t)c->a[1]); if (g) signal_one(g); }
	long long ns = -1;
	if (c->a[2]) {
		long long sec = (long long)c->a[4], nsec = (long long)(int)ctx_arg(c, 5);
		if (c->a[3]) ns = sec * 1000000000LL + nsec;      // relativo
		else { struct timespec now; clock_gettime(CLOCK_REALTIME, &now); ns = (sec - now.tv_sec) * 1000000000LL + (nsec - now.tv_nsec); if (ns < 0) ns = 0; }
	}
	return wait_sem(w, ns) ? -60 /* ETIMEDOUT */ : 0;
}


// ---- semáforos POSIX con nombre: los de Linux (glibc, /dev/shm/sem.*), compartidos entre procesos como en macOS.
// sem_open de Darwin devuelve un identificador que libsystem trata como sem_t*; aquí es un índice de esta tabla + 1.
#include <semaphore.h>
#include <fcntl.h>
#include <stdio.h>
#define PSEM_MAX 256
static sem_t* psem_tab[PSEM_MAX];
static pthread_mutex_t psem_lock = PTHREAD_MUTEX_INITIALIZER;
static int psem_name(uint64_t gname, char* out, size_t cap) {
	char n[256];
	if (safe_string(gname, n, sizeof n) != 0) return -1;
	const char* s = n[0] == '/' ? n + 1 : n;
	snprintf(out, cap, "/tahoe-%s", s);
	for (char* q = out + 1; *q; q++) if (*q == '/') *q = '_';
	return 0;
}
static sem_t* psem_get(uint64_t id) { return (id >= 1 && id <= PSEM_MAX) ? psem_tab[id - 1] : NULL; }
static long bsd_sem_open(struct ctx* c) {
	char nm[300];
	if (psem_name(c->a[0], nm, sizeof nm) != 0) return -14;
	int df = (int)c->a[1], lf = 0;
	if (df & 0x200) lf |= O_CREAT;
	if (df & 0x800) lf |= O_EXCL;
	sem_t* s = (lf & O_CREAT) ? sem_open(nm, lf, (mode_t)c->a[2], (unsigned)c->a[3]) : sem_open(nm, lf);
	if (s == SEM_FAILED) return -darwin_errno(errno);
	pthread_mutex_lock(&psem_lock);
	long id = -24;                                       // EMFILE
	for (int i = 0; i < PSEM_MAX; i++) if (!psem_tab[i]) { psem_tab[i] = s; id = i + 1; break; }
	pthread_mutex_unlock(&psem_lock);
	if (id < 0) sem_close(s);
	return id;
}
static long bsd_sem_close(struct ctx* c) {
	pthread_mutex_lock(&psem_lock);
	sem_t* s = psem_get(c->a[0]);
	if (s) psem_tab[c->a[0] - 1] = NULL;
	pthread_mutex_unlock(&psem_lock);
	if (!s) return -22;
	sem_close(s);
	return 0;
}
static long bsd_sem_unlink(struct ctx* c) {
	char nm[300];
	if (psem_name(c->a[0], nm, sizeof nm) != 0) return -14;
	return sem_unlink(nm) == 0 ? 0 : -darwin_errno(errno);
}
static long bsd_sem_wait(struct ctx* c) {
	sem_t* s = psem_get(c->a[0]);
	if (!s) return -22;
	while (sem_wait(s) != 0) { if (errno != EINTR) return -darwin_errno(errno); return -4; }
	return 0;
}
static long bsd_sem_trywait(struct ctx* c) {
	sem_t* s = psem_get(c->a[0]);
	if (!s) return -22;
	return sem_trywait(s) == 0 ? 0 : -darwin_errno(errno);   // EAGAIN -> 35 en Darwin
}
static long bsd_sem_post(struct ctx* c) {
	sem_t* s = psem_get(c->a[0]);
	if (!s) return -22;
	return sem_post(s) == 0 ? 0 : -darwin_errno(errno);
}

void emu_sem_init(void) {
	reg_mach(33, t_signal); reg_mach(34, t_signal_all); reg_mach(36, t_wait); reg_mach(37, t_wait_signal);
	reg_mach(38, t_timedwait); reg_mach(39, t_timedwait_signal);
	reg_bsd(334, bsd_semwait_signal); reg_bsd(423, bsd_semwait_signal);
	reg_bsd(268, bsd_sem_open); reg_bsd(269, bsd_sem_close); reg_bsd(270, bsd_sem_unlink);
	reg_bsd(271, bsd_sem_wait); reg_bsd(272, bsd_sem_trywait); reg_bsd(273, bsd_sem_post);
}
