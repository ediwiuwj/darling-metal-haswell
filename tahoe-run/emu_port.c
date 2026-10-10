// Puertos Mach compartidos entre los procesos de tahoe-run: derechos de recepción con cola de mensajes, conjuntos
// de puertos y envío/recepción con mach_msg2 (ver la región compartida más abajo).
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <glob.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include <sched.h>
#include <sys/syscall.h>
#include <time.h>
#include "tahoe.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

// ---------------------------------------------------------------- región compartida entre procesos
// Todos los procesos de tahoe-run de un mismo arranque comparten una región (archivo en /dev/shm indicado por
// TAHOE_PORTS) con la tabla de puertos y las colas de mensajes. Un nombre de puerto es global: el mismo número
// designa el mismo puerto en cualquier proceso. El dueño del derecho de recepción es quien lo creó; para despertar
// a su epoll (EVFILT_MACHPORT) cada puerto tiene un socket de datagramas con nombre abstracto.
#define MAXPORTS 2048
#define MAXMSG   512
#define MSGSZ    (64 * 1024)
struct sport { uint32_t name, set, head, tail, count; int32_t owner, rpid; uint8_t used, is_set; pthread_cond_t cv; };   // cv: despierta solo a quien espera este puerto/conjunto   // rpid: proceso que recibe ahora (cambia al mover el derecho de recepción)
struct mslot { uint32_t next, size, total, spid, suid, sgid; uint8_t data[MSGSZ - 24]; };
struct shm {
	pthread_mutex_t lk; pthread_cond_t cv;
	uint32_t next_name, free_head, magic, special[8];
	struct sport ports[MAXPORTS];
	struct mslot msgs[MAXMSG];
};
static struct shm* shm;
static char shm_path[128], tag[32];
static int local_sock[MAXPORTS];           // socket de despertar de los puertos propios (índice = posición en la tabla)

static int is_creator;
void start_syslog_listener(void);
void ports_cleanup(void);
void ports_cleanup(void) {                       // solo el proceso que creó la región la borra (y los shm_open del arranque)
	if (!is_creator) return;
	unlink(shm_path);
	glob_t g;
	char pat[128];
	snprintf(pat, sizeof pat, "/dev/shm/tahoe.%s.*", tag);
	if (glob(pat, 0, NULL, &g) == 0) { for (size_t i = 0; i < g.gl_pathc; i++) unlink(g.gl_pathv[i]); globfree(&g); }
}

static void shm_init(void) {
	const char* env = getenv("TAHOE_PORTS");
	int creator = 0;
	if (env) snprintf(shm_path, sizeof shm_path, "%s", env);
	else { struct timespec tsn; clock_gettime(CLOCK_REALTIME, &tsn); snprintf(tag, sizeof tag, "%lx%lx", (long)tsn.tv_sec, (long)tsn.tv_nsec); snprintf(shm_path, sizeof shm_path, "/dev/shm/tahoe-ports-%s", tag); creator = 1; }
	int fd = open(shm_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) { logf_("    puertos: no puedo abrir %s: %s\n", shm_path, strerror(errno)); exit(70); }
	if (creator && ftruncate(fd, sizeof(struct shm)) != 0) { logf_("    puertos: ftruncate: %s\n", strerror(errno)); exit(70); }
	shm = mmap(NULL, sizeof(struct shm), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (shm == MAP_FAILED) { logf_("    puertos: mmap: %s\n", strerror(errno)); exit(70); }
	if (creator) {
		is_creator = 1;
		start_syslog_listener();
		pthread_mutexattr_t ma; pthread_mutexattr_init(&ma); pthread_mutexattr_setpshared(&ma, PTHREAD_PROCESS_SHARED); pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
		pthread_mutex_init(&shm->lk, &ma);
		pthread_condattr_t ca; pthread_condattr_init(&ca); pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED); pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
		pthread_cond_init(&shm->cv, &ca);
		for (int i = 0; i < MAXPORTS; i++) pthread_cond_init(&shm->ports[i].cv, &ca);
		shm->next_name = 0x2503;
		for (int i = 0; i < MAXMSG; i++) shm->msgs[i].next = i + 1 < MAXMSG ? (uint32_t)(i + 2) : 0;   // índices desde 1; 0 = fin
		shm->free_head = 1;
		shm->magic = 0x7a110001;
		setenv("TAHOE_PORTS", shm_path, 1);
		setenv("TAHOE_PORTS_OWNER", tag, 1);
		atexit(ports_cleanup);
	} else {
		snprintf(tag, sizeof tag, "%s", getenv("TAHOE_PORTS_OWNER") ? getenv("TAHOE_PORTS_OWNER") : "x");
	}
	for (int i = 0; i < MAXPORTS; i++) local_sock[i] = -1;
}
static pthread_once_t once = PTHREAD_ONCE_INIT;
static void init_all(void) { shm_init(); }
static void lock(void) { pthread_once(&once, init_all); int r = pthread_mutex_lock(&shm->lk); if (r == EOWNERDEAD) pthread_mutex_consistent(&shm->lk); }
static void unlock(void) { pthread_mutex_unlock(&shm->lk); }

enum { KERN_OK = 0, KERN_INVALID_NAME_ = 15, KERN_INVALID_RIGHT_ = 17, KERN_INVALID_VALUE_ = 18 };
#define MACH_RCV_TIMED_OUT 0x10004003
#define MACH_RCV_TOO_LARGE_ 0x10004004

// Los nombres se piden siempre a la región compartida (también los de semáforos y puertos del kernel falsos).
uint32_t alloc_port(void) {
	lock();
	uint32_t n = shm->next_name;
	shm->next_name += 0x100;
	unlock();
	return n;
}

static struct sport* find_locked(uint32_t name) {
	for (int i = 0; i < MAXPORTS; i++) if (shm->ports[i].used && shm->ports[i].name == name) return &shm->ports[i];
	return NULL;
}
static int port_index(struct sport* p) { return (int)(p - shm->ports); }

// Despierta a quien espere por un puerto con epoll (el dueño puede ser otro proceso).
static void poke(uint32_t name, int32_t rpid) {
	int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s < 0) return;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	int n = snprintf(a.sun_path + 1, sizeof a.sun_path - 1, "tahoe.%s.%u.%d", getenv("TAHOE_PORTS_OWNER") ? getenv("TAHOE_PORTS_OWNER") : "x", name, (int)rpid);
	char b = 1;
	if (sendto(s, &b, 1, 0, (struct sockaddr*)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n)) < 0 && mach_trace()) logf_("    poke 0x%x -> pid %d FALLÓ: %s\n", name, (int)rpid, strerror(errno));
	close(s);
}
// Vacía todos los avisos pendientes del socket: el aviso es un nivel ("hay mensajes"), no un contador; la cola de datagramas
// de Unix es corta y puede perder avisos, así que tras recibir se vuelve a avisar si aún quedan mensajes.
static void drain_all(int fd) { char b[64]; if (fd < 0) return; while (recv(fd, b, sizeof b, MSG_DONTWAIT) > 0) {} }

static int make_wake_socket(uint32_t name, int32_t rpid) {
	int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s < 0) return -1;
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	int n = snprintf(a.sun_path + 1, sizeof a.sun_path - 1, "tahoe.%s.%u.%d", getenv("TAHOE_PORTS_OWNER") ? getenv("TAHOE_PORTS_OWNER") : "x", name, (int)rpid);
	if (bind(s, (struct sockaddr*)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n)) < 0) { close(s); return -1; }
	return s;
}

uint32_t port_create(int is_set) {
	uint32_t name = alloc_port();
	lock();
	struct sport* p = NULL;
	for (int i = 0; i < MAXPORTS; i++) if (!shm->ports[i].used) { p = &shm->ports[i]; break; }
	if (!p) { unlock(); logf_("    puertos: tabla llena\n"); return 0; }
	{ pthread_cond_t keep = p->cv; memset(p, 0, sizeof *p); p->cv = keep; }   // la variable de condición se inicializó al crear la región
	p->used = 1; p->is_set = (uint8_t)is_set; p->name = name; p->owner = (int32_t)getpid(); p->rpid = (int32_t)getpid();
	local_sock[port_index(p)] = make_wake_socket(name, p->rpid);
	unlock();
	if (trace_all) logf_("    puerto 0x%x creado por pid %d (conjunto=%d)\n", name, (int)getpid(), is_set);
	return name;
}

int port_exists(uint32_t name) { lock(); int r = find_locked(name) != NULL; unlock(); return r; }

// Socket legible mientras haya mensajes pendientes (solo para puertos que creó este proceso). -1 si no.
int port_eventfd(uint32_t name) {
	lock();
	struct sport* p = find_locked(name);
	int r = -1;
	if (p) {
		int i = port_index(p);
		if (p->rpid != (int32_t)getpid() || local_sock[i] < 0) {             // el derecho de recepción se movió a este proceso
			if (local_sock[i] >= 0) close(local_sock[i]);
			p->rpid = (int32_t)getpid();
			local_sock[i] = make_wake_socket(name, p->rpid);
			if (mach_trace()) logf_("    puerto 0x%x: socket de aviso para pid %d fd=%d\n", name, (int)p->rpid, local_sock[i]);
			if (p->count) poke(name, p->rpid);                              // ya hay mensajes: despertar de inmediato
		}
		r = local_sock[i];
	}
	unlock();
	return r;
}

static void free_msgs_locked(struct sport* p) {
	while (p->head) { struct mslot* q = &shm->msgs[p->head - 1]; uint32_t nx = q->next; q->next = shm->free_head; shm->free_head = p->head; p->head = nx; }
	p->tail = 0; p->count = 0;
}

static void destroy(uint32_t name) {
	lock();
	struct sport* p = find_locked(name);
	if (p) {
		logf_("    puerto 0x%x destruido por pid %d (cola=%u)\n", name, (int)getpid(), p->count);
		int i = port_index(p);
		for (int k = 0; k < MAXPORTS; k++) if (shm->ports[k].used && shm->ports[k].set == name) shm->ports[k].set = 0;
		free_msgs_locked(p);
		if (local_sock[i] >= 0) { close(local_sock[i]); local_sock[i] = -1; }
		p->used = 0;
		pthread_cond_broadcast(&p->cv);   // quien espere en este puerto debe enterarse de que murió
	}
	unlock();
}

// Descriptores OOL (tipos 1 y 3 = memoria, 2 = puertos): el contenido se copia dentro del mensaje porque la
// dirección del emisor no vale en el proceso receptor.
static int ool_scan(const uint8_t* m, uint32_t size, uint32_t* out_off, uint32_t* out_len, int max) {
	if (size < 28 || !(m[3] & 0x80)) return 0;
	uint32_t cnt; memcpy(&cnt, m + 24, 4);
	uint32_t off = 28;
	int n = 0;
	for (uint32_t i = 0; i < cnt && off + 12 <= size; i++) {
		uint8_t type = m[off + 11];
		if (type == 0) { off += 12; continue; }
		if (off + 16 > size) break;
		if (n < max) {
			out_off[n] = off; memcpy(&out_len[n], m + off + 12, 4);
			if (type == 2) out_len[n] *= 4;                  // OOL de puertos: el campo es el número de puertos (4 bytes cada uno)
			n++;
		}
		off += 16;
	}
	return n;
}

// Encola un mensaje completo (cabecera con los campos reales). 0 si el puerto existe.
int port_send(uint32_t dest, const uint8_t* msg, uint32_t size) {
	uint32_t ooff[32], olen[32];
	uint8_t desc_fix[32 * 16];
	int nool = ool_scan(msg, size, ooff, olen, 32);
	uint64_t total = size;
	for (int i = 0; i < nool; i++) total += olen[i];
	(void)desc_fix;
	if (total > sizeof(((struct mslot*)0)->data)) { logf_("    puertos: mensaje de %lu bytes demasiado grande\n", (unsigned long)total); return -1; }
	lock();
	struct sport* p = find_locked(dest);
	if (!p || p->is_set || !shm->free_head) { unlock(); return -1; }
	uint32_t idx = shm->free_head;
	struct mslot* q = &shm->msgs[idx - 1];
	shm->free_head = q->next;
	q->next = 0; q->size = size; q->total = (uint32_t)total;
	q->spid = (uint32_t)getpid(); q->suid = geteuid(); q->sgid = getegid();   // para el trailer de auditoría del receptor
	memcpy(q->data, msg, size);
	uint32_t pos = size;
	for (int i = 0; i < nool; i++) {                       // copiar los bytes de cada descriptor OOL tras el mensaje
		uint64_t addr; memcpy(&addr, msg + ooff[i], 8);
		if (olen[i] && safe_read(addr, q->data + pos, olen[i]) != (ssize_t)olen[i]) memset(q->data + pos, 0, olen[i]);
		pos += olen[i];
	}
	if (p->tail) shm->msgs[p->tail - 1].next = idx; else p->head = idx;
	p->tail = idx; p->count++;
	uint32_t setname = p->set;
	int32_t rp_dest = p->rpid, rp_set = 0;
	if (setname) { struct sport* s = find_locked(setname); if (s) { s->count++; rp_set = s->rpid; } }
	pthread_cond_broadcast(&p->cv);
	if (setname) { struct sport* st2 = find_locked(setname); if (st2) pthread_cond_broadcast(&st2->cv); }
	unlock();
	poke(dest, rp_dest);
	if (setname) poke(setname, rp_set);
	return 0;
}

// Saca un mensaje de un puerto o de cualquier miembro de un conjunto. timeout_ms < 0: sin plazo.
// Devuelve 0 con *out/*size (a liberar con free), o un código mach_msg de error.
int port_receive(uint32_t name, int timeout_ms, uint8_t** out, uint32_t* size, uint32_t* sender /* pid, uid, gid */, uint32_t limit, int large) {
	struct timespec dl;
	if (timeout_ms >= 0) { clock_gettime(CLOCK_MONOTONIC, &dl); dl.tv_sec += timeout_ms / 1000; dl.tv_nsec += (timeout_ms % 1000) * 1000000L; if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; } }
	lock();
	int waited = 0;
	for (;;) {
		struct sport* p = find_locked(name);
		if (!p) { unlock(); return waited ? MACH_RCV_PORT_DIED_ : MACH_RCV_INVALID_NAME_; }
		struct sport* src = NULL;
		if (!p->is_set) src = p->count ? p : NULL;
		else for (int i = 0; i < MAXPORTS; i++) if (shm->ports[i].used && shm->ports[i].set == name && shm->ports[i].count) { src = &shm->ports[i]; break; }
		if (src) {
			uint32_t idx = src->head;
			struct mslot* q = &shm->msgs[idx - 1];
			if (large && limit && q->total > limit) {                       // MACH_RCV_LARGE: no se consume; se informa del tamaño necesario
				uint8_t* h = malloc(q->size ? q->size : 1);
				memcpy(h, q->data, q->size);
				*size = q->size; *out = h;
				unlock();
				return 0x10004004;
			}
			src->head = q->next; if (!src->head) src->tail = 0;
			src->count--;
			if (src->set) { struct sport* s = find_locked(src->set); if (s && s->count) s->count--; }
			uint32_t sz = q->size, tot = q->total;
			if (sender) { sender[0] = q->spid; sender[1] = q->suid; sender[2] = q->sgid; }
			uint8_t* m = malloc(tot ? tot : 1);
			memcpy(m, q->data, tot);
			q->next = shm->free_head; shm->free_head = idx;
			int si = port_index(src);
			int fd1 = local_sock[si], fd2 = -1;
			uint32_t rem1 = src->count, rname1 = src->name, rname2 = 0, rem2 = 0;
			int32_t rp1 = src->rpid, rp2 = 0;
			if (src->set) { struct sport* s = find_locked(src->set); if (s) { fd2 = local_sock[port_index(s)]; rem2 = s->count; rname2 = s->name; rp2 = s->rpid; } }
			unlock();
			drain_all(fd1); drain_all(fd2);
			if (rem1) poke(rname1, rp1);                        // aún quedan mensajes: renovar el aviso
			if (rem2) poke(rname2, rp2);
			// materializar los descriptores OOL en memoria nueva de este proceso
			uint32_t ooff[32], olen[32];
			int nool = ool_scan(m, sz, ooff, olen, 32);
			uint32_t pos = sz;
			for (int i = 0; i < nool; i++) {
				uint64_t addr = 0;
				if (olen[i]) {
					void* mem = mmap(NULL, (olen[i] + 4095u) & ~4095u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
					if (mem != MAP_FAILED) { memcpy(mem, m + pos, olen[i]); addr = (uint64_t)mem; }
				}
				memcpy(m + ooff[i], &addr, 8);
				pos += olen[i];
			}
			*out = m; *size = sz;
			return 0;
		}
		waited = 1;
		if (trace_all) logf_("    mach_msg: <%d> espera mensaje en 0x%x (plazo %d ms)\n", (int)getpid(), name, timeout_ms);
		int r = timeout_ms >= 0 ? pthread_cond_timedwait(&p->cv, &shm->lk, &dl) : pthread_cond_wait(&p->cv, &shm->lk);
		if (r == EOWNERDEAD) pthread_mutex_consistent(&shm->lk);
		else if (r) { unlock(); return MACH_RCV_TIMED_OUT; }
	}
}

// Puertos especiales de la tarea (bootstrap = 4): compartidos, para que los hijos hereden el de launchd.
// /var/run/syslog: libsystem usa asl/syslog como último recurso para mensajes de error (p. ej. launchd cuando rechaza una
// petición). Un hilo del proceso creador escucha en ese socket de datagramas y vuelca el texto al registro.
static void* syslog_thread(void* arg) {
	int s = (int)(long)arg;
	char buf[4096];
	for (;;) {
		ssize_t n = recv(s, buf, sizeof buf - 1, 0);
		if (n <= 0) { if (errno == EINTR) continue; break; }
		char out[4096]; size_t o = 0, run = 0;                 // texto imprimible del mensaje (ASL es binario)
		for (ssize_t i = 0; i < n && o < sizeof out - 2; i++) {
			unsigned char ch = (unsigned char)buf[i];
			if (ch >= 32 && ch < 127) { out[o++] = (char)ch; run++; }
			else { if (run >= 3 && o < sizeof out - 2) out[o++] = '|'; else o -= run; run = 0; }
		}
		out[o] = 0;
		logf_("    [syslog] %s\n", out);
	}
	return NULL;
}
void start_syslog_listener(void) {
	if (!tahoe_root) return;
	char path[4300];
	snprintf(path, sizeof path, "%s/private/var/run/syslog", tahoe_root);
	unlink(path);
	int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un a = { .sun_family = AF_UNIX };
	snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
	if (s < 0 || bind(s, (struct sockaddr*)&a, sizeof a) < 0) { if (s >= 0) close(s); return; }
	chmod(path, 0666);
	pthread_t th;
	pthread_create(&th, NULL, syslog_thread, (void*)(long)s);
	pthread_detach(th);
}

// Puertos especiales de ESTA tarea. Los hijos reciben los suyos por el entorno (TAHOE_SP<n>) desde las acciones de
// puerto de posix_spawn, como el bootstrap que launchd da a cada servicio.
static uint32_t special[8];
static pthread_once_t sp_once = PTHREAD_ONCE_INIT;
static void sp_init(void) {
	for (int i = 0; i < 8; i++) { char k[16]; snprintf(k, sizeof k, "TAHOE_SP%d", i); const char* v = getenv(k); if (v) special[i] = (uint32_t)strtoul(v, NULL, 10); }
}
// mach_ports_register(ports[3]): se guardan en la región compartida; los hijos los heredan (en XNU, task_create copia
// itk_registered) y, mientras no tengan puerto bootstrap propio, usan el primero: así encuentran a launchd.
void registered_ports_set(const uint32_t* p, int n) { lock(); for (int i = 0; i < 3; i++) shm->special[i] = i < n ? p[i] : 0; unlock(); }
static uint32_t registered_port(int i) { lock(); uint32_t v = shm->special[i]; unlock(); return v; }
uint32_t special_port_get(int which) {
	pthread_once(&sp_once, sp_init);
	if (which < 0 || which >= 8) return 0;
	if (which == 4 && !special[4]) return registered_port(0);
	return special[which];
}
void special_port_set(int which, uint32_t name) { pthread_once(&sp_once, sp_init); if (which >= 0 && which < 8) special[which] = name; }

// ---------------------------------------------------------------- trampas Mach
// mach_port_allocate_trap(task, right, *name): 1 = derecho de recepción, 3 = conjunto de puertos
static long t_allocate(struct ctx* c) {
	if (c->a[1] != 1 && c->a[1] != 3) return KERN_INVALID_VALUE_;
	uint32_t n = port_create(c->a[1] == 3);
	return safe_write(c->a[2], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
// mach_port_construct_trap(task, options*, context, *name)
static long t_construct(struct ctx* c) {
	uint32_t flags = 0;
	if (c->a[1]) safe_read(c->a[1], &flags, 4);
	uint32_t n = port_create(0);                     // construct nunca crea conjuntos (el bit 8 es MPO_IMPORTANCE_RECEIVER)
	if (trace_all) { uint32_t opt[6] = { 0 }; if (c->a[1]) safe_read(c->a[1], opt, 24); logf_("    construct 0x%x: flags=0x%x qlimit=%u opt2=0x%x opt3=0x%x contexto=0x%lx\n", n, opt[0], opt[1], opt[2], opt[3], c->a[2]); }
	return safe_write(c->a[3], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
// Los nombres de puerto son globales, pero en Mach cada tarea tiene los suyos: quien suelta su derecho de ENVÍO no debe destruir el
// puerto del receptor. Solo el dueño del derecho de recepción (el creador, o quien lo recibió con MOVE_RECEIVE) puede destruirlo.
// Vacía el aviso de un puerto sin mensajes (o inexistente): evita que un aviso viejo mantenga legible el descriptor y
// el kqueue vuelva a despertar sin fin. Devuelve 1 si el puerto ya no existe.
int port_drain_idle(uint32_t name) {
	lock(); struct sport* p = find_locked(name);
	int gone = p == NULL, fd = p ? local_sock[port_index(p)] : -1, cnt = p ? p->count : 0;
	unlock();
	if (!cnt) drain_all(fd);
	return gone;
}
int port_rpid(uint32_t name) { lock(); struct sport* p = find_locked(name); int r = p ? p->rpid : -1; unlock(); return r; }
static int owns(uint32_t name) { lock(); struct sport* p = find_locked(name); int r = p && p->owner == (int32_t)getpid(); unlock(); return r; }
void port_move_receive(uint32_t name) { lock(); struct sport* p = find_locked(name); if (p) p->owner = (int32_t)getpid(); unlock(); }
static long t_ret0(struct ctx* c) { (void)c; return KERN_OK; }   // extract_member: sin efecto
extern void diag_crash(ucontext_t* uc);
static long t_destruct(struct ctx* c) {
	if (diag_target()) { logf_("    destruct 0x%x (hilo %ld):\n", (uint32_t)c->a[1], (long)syscall(SYS_gettid)); diag_crash(c->uc); }
	if (owns((uint32_t)c->a[1])) destroy((uint32_t)c->a[1]);
	return KERN_OK;
}
// mach_port_mod_refs_trap(task, name, right, delta): quitar la última referencia de recepción destruye el puerto
static long t_mod_refs(struct ctx* c) {
	int32_t delta = (int32_t)c->a[3];
	if (c->a[2] == 1 /* RECEIVE */ && delta < 0 && owns((uint32_t)c->a[1])) {
		if (diag_target()) { logf_("    mod_refs RECEIVE -1 0x%x (hilo %ld):\n", (uint32_t)c->a[1], (long)syscall(SYS_gettid)); diag_crash(c->uc); }
		destroy((uint32_t)c->a[1]);
	}
	return KERN_OK;
}
static long t_nop(struct ctx* c) { (void)c; return KERN_OK; }
// mach_port_insert_member_trap(task, name, pset) / move_member(task, member, after)
static long t_insert_member(struct ctx* c) {
	lock();
	struct sport *p = find_locked((uint32_t)c->a[1]), *st = find_locked((uint32_t)c->a[2]);
	long r = KERN_INVALID_NAME_;
	if (p && st && st->is_set) { p->set = st->name; r = KERN_OK; }
	unlock();
	return r;
}
// mach_port_type_trap(task, name, *tipo): bits de MACH_PORT_TYPE_* del nombre
static long t_type(struct ctx* c) {
	uint32_t name = (uint32_t)c->a[1], t;
	lock();
	struct sport* p = find_locked(name);
	t = p ? (p->is_set ? 1u << 19 : (1u << 17) | (1u << 16)) : (name >> 8) < 0x25 ? (1u << 16) : 0;   // nombres bajos = objetos del kernel
	unlock();
	if (!t) return KERN_INVALID_NAME_;
	return safe_write(c->a[2], &t, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}
// thread_switch(hilo, opción, ms): ceder la CPU. Con OSLOCK_WAIT/WAIT (4/2) se espera el tiempo indicado; si no, solo se cede.
static long t_thread_switch(struct ctx* c) {
	uint32_t opt = (uint32_t)c->a[1], ms = (uint32_t)c->a[2];
	if ((opt == 2 || opt == 4) && ms) { struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L }; nanosleep(&ts, NULL); }
	else sched_yield();
	return 0;
}
static long t_reply_port(struct ctx* c) { (void)c; return port_create(0); }
// thread_get_special_reply_port: cada hilo tiene UN puerto de respuesta especial que se reutiliza mientras exista
static __thread uint32_t special_reply;
static long t_special_reply_port(struct ctx* c) {
	(void)c;
	if (!special_reply || !port_exists(special_reply)) special_reply = port_create(0);
	return special_reply;
}

// mach_generate_activity_id(task, cantidad, *id): identificadores de actividad (os_activity) únicos
static long t_activity_id(struct ctx* c) {
	static _Atomic uint64_t next = 1;
	uint64_t n = c->a[1] ? c->a[1] : 1;
	uint64_t id = atomic_fetch_add(&next, n) | ((uint64_t)getpid() << 40);
	return safe_write(c->a[2], &id, 8) == 8 ? KERN_OK : KERN_INVALID_VALUE_;
}

// ---------------------------------------------------------------- mk_timer: puertos que reciben un mensaje al vencer
// mach_absolute_time de este entorno son nanosegundos de CLOCK_MONOTONIC, así que el plazo se usa tal cual.
struct mktimer { uint32_t name; int tfd; pthread_t th; int live; };
static struct mktimer timers[64];
static pthread_mutex_t timers_lock = PTHREAD_MUTEX_INITIALIZER;
static void* mk_timer_thread(void* p) {
	struct mktimer* t = p;
	for (;;) {
		uint64_t n;
		ssize_t r = read(t->tfd, &n, 8);
		if (r != 8) { if (errno == EINTR) continue; break; }
		uint8_t msg[48] = { 0 };                                   // mk_timer_expire_msg: cabecera + 3 palabras sin uso
		uint32_t bits = 0x11, size = 48, id = 0;
		memcpy(msg, &bits, 4); memcpy(msg + 4, &size, 4); memcpy(msg + 8, &t->name, 4); memcpy(msg + 20, &id, 4);
		port_send(t->name, msg, 48);
	}
	return NULL;
}
static struct mktimer* timer_find(uint32_t name) { for (int i = 0; i < 64; i++) if (timers[i].live && timers[i].name == name) return &timers[i]; return NULL; }
static long t_mk_create(struct ctx* c) {
	(void)c;
	pthread_mutex_lock(&timers_lock);
	struct mktimer* t = NULL;
	for (int i = 0; i < 64; i++) if (!timers[i].live) { t = &timers[i]; break; }
	if (!t) { pthread_mutex_unlock(&timers_lock); return 0; }
	t->name = port_create(0);
	t->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	t->live = 1;
	pthread_create(&t->th, NULL, mk_timer_thread, t);
	pthread_detach(t->th);
	pthread_mutex_unlock(&timers_lock);
	return t->name;
}
static long t_mk_arm(struct ctx* c) {              // (name, expire) o (name, flags, expire, leeway)
	struct mktimer* t = timer_find((uint32_t)c->a[0]);
	if (!t) return KERN_INVALID_NAME_;
	uint64_t exp = c->a[1];
	struct itimerspec it = { .it_value = { exp / 1000000000ULL, exp % 1000000000ULL } };
	if (!it.it_value.tv_sec && !it.it_value.tv_nsec) it.it_value.tv_nsec = 1;
	timerfd_settime(t->tfd, TFD_TIMER_ABSTIME, &it, NULL);
	return KERN_OK;
}
static long t_mk_arm_leeway(struct ctx* c) { struct ctx c2 = *c; c2.a[1] = c->a[2]; return t_mk_arm(&c2); }
static long t_mk_cancel(struct ctx* c) {
	struct mktimer* t = timer_find((uint32_t)c->a[0]);
	if (!t) return KERN_INVALID_NAME_;
	struct itimerspec cur, off = { 0 };
	timerfd_settime(t->tfd, 0, &off, &cur);
	uint64_t res = cur.it_value.tv_sec ? (uint64_t)cur.it_value.tv_sec * 1000000000ULL + cur.it_value.tv_nsec : cur.it_value.tv_nsec;
	if (c->a[1]) safe_write(c->a[1], &res, 8);
	return KERN_OK;
}
static long t_mk_destroy(struct ctx* c) {
	struct mktimer* t = timer_find((uint32_t)c->a[0]);
	if (!t) return KERN_INVALID_NAME_;
	t->live = 0;
	close(t->tfd);
	destroy(t->name);
	return KERN_OK;
}

// host_create_mach_voucher_trap(host, recetas*, tamaño, *puerto): los vouchers son nombres de puerto sin contenido
static long t_voucher_create(struct ctx* c) {
	uint32_t n = alloc_port();
	return safe_write(c->a[3], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}

// mach_port_guard_trap(task, nombre, guarda, estricto): sin efecto
static long t_guard(struct ctx* c) { (void)c; return KERN_OK; }
// mach_port_get_attributes_trap(task, nombre, sabor, info*, cuenta*): solo MACH_PORT_RECEIVE_STATUS (2)
static long t_get_attributes(struct ctx* c) {
	if ((int)c->a[2] != 2) return KERN_INVALID_VALUE_;
	uint32_t st[10] = { 0 };            // mach_port_status_t: pset, seqno, mscount, qlimit, msgcount, sorights, srights, pdrequest, nsrequest, flags
	lock();
	struct sport* p = find_locked((uint32_t)c->a[1]);
	if (p) { st[3] = 5; st[4] = p->count; st[6] = 1; }
	unlock();
	if (!p) return KERN_INVALID_NAME_;
	if (safe_write(c->a[3], st, sizeof st) != sizeof st) return KERN_INVALID_VALUE_;
	return KERN_OK;
}
// task_name_for_pid(host, pid, *puerto): puerto de nombre de tarea ficticio por proceso
static long t_task_name_for_pid(struct ctx* c) {
	uint32_t n = alloc_port();
	return safe_write(c->a[2], &n, 4) == 4 ? KERN_OK : KERN_INVALID_VALUE_;
}

// mach_port_request_notification_trap(task, nombre, variante, sync, aviso, polí, *anterior): se acepta sin generar avisos
static long t_request_notification(struct ctx* c) {
	uint64_t prev = ctx_arg(c, 6);
	uint32_t zero = 0;
	if (prev) safe_write(prev, &zero, 4);
	return KERN_OK;
}

void emu_port_init(void) {
	reg_mach(42, t_guard); reg_mach(77, t_request_notification);
	reg_mach(41, t_guard); reg_mach(40, t_get_attributes); reg_mach(44, t_task_name_for_pid);
	reg_mach(70, t_voucher_create);
	reg_mach(91, t_mk_create); reg_mach(92, t_mk_destroy); reg_mach(93, t_mk_arm); reg_mach(94, t_mk_cancel); reg_mach(95, t_mk_arm_leeway);
	reg_mach(43, t_activity_id);
	reg_mach(16, t_allocate); reg_mach(23, t_ret0); reg_mach(24, t_construct); reg_mach(25, t_destruct); reg_mach(19, t_mod_refs);
	reg_mach(18, t_nop); reg_mach(21, t_nop); reg_mach(22, t_insert_member); reg_mach(20, t_insert_member);
	reg_mach(26, t_reply_port); reg_mach(61, t_thread_switch); reg_mach(50, t_special_reply_port); reg_mach(76, t_type);
}
