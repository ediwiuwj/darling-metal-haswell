// Mach IPC: mach_msg2 (trampa 47) hacia objetos del kernel (tarea, host, hilo).
//
// macOS 26 llama a las rutinas MIG del kernel (mach_vm_map, host_info...) con mach_msg2 y la opción
// MACH64_SEND_KOBJECT_CALL, sin vector: el mensaje completo (cabecera incluida) está en `data` y la respuesta
// se escribe en ese mismo búfer (hasta rcv_size bytes), seguida de un trailer de 8 bytes.
//
// Aquí el "kernel" es este proceso: cada identificador de mensaje se atiende en una función. Lo que no se
// conozca recibe la respuesta estándar de MIG "identificador erróneo" (MIG_BAD_ID) y se registra.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#include <time.h>
#include <fcntl.h>
#include "tahoe.h"

#define MACH_MSG_SUCCESS     0
#define MACH_RCV_TOO_LARGE   0x10004004
#define MIG_BAD_ID           (-303)
#define KERN_SUCCESS_        0
#define KERN_INVALID_ADDR    1
#define KERN_NO_SPACE_       3
#define KERN_INVALID_ARG     4

struct hdr { uint32_t bits, size, remote, local, voucher; int32_t id; };

// ---------------------------------------------------------------- volcado para depurar
static void hexdump(const uint8_t* b, size_t len) {
	for (size_t i = 0; i < len; i += 16) {
		char line[100];
		int n = snprintf(line, sizeof line, "      %04zx ", i);
		for (size_t j = i; j < i + 16 && j < len; j++) n += snprintf(line + n, sizeof line - n, " %02x", b[j]);
		logf_("%s\n", line);
	}
}

// ---------------------------------------------------------------- construcción de respuestas
// Respuesta MIG: cabecera (24) + NDR (8) + código de retorno (4) + datos. Todo empaquetado a 4 bytes.
static const uint8_t NDR_LE[8] = { 0, 0, 0, 0, 1, 0, 0, 0 };   // little-endian, ASCII, IEEE

static size_t reply_begin(uint8_t* r, const struct hdr* req, int32_t retcode) {
	struct hdr h = { .bits = 0, .size = 0, .remote = 0, .local = 0, .voucher = 0, .id = req->id + 100 };
	memcpy(r, &h, sizeof h);
	memcpy(r + 24, NDR_LE, 8);
	memcpy(r + 32, &retcode, 4);
	return 36;
}
static void reply_end(uint8_t* r, size_t len) { memcpy(r + 4, &(uint32_t){ (uint32_t)len }, 4); }


#include "emu_iokit.inc"

// ---- entradas de memoria (mach_make_memory_entry): se respaldan con un archivo en /dev/shm, nombrado por el puerto.
// El rango del creador se sustituye por una proyección compartida del archivo para que el receptor vea sus escrituras.
static void me_path(char* b, size_t n, uint32_t port) { snprintf(b, n, "/dev/shm/tahoe-me-%s-%u", getenv("TAHOE_PORTS_OWNER") ? getenv("TAHOE_PORTS_OWNER") : "x", port); }
static size_t mig_make_memory_entry(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	uint64_t size, off;
	memcpy(&size, m + 48, 8); memcpy(&off, m + 56, 8);
	uint64_t len = round_up(size);
	uint32_t port = port_create(0);
	char path[128]; me_path(path, sizeof path, port);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	int ok = fd >= 0 && ftruncate(fd, (off_t)len) == 0 && off != 0;
	if (ok) {
		uint8_t* tmp = malloc(len);
		memcpy(tmp, (void*)off, len);                           // lo que ya hubiera escrito el creador
		if (pwrite(fd, tmp, len, 0) != (ssize_t)len) ok = 0;
		free(tmp);
		if (ok && mmap((void*)off, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0) == MAP_FAILED) ok = 0;
	}
	if (fd >= 0) close(fd);
	if (!ok) return reply_begin(r, req, KERN_INVALID_ARG);
	size_t n = reply_port(r, req, port, 17);
	memcpy(r + n, NDR_LE, 8); memcpy(r + n + 8, &len, 8);
	n += 16;
	return n;
}

// ---------------------------------------------------------------- rutinas MIG
// mach_vm_map (id 4811): cabecera, 1 descriptor de puerto (objeto), NDR, address, size, mask, flags, offset,
// copy, cur_protection, max_protection, inheritance. Solo se soporta memoria anónima (objeto nulo).
static size_t mig_mach_vm_map(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	if (req->size < 100) return reply_begin(r, req, KERN_INVALID_ARG);
	uint32_t objname;
	uint64_t addr, size, mask;
	int32_t flags, cur;
	memcpy(&objname, m + 28, 4);
	memcpy(&addr, m + 48, 8);
	memcpy(&size, m + 56, 8);
	memcpy(&mask, m + 64, 8);
	memcpy(&flags, m + 72, 4);
	memcpy(&cur, m + 88, 4);
	int32_t kr = KERN_SUCCESS_;
	if (objname) {                                          // objeto = entrada de memoria compartida
		uint64_t moff; memcpy(&moff, m + 76, 8);
		char path[128]; me_path(path, sizeof path, objname);
		int fd = open(path, O_RDWR | O_CLOEXEC);
		if (fd < 0) { kr = KERN_INVALID_ARG; goto done; }
		uint64_t len = round_up(size);
		void* p = mmap((flags & 1) ? NULL : (void*)addr, len, cur & 7, MAP_SHARED | ((flags & 1) ? 0 : ((flags & 0x4000) ? MAP_FIXED : MAP_FIXED_NOREPLACE)), fd, (off_t)moff);
		close(fd);
		if (p == MAP_FAILED) { kr = KERN_NO_SPACE_; goto done; }
		addr = (uint64_t)p;
	} else {
		int prot = cur & 7;
		uint64_t len = round_up(size);
		void* p;
		if (flags & 1) {                                        // VM_FLAGS_ANYWHERE
			uint64_t align = mask + 1 > PAGE ? mask + 1 : PAGE;
			uint8_t* q = mmap(NULL, len + align, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (q == MAP_FAILED) { kr = KERN_NO_SPACE_; goto done; }
			uint64_t a = ((uint64_t)q + align - 1) & ~(align - 1);
			if (a > (uint64_t)q) munmap(q, a - (uint64_t)q);
			if ((uint64_t)q + len + align > a + len) munmap((void*)(a + len), (uint64_t)q + len + align - (a + len));
			p = (void*)a;
		} else {
			int extra = (flags & 0x4000) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
			p = mmap((void*)addr, len, prot, MAP_PRIVATE | MAP_ANONYMOUS | extra, -1, 0);
			if (p == MAP_FAILED) { kr = KERN_NO_SPACE_; goto done; }
		}
		addr = (uint64_t)p;
	}
done:;
	size_t n = reply_begin(r, req, kr);
	memcpy(r + n, &addr, 8);                                    // address (salida)
	return n + 8;
}

// host_info (id 200): NDR, flavor, capacidad. Solo HOST_BASIC_INFO (1): 12 enteros.
static size_t mig_host_info(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	int32_t flavor, cap;
	memcpy(&flavor, m + 32, 4);
	memcpy(&cap, m + 36, 4);
	if (flavor == 5 && cap >= 8) {                              // HOST_PRIORITY_INFO (valores de osfmk/kern/sched.h)
		int32_t prio[8] = { 80, 80, 64, 31, 0, 0, 0, 79 };
		size_t n = reply_begin(r, req, KERN_SUCCESS_);
		int32_t cnt = 8;
		memcpy(r + n, &cnt, 4);
		memcpy(r + n + 4, prio, sizeof prio);
		return n + 4 + sizeof prio;
	}
	if (flavor != 1 || cap < 12) {
		logf_("    host_info: sabor %d (capacidad %d) sin implementar\n", flavor, cap);
		return reply_begin(r, req, KERN_INVALID_ARG);
	}
	long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	uint64_t mem = (uint64_t)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	int32_t info[12] = {
		(int32_t)ncpu, (int32_t)ncpu,                           // max_cpus, avail_cpus
		(int32_t)(mem > 0x7fffffff ? 0x7fffffff : mem),         // memory_size (32 bits)
		7, 8, 0,                                                // CPU_TYPE_X86, CPU_SUBTYPE_X86_64_H, threadtype
		(int32_t)(ncpu > 1 ? ncpu / 2 : 1), (int32_t)(ncpu > 1 ? ncpu / 2 : 1),   // physical_cpu(_max)
		(int32_t)ncpu, (int32_t)ncpu,                           // logical_cpu(_max)
		0, 0,                                                   // max_mem (64 bits), se rellena abajo
	};
	memcpy(&info[10], &mem, 8);
	size_t n = reply_begin(r, req, KERN_SUCCESS_);
	int32_t outcnt = 12;
	memcpy(r + n, &outcnt, 4);
	memcpy(r + n + 4, info, sizeof info);
	return n + 4 + sizeof info;
}

// host_get_clock_service (id 206): NDR + clock_id. La respuesta es un mensaje complejo con un descriptor de puerto
// (sin NDR ni código de retorno): cabecera (24) + cuerpo con 1 descriptor (4) + descriptor (12) = 40 bytes.
static size_t mig_host_get_clock_service(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	int32_t clock_id;
	memcpy(&clock_id, m + 32, 4);
	struct hdr h = { .bits = 0x80000000u, .size = 40, .remote = 0, .local = 0, .voucher = 0, .id = req->id + 100 };
	memcpy(r, &h, sizeof h);
	uint32_t ndesc = 1;
	memcpy(r + 24, &ndesc, 4);
	uint32_t name = 0x2203 + (uint32_t)clock_id * 0x100;       // nombre de puerto ficticio y estable por reloj
	uint8_t desc[12] = { 0 };
	memcpy(desc, &name, 4);
	desc[10] = 17;                                              // MACH_MSG_TYPE_PORT_SEND
	desc[11] = 0;                                               // MACH_MSG_PORT_DESCRIPTOR
	memcpy(r + 28, desc, 12);
	return 40;
}

// Asignador de nombres de puerto: en Mach un nombre es (índice << 8 | generación); aquí solo importa que sean únicos.

// Respuesta compleja con un único descriptor de puerto: cabecera (24) + cuerpo (4) + descriptor (12) = 40 bytes.
static size_t reply_port(uint8_t* r, const struct hdr* req, uint32_t name, uint8_t disposition) {
	struct hdr h = { .bits = 0x80000000u, .size = 40, .remote = 0, .local = 0, .voucher = 0, .id = req->id + 100 };
	memcpy(r, &h, sizeof h);
	uint32_t ndesc = 1;
	memcpy(r + 24, &ndesc, 4);
	uint8_t desc[12] = { 0 };
	memcpy(desc, &name, 4);
	desc[10] = disposition;                                     // p. ej. 17 = MACH_MSG_TYPE_PORT_SEND
	memcpy(r + 28, desc, 12);
	return 40;
}

// semaphore_create (id 3418): NDR, política, valor inicial. Devuelve un puerto de semáforo.
static size_t mig_semaphore_create(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	int32_t policy, value;
	memcpy(&policy, m + 32, 4);
	memcpy(&value, m + 36, 4);
	if (trace_all) logf_("    semaphore_create(política=%d, valor=%d)\n", policy, value);
	return reply_port(r, req, sem_create(value), 17);
}

// task_restartable_ranges_register (id 8000, subsistema task_restartable): libsystem registra rangos de código
// "reiniciables" para sus colas sin bloqueo. Es solo una optimización del kernel; se acepta sin hacer nada.
static size_t mig_task_restartable_register(const struct hdr* req, uint8_t* r) { return reply_begin(r, req, KERN_SUCCESS_); }

// task_get_special_port (id 3409): NDR + qué puerto. No hay launchd ni bootstrap: se devuelve el puerto nulo.
static size_t mig_task_get_special_port(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	int32_t which;
	memcpy(&which, m + 32, 4);
	if (trace_all) logf_("    task_get_special_port(%d)\n", which);
	return reply_port(r, req, special_port_get(which), 17);
}

// task_set_special_port (id 3410): descriptor de puerto + NDR + qué puerto. Se acepta sin efecto.
static size_t mig_task_set_special_port(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	uint32_t name, which;
	memcpy(&name, m + 28, 4);                                   // descriptor de puerto: nombre en +28
	memcpy(&which, m + 48, 4);                                  // cabecera 24 + cuerpo 4 + descriptor 12 + NDR 8
	special_port_set((int)which, name);
	if (trace_all) logf_("    task_set_special_port(%u) = 0x%x\n", which, name);
	return reply_begin(r, req, KERN_SUCCESS_);
}

// task_info (id 3405): NDR, sabor, capacidad (en enteros). Sabores soportados: 15 (TASK_AUDIT_TOKEN).
static size_t mig_task_info(const struct hdr* req, const uint8_t* m, uint8_t* r) {
	int32_t flavor, cap;
	memcpy(&flavor, m + 32, 4);
	memcpy(&cap, m + 36, 4);
	if (flavor == 15 && cap >= 8) {                             // audit_token_t: 8 enteros
		uint32_t tok[8] = { (uint32_t)-1, geteuid(), getegid(), getuid(), getgid(), (uint32_t)getpid(), 0, 1 };
		size_t n = reply_begin(r, req, KERN_SUCCESS_);
		int32_t cnt = 8;
		memcpy(r + n, &cnt, 4);
		memcpy(r + n + 4, tok, sizeof tok);
		return n + 4 + sizeof tok;
	}
	logf_("    task_info: sabor %d (capacidad %d) sin implementar\n", flavor, cap);
	return reply_begin(r, req, KERN_INVALID_ARG);
}

// clock_get_time (id 1000, clock.defs): devuelve mach_timespec_t {u32 segundos, i32 nanosegundos}.
static size_t mig_clock_get_time(const struct hdr* req, uint8_t* r) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	size_t n = reply_begin(r, req, KERN_SUCCESS_);
	uint32_t v[2] = { (uint32_t)ts.tv_sec, (uint32_t)ts.tv_nsec };
	memcpy(r + n, v, 8);
	return n + 8;
}

// host_get_exception_ports (id 415): no hay manejadores de excepciones registrados -> 0 entradas. El stub de
// libsystem_kernel exige una respuesta compleja con SIEMPRE 32 descriptores de puerto (los no usados, nulos):
// cabecera(24) + nº de descriptores=32 (4) + 32*12 descriptores + NDR(8) + masksCnt=0 (los tres arrays comparten el contador): 424 bytes.
static size_t mig_host_get_exception_ports(const struct hdr* req, uint8_t* r) {
	size_t n = 24 + 4 + 32 * 12 + 8 + 4;
	struct hdr h = { .bits = 0x80000000u, .size = (uint32_t)n, .id = req->id + 100 };
	memset(r, 0, n);
	memcpy(r, &h, sizeof h);
	uint32_t cnt = 32;
	memcpy(r + 24, &cnt, 4);
	static const uint8_t ndr[8] = { 0, 0, 0, 0, 1, 0, 0, 0 };
	memcpy(r + 28 + 32 * 12, ndr, 8);
	return n;
}

// mach_ports_lookup3 (id 3404): puertos registrados por el padre con mach_ports_register. Respuesta compleja con
// exactamente 3 descriptores de puerto (cabecera 24 + cuenta 4 + 3*12 = 64 bytes), sin NDR ni retcode.
static size_t mig_mach_ports_lookup(const struct hdr* req, uint8_t* r) {
	uint32_t ports[3] = { special_port_get(4), 0, 0 };
	struct hdr h = { .bits = 0x80000000u, .size = 64, .id = req->id + 100 };
	memset(r, 0, 64);
	memcpy(r, &h, sizeof h);
	uint32_t three = 3;
	memcpy(r + 24, &three, 4);
	for (int i = 0; i < 3; i++) {
		memcpy(r + 28 + i * 12, &ports[i], 4);
		r[28 + i * 12 + 10] = 17;                      // disposición: MACH_MSG_TYPE_PORT_SEND; el tipo (byte 11) es 0 = descriptor de puerto
	}
	return 64;
}

// ---------------------------------------------------------------- mach_msg2
// Recepción desde un puerto de usuario: saca el mensaje, ajusta la cabecera como lo hace el kernel (el puerto de
// destino pasa a ser "local" y el de respuesta "remoto", con las disposiciones convertidas) y añade el trailer pedido.
static uint32_t rx_disp(uint32_t tx) {
	switch (tx) {
	case 17: case 19: case 20: return 17;        // MOVE_SEND / COPY_SEND / MAKE_SEND -> PORT_SEND
	case 18: case 21: return 18;                 // MOVE_SEND_ONCE / MAKE_SEND_ONCE -> PORT_SEND_ONCE
	default: return tx;
	}
}
// Recibe un mensaje de `rcv_name` en `buf` (capacidad `cap`) con el trailer que piden las opciones (bits 24-27).
// Devuelve 0 o un código mach_msg; *total = bytes escritos (mensaje + trailer).
long mach_rx_message(uint32_t rcv_name, int timeout_ms, uint64_t options, uint64_t buf, uint32_t cap, uint32_t* total) {
	uint32_t elems = (uint32_t)(options >> 24) & 0xf, tsize = elems == 0 ? 8 : elems == 1 ? 12 : elems == 2 ? 20 : elems == 3 ? 52 : 68;
	uint8_t* m; uint32_t size, snd[3] = { 0, 0, 0 };
	int large = (options & 0x4) != 0;                         // MACH_RCV_LARGE
	int r = port_receive(rcv_name, timeout_ms, &m, &size, snd, cap > tsize ? cap - tsize : 1, large);
	if (r == 0x10004004 && large) {                           // el mensaje sigue en la cola; el receptor lee el tamaño de la cabecera
		struct hdr hh; memcpy(&hh, m, sizeof hh);
		safe_write(buf, m, sizeof hh < size ? sizeof hh : size);
		if (trace_all) logf_("    mach_msg: 0x%x demasiado grande (%u bytes, cabía %u): RCV_LARGE\n", rcv_name, size, cap);
		free(m);
		return r;
	}
	if (r) { if (r != 0x10004003) logf_("    mach_msg: <%d> recepción en 0x%x falló: 0x%x\n", (int)getpid(), rcv_name, r); return r; }
	struct hdr h;
	memcpy(&h, m, sizeof h);
	uint32_t txr = h.bits & 0xff, txl = (h.bits >> 8) & 0xff;
	uint32_t nb = (h.bits & ~0x1f1fu & ~0xffu) | (txl ? rx_disp(txl) : 0) | ((txr ? 16u : 0) << 8);
	uint32_t remote = h.local, local = h.remote;
	h.bits = nb; h.remote = remote; h.local = local;
	memcpy(m, &h, sizeof h);
	if (size >= 28 && (m[3] & 0x80)) {                        // complejo: el receptor ve los derechos de los descriptores ya convertidos
		uint32_t dc, off = 28;
		memcpy(&dc, m + 24, 4);
		for (uint32_t i = 0; i < dc && off + 12 <= size; i++) {
			uint8_t type = m[off + 11];
			if (trace_all && type == 0) { uint32_t nm; memcpy(&nm, m + off, 4); logf_("    mach_msg: <%d> descriptor de puerto 0x%x disposición %u\n", (int)getpid(), nm, m[off + 10]); }
			if (type == 0 && m[off + 10] == 16) { uint32_t nm; memcpy(&nm, m + off, 4); port_move_receive(nm); }   // MOVE_RECEIVE: el receptor pasa a ser dueño
			if (type == 0 || type == 2) m[off + 10] = (uint8_t)rx_disp(m[off + 10]);       // puerto / puertos OOL: disposición
			off += (type == 0) ? 12 : 16;
		}
	}
	uint8_t tr[68] = { 0 };
	uint32_t seq = 0, uid = snd[1], gid = snd[2], at[8] = { (uint32_t)-1, snd[1], snd[2], snd[1], snd[2], snd[0], 0, 1 };
	memcpy(tr + 4, &tsize, 4);
	if (tsize >= 12) memcpy(tr + 8, &seq, 4);
	if (tsize >= 20) { memcpy(tr + 12, &uid, 4); memcpy(tr + 16, &gid, 4); }
	if (tsize >= 52) memcpy(tr + 20, at, 32);
	long res = 0;
	if (size + tsize > cap) {                                 // sin RCV_LARGE: se entrega truncado y se descarta el resto
		uint32_t fit = cap > 24 ? cap - 24 : 0;
		safe_write(buf, m, cap < size ? cap : size);
		(void)fit;
		res = 0x10004004;
	}
	else if (safe_write(buf, m, size) != (ssize_t)size || safe_write(buf + size, tr, tsize) != (ssize_t)tsize) res = 0x10004003;
	else if (total) *total = size + tsize;
	if (trace_all) logf_("    mach_msg: recibe en 0x%x id=%d (%u bytes) -> 0x%lx\n", rcv_name, h.id, size, res);
	free(m);
	return res;
}

static long user_receive(struct ctx* c, uint64_t options, uint64_t buf, uint32_t rcv_name, uint32_t rcvsize) {
	int timeout = (options & 0x100) ? (int)ctx_arg(c, 7) : -1;
	if (trace_all && timeout < 0 && getenv("TAHOE_STACKS")) diag_crash(c->uc);   // quién se bloquea esperando
	return mach_rx_message(rcv_name, timeout, options, buf, rcvsize, NULL);
}

static long mach_msg2(struct ctx* c) {
	uint64_t options = c->a[1];
	uint64_t buf = c->a[0];
	uint32_t ssize = (uint32_t)(c->a[2] >> 32);
	uint32_t rcvsize = (uint32_t)ctx_arg(c, 6);

	static __thread uint8_t reqbuf[512 * 1024];     // los mensajes entre procesos (listas de servicios...) pueden ser grandes
	uint8_t* req = reqbuf;
	uint8_t rep[1024];
	uint32_t rcv_name = (uint32_t)(c->a[5] >> 32);
	if (!(options & 1) && (options & 2)) return user_receive(c, options, buf, rcv_name, rcvsize);
	if (ssize < sizeof(struct hdr) || ssize > sizeof reqbuf || safe_read(buf, req, ssize) != (ssize_t)ssize) {
		logf_("    mach_msg2: mensaje ilegible o fuera de tamaño (%u bytes)\n", ssize);
		return 0x10000003;                                      // MACH_SEND_INVALID_DATA
	}
	struct hdr h;
	memcpy(&h, req, sizeof h);
	// La cabecera de verdad viaja en registros (bits/tamaño, destino/local, voucher/id). Con SEND_KOBJECT_CALL el
	// búfer la repite; en mensajes a puertos normales el búfer puede no contenerla.
	uint64_t bs = c->a[2], rl = c->a[3], vi = c->a[4];
	h.bits = (uint32_t)bs; h.size = (uint32_t)(bs >> 32);
	h.remote = (uint32_t)rl; h.local = (uint32_t)(rl >> 32);
	h.voucher = (uint32_t)vi; h.id = (int32_t)(vi >> 32);
	int kobject = (options & 0x200000000ULL) != 0;
	if (!kobject && port_exists(h.remote)) {                    // envío a un puerto de usuario: se encola tal cual
		memcpy(req, &h, sizeof h);
		port_send(h.remote, req, ssize);
		if (trace_all) logf_("    mach_msg2: envía a 0x%x (respuesta 0x%x) id=%d (%u bytes) bits=0x%x opciones=0x%lx\n", h.remote, h.local, h.id, ssize, h.bits, options);
		return (options & 2) ? user_receive(c, options, buf, rcv_name, rcvsize) : MACH_MSG_SUCCESS;
	}
	size_t n;
	switch (h.id) {
	case 3420: case 3218: n = reply_begin(rep, &h, KERN_SUCCESS_); break;   // task_policy_set / mach_port_set_attributes: sin efecto
	case 4811: n = mig_mach_vm_map(&h, req, rep); break;
	case 4817: n = mig_make_memory_entry(&h, req, rep); break;
	case 4807: {                                                  // mach_vm_copy(task, src, size, dst): el destino ya está asignado
		uint64_t src, size, dst; memcpy(&src, req + 32, 8); memcpy(&size, req + 40, 8); memcpy(&dst, req + 48, 8);
		memmove((void*)dst, (void*)src, size);
		n = reply_begin(rep, &h, KERN_SUCCESS_);
		break;
	}
	case 4808: {                                                  // mach_vm_read_overwrite(task, addr, size, data) -> outsize
		uint64_t src, size, dst; memcpy(&src, req + 32, 8); memcpy(&size, req + 40, 8); memcpy(&dst, req + 48, 8);
		memmove((void*)dst, (void*)src, size);
		n = reply_begin(rep, &h, KERN_SUCCESS_); memcpy(rep + n, &size, 8); n += 8;
		break;
	}
	case 4803: case 4809: case 4810: n = reply_begin(rep, &h, KERN_SUCCESS_); break;   // inherit / msync / behavior_set: sin efecto
	case 200:  n = mig_host_info(&h, req, rep); break;
	case 206:  n = mig_host_get_clock_service(&h, req, rep); break;
	case 222: n = reply_port(rep, &h, alloc_port(), 17); break;   // host_create_mach_voucher: puerto de voucher ficticio
	case 225: n = reply_begin(rep, &h, KERN_SUCCESS_); break;     // (host, un entero): se acepta sin efecto
	case 413: n = reply_begin(rep, &h, KERN_SUCCESS_); break;   // host_set_special_port: sin efecto
	case 205: n = reply_port(rep, &h, alloc_port(), 17); break;  // host_get_io_main
	case 412: n = reply_begin(rep, &h, KERN_INVALID_ARG); break;   // host_get_special_port: sin puertos privilegiados (libdispatch usa mach_host_self)
	case 415: n = mig_host_get_exception_ports(&h, rep); break;
	case 414: case 416: n = reply_begin(rep, &h, KERN_SUCCESS_); break;   // set / swap exception ports: sin efecto
	case 1000: n = mig_clock_get_time(&h, rep); break;
	case 3418: n = mig_semaphore_create(&h, req, rep); break;
	case 3404: n = mig_mach_ports_lookup(&h, rep); break;
	case 3403: {                                                  // mach_ports_register: 3 descriptores de puerto
		uint32_t cnt, ports[3] = { 0, 0, 0 };
		memcpy(&cnt, req + 24, 4);
		for (uint32_t i = 0; i < cnt && i < 3; i++) memcpy(&ports[i], req + 28 + i * 12, 4);
		registered_ports_set(ports, (int)(cnt < 3 ? cnt : 3));
		if (trace_all) logf_("    mach_ports_register: 0x%x 0x%x 0x%x\n", ports[0], ports[1], ports[2]);
		n = reply_begin(rep, &h, KERN_SUCCESS_);
		break;
	}     // mach_ports_register: sin efecto
	case 8000: case 8001: n = mig_task_restartable_register(&h, rep); break;   // register y synchronize
	case 3409: n = mig_task_get_special_port(&h, req, rep); break;
	case 3410: n = mig_task_set_special_port(&h, req, rep); break;
	case 3405: n = mig_task_info(&h, req, rep); break;
	default:
		if (h.id >= 2800 && h.id < 2900) {                          // IOKit (device.defs): sin registro de E/S todavía -> kIOReturnNotFound
			{ int hd; size_t r2 = mig_iokit(&h, req, rep, &hd); if (hd) { n = r2; break; } }
			{ char s[96] = ""; size_t k = 0; for (uint32_t i = 32; i < ssize && k < sizeof s - 1; i++) { uint8_t ch = req[i]; if (ch >= 32 && ch < 127) s[k++] = (char)ch; else if (k && s[k - 1] != 0x7c) s[k++] = 0x7c; } s[k] = 0; logf_("    iokit <%d> id=%d (%u bytes) \"%s\" -> kIOReturnNotFound\n", (int)getpid(), h.id, ssize, s); }
			n = reply_begin(rep, &h, (int32_t)0xe00002f0);
			break;
		}
		logf_("    mach_msg2: opciones=0x%lx %s id=%d destino=0x%x local=0x%x (%u bytes, bits=0x%x) sin implementar -> MIG_BAD_ID\n",
		      options, kobject ? "kobject" : "puerto", h.id, h.remote, h.local, ssize, h.bits);
		hexdump(req, ssize < 128 ? ssize : 128);
		n = reply_begin(rep, &h, MIG_BAD_ID);
		break;
	}
	reply_end(rep, n);
	if (trace_all) logf_("    mach_msg2: id=%d -> respuesta id=%d (%zu bytes)\n", h.id, h.id + 100, n);

	if (!(options & 2)) return MACH_MSG_SUCCESS;               // solo envío: no hay respuesta que entregar
	memset(rep + n, 0, 8);                                      // trailer: tipo 0, tamaño 8
	uint32_t tsize = 8;
	memcpy(rep + n + 4, &tsize, 4);
	if (kobject && rcvsize < 16) {
		// En algunas ramas (reinicialización tras fork) el tamaño de recepción de la pila no es fiable. Un cliente MIG
		// reserva un búfer del tamaño de la respuesta + trailer, y nuestras respuestas tienen el tamaño real.
		if (trace_all) logf_("    mach_msg2: rcv_size=%u no fiable; se usa el tamaño de la respuesta (%zu+8)\n", rcvsize, n);
		rcvsize = (uint32_t)(n + 8);
	}
	if (n + 8 > rcvsize) {
		logf_("    mach_msg2: la respuesta (%zu+8) no cabe en rcv_size=%u (id=%d destino=0x%x)\n", n, rcvsize, h.id, h.remote);
		return MACH_RCV_TOO_LARGE;
	}
	if (safe_write(buf, rep, n + 8) != (ssize_t)(n + 8)) return 0x10004003;   // MACH_RCV_INVALID_DATA
	return MACH_MSG_SUCCESS;
}

void emu_mach_init(void) { reg_mach(47, mach_msg2); }
