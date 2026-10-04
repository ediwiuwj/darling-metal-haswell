// sysctl de macOS 26 sobre Linux.
//
// libSystem usa sysctlbyname(): primero traduce el nombre a un identificador con sysctl({0, 3}) (name2oid)
// y luego consulta ese identificador. Aquí hay una tabla de valores conocidos; lo que no esté se registra
// y devuelve ENOENT, de modo que cada ejecución indica qué falta.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/sysinfo.h>

#include "tahoe.h"

enum kind { K_INT, K_QUAD, K_STR, K_BOOT };
struct entry {
	const char* name;
	int mib[2];
	enum kind kind;
	long long ival;
	const char* sval;
};

#define CTL_KERN 1
#define CTL_HW 6
// Identificadores reales de Darwin cuando existen; el resto (nombres dinámicos) usan 0x7000 + n.
static struct entry table[] = {
	{ "kern.ostype", { CTL_KERN, 1 }, K_STR, 0, "Darwin" },
	{ "kern.osrelease", { CTL_KERN, 2 }, K_STR, 0, "25.6.0" },
	{ "kern.version", { CTL_KERN, 4 }, K_STR, 0, "Darwin Kernel Version 25.6.0: tahoe-run; root:xnu-12377.121.6~1/RELEASE_X86_64" },
	{ "kern.maxproc", { CTL_KERN, 6 }, K_INT, 4000, NULL },
	{ "kern.maxfiles", { CTL_KERN, 7 }, K_INT, 245760, NULL },
	{ "kern.argmax", { CTL_KERN, 8 }, K_INT, 1048576, NULL },
	{ "kern.hostname", { CTL_KERN, 10 }, K_STR, 0, "localhost" },
	{ "kern.maxfilesperproc", { CTL_KERN, 29 }, K_INT, 122880, NULL },
	{ "kern.usrstack64", { CTL_KERN, 59 }, K_QUAD, (long long)STACK_TOP, NULL },
	{ "kern.osversion", { CTL_KERN, 65 }, K_STR, 0, "25G83" },
	{ "kern.boottime", { CTL_KERN, 21 }, K_BOOT, 0, NULL },
	{ "kern.bootargs", { CTL_KERN, 0x7000 }, K_STR, 0, "" },
	{ "kern.osproductversion", { CTL_KERN, 0x7001 }, K_STR, 0, "26.6.2" },
	{ "kern.osproductversionextra", { CTL_KERN, 0x7002 }, K_STR, 0, "" },
	{ "kern.secure_kernel", { CTL_KERN, 0x7003 }, K_INT, 0, NULL },
	{ "kern.safeboot", { CTL_KERN, 0x7004 }, K_INT, 0, NULL },
	{ "kern.osvariant_status", { CTL_KERN, 0x7005 }, K_QUAD, 0, NULL },
	{ "kern.wq_limit_cooperative_threads", { CTL_KERN, 0x7006 }, K_INT, 4, NULL },
	{ "kern.wq_max_threads", { CTL_KERN, 0x7007 }, K_INT, 512, NULL },
	{ "kern.wq_stalled_window_usecs", { CTL_KERN, 0x7008 }, K_INT, 200, NULL },
	{ "kern.wq_reduce_pool_window_usecs", { CTL_KERN, 0x7009 }, K_INT, 5000000, NULL },
	{ "kern.wq_max_timer_interval_usecs", { CTL_KERN, 0x700a }, K_INT, 50000, NULL },
	{ "security.mac.lockdown_mode_state", { 200, 1 }, K_INT, 0, NULL },
	{ "hw.machine", { CTL_HW, 1 }, K_STR, 0, "x86_64" },
	{ "hw.model", { CTL_HW, 2 }, K_STR, 0, "MacBookPro16,1" },
	{ "hw.ncpu", { CTL_HW, 3 }, K_INT, -1, NULL },            // -1: se rellena al iniciar
	{ "hw.byteorder", { CTL_HW, 4 }, K_INT, 1234, NULL },
	{ "hw.physmem", { CTL_HW, 5 }, K_INT, -2, NULL },
	{ "hw.pagesize", { CTL_HW, 7 }, K_INT, 4096, NULL },
	{ "hw.cachelinesize", { CTL_HW, 16 }, K_INT, 64, NULL },
	{ "hw.memsize", { CTL_HW, 24 }, K_QUAD, -2, NULL },
	{ "hw.availcpu", { CTL_HW, 25 }, K_INT, -1, NULL },
	{ "hw.activecpu", { CTL_HW, 0x7100 }, K_INT, -1, NULL },
	{ "hw.logicalcpu", { CTL_HW, 0x7101 }, K_INT, -1, NULL },
	{ "hw.logicalcpu_max", { CTL_HW, 0x7102 }, K_INT, -1, NULL },
	{ "hw.physicalcpu", { CTL_HW, 0x7103 }, K_INT, -3, NULL },
	{ "hw.physicalcpu_max", { CTL_HW, 0x7104 }, K_INT, -3, NULL },
	{ "hw.cpu64bit_capable", { CTL_HW, 0x7105 }, K_INT, 1, NULL },
	{ "hw.cputype", { CTL_HW, 0x7106 }, K_INT, 7, NULL },       // CPU_TYPE_X86
	{ "hw.pagesize32", { CTL_HW, 0x7107 }, K_INT, 4096, NULL },
	{ "hw.optional.x86_64", { CTL_HW, 0x7108 }, K_INT, 1, NULL },
	{ "hw.optional.avx1_0", { CTL_HW, 0x7109 }, K_INT, 1, NULL },
	{ "hw.optional.avx2_0", { CTL_HW, 0x710a }, K_INT, 1, NULL },
	{ "hw.optional.sse4_2", { CTL_HW, 0x710b }, K_INT, 1, NULL },
};
#define NENT (sizeof table / sizeof table[0])

void emu_sysctl_init(void) {
	long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	long long mem = (long long)sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE);
	for (size_t i = 0; i < NENT; i++) {
		if (table[i].ival == -1) table[i].ival = ncpu;
		else if (table[i].ival == -2) table[i].ival = mem;
		else if (table[i].ival == -3) table[i].ival = ncpu > 1 ? ncpu / 2 : 1;
	}
	extern long bsd_sysctl(struct ctx*);
	reg_bsd(202, bsd_sysctl);
}

// Escribe el valor en el búfer del programa como lo hace sysctl(2): oldlenp entra con la capacidad y sale
// con el tamaño real; si el búfer no basta se devuelve ENOMEM.
static long sc_out(struct ctx* c, const void* data, size_t len) {
	uint64_t oldp = c->a[2], oldlenp = c->a[3], cap = 0;
	if (oldlenp && safe_read(oldlenp, &cap, 8) != 8) return -D_EFAULT;
	if (!oldp) {
		if (oldlenp && safe_write(oldlenp, &len, 8) != 8) return -D_EFAULT;
		return 0;
	}
	size_t n = len < cap ? len : cap;
	if (n && safe_write(oldp, data, n) != (ssize_t)n) return -D_EFAULT;
	if (oldlenp) { uint64_t l = len; if (safe_write(oldlenp, &l, 8) != 8) return -D_EFAULT; }
	return n < len ? -D_ENOMEM : 0;
}

long bsd_sysctl(struct ctx* c) {
	int mib[16];
	uint32_t n = (uint32_t)c->a[1];
	if (n == 0 || n > 16 || safe_read(c->a[0], mib, n * 4) != (ssize_t)(n * 4)) return -D_EINVAL;

	if (n == 2 && mib[0] == 0 && mib[1] == 3) {          // name2oid: nombre en newp -> identificador
		char name[256];
		size_t len = c->a[5] < sizeof name - 1 ? c->a[5] : sizeof name - 1;
		if (!c->a[4] || safe_read(c->a[4], name, len) != (ssize_t)len) return -D_EFAULT;
		name[len] = 0;
		for (size_t i = 0; i < NENT; i++)
			if (!strcmp(table[i].name, name)) return sc_out(c, table[i].mib, sizeof table[i].mib);
		if (trace_all || 1) logf_("    sysctl: nombre desconocido \"%s\"\n", name);
		return -D_ENOENT;
	}
	if (n == 2) {
		for (size_t i = 0; i < NENT; i++) {
			if (table[i].mib[0] != mib[0] || table[i].mib[1] != mib[1]) continue;
			const struct entry* e = &table[i];
			if (trace_all) logf_("    sysctl %s\n", e->name);
			switch (e->kind) {
			case K_INT:  { int v = (int)e->ival; return sc_out(c, &v, sizeof v); }
			case K_QUAD: { long long v = e->ival; return sc_out(c, &v, sizeof v); }
			case K_STR:  return sc_out(c, e->sval, strlen(e->sval) + 1);
			case K_BOOT: {
				struct timespec up, now;
				clock_gettime(CLOCK_BOOTTIME, &up);
				clock_gettime(CLOCK_REALTIME, &now);
				long long tv[2] = { now.tv_sec - up.tv_sec, (now.tv_nsec - up.tv_nsec) / 1000 };
				if (tv[1] < 0) { tv[1] += 1000000; tv[0]--; }
				return sc_out(c, tv, 16);
			}
			}
		}
	}
	logf_("    sysctl: identificador desconocido [");
	for (uint32_t i = 0; i < n; i++) logf_("%s%d", i ? "." : "", mib[i]);
	logf_("]\n");
	return -D_ENOENT;
}
