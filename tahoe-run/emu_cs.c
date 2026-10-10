// Firma de código: los derechos (entitlements) de un proceso salen de la firma real de su ejecutable.
//
// En XNU, csops(CS_OPS_ENTITLEMENTS_BLOB / CS_OPS_DER_ENTITLEMENTS_BLOB) copia el blob de derechos de la firma que el
// núcleo validó al cargar el binario. Aquí se lee lo mismo del archivo: el comando LC_CODE_SIGNATURE apunta a un
// "superblob" (big endian) con un índice de ranuras; la 5 son los derechos en XML (0xfade7171) y la 7 en DER
// (0xfade7172). Muchos servicios consultan los derechos de quien les habla (csops_audittoken sobre el pid del cliente).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tahoe.h"

// Ruta del ejecutable de macOS de un proceso: tahoe-run <caché> <dyld> <ejecutable> [args...]
static int exe_host_path(int pid, char* out, size_t cap) {
	char p[64], buf[8192];
	snprintf(p, sizeof p, "/proc/%d/cmdline", pid ? pid : (int)getpid());
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0) return -1;
	buf[n] = 0;
	const char* a = buf; int i = 0;
	while (a < buf + n && i < 3) { a += strlen(a) + 1; i++; }
	if (a >= buf + n || !*a) return -1;
	snprintf(out, cap, "%s", a);
	return 0;
}

static uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint32_t be32(const uint8_t* p) { return ntohl(rd32(p)); }

// Busca en la firma del ejecutable el blob de la ranura indicada. Devuelve malloc() con el blob (cabecera incluida).
static uint8_t* cs_blob(int pid, uint32_t slot, uint32_t* len) {
	char path[4096];
	if (exe_host_path(pid, path, sizeof path) != 0) return NULL;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return NULL;
	uint8_t h[4096];
	uint64_t base = 0;
	if (pread(fd, h, sizeof h, 0) < 32) { close(fd); return NULL; }
	if (be32(h) == 0xcafebabe) {                              // binario universal: rebanada x86_64
		uint32_t nf = be32(h + 4);
		for (uint32_t i = 0; i < nf && 8 + (i + 1) * 20 <= sizeof h; i++)
			if (be32(h + 8 + i * 20) == 0x01000007) { base = be32(h + 8 + i * 20 + 8); break; }
		if (!base || pread(fd, h, sizeof h, (off_t)base) < 32) { close(fd); return NULL; }
	}
	uint8_t* out = NULL;
	if (rd32(h) == 0xfeedfacf) {
		uint32_t ncmds = rd32(h + 16), sizeofcmds = rd32(h + 20);
		uint8_t* lc = malloc(sizeofcmds);
		if (lc && pread(fd, lc, sizeofcmds, (off_t)base + 32) == (ssize_t)sizeofcmds) {
			uint32_t off = 0;
			for (uint32_t i = 0; i < ncmds && off + 8 <= sizeofcmds; i++) {
				uint32_t cmd = rd32(lc + off), cs = rd32(lc + off + 4);
				if (cs < 8) break;
				if (cmd == 0x1d && off + 16 <= sizeofcmds) {          // LC_CODE_SIGNATURE: dataoff, datasize
					uint32_t doff = rd32(lc + off + 8), dsz = rd32(lc + off + 12);
					uint8_t* sb = malloc(dsz);
					if (sb && dsz >= 12 && pread(fd, sb, dsz, (off_t)(base + doff)) == (ssize_t)dsz && be32(sb) == 0xfade0cc0) {
						uint32_t count = be32(sb + 8);
						for (uint32_t k = 0; k < count && 12 + (k + 1) * 8 <= dsz; k++) {
							uint32_t type = be32(sb + 12 + k * 8), bo = be32(sb + 12 + k * 8 + 4);
							if (type != slot || bo + 8 > dsz) continue;
							uint32_t bl = be32(sb + bo + 4);
							if (bl < 8 || bo + bl > dsz) break;
							out = malloc(bl);
							if (out) { memcpy(out, sb + bo, bl); *len = bl; }
							break;
						}
					}
					free(sb);
					break;
				}
				off += cs;
			}
		}
		free(lc);
	}
	close(fd);
	return out;
}

// Como csops_copy_token de XNU: si no cabe, solo la cabecera con la longitud necesaria y ERANGE.
static long copy_token(const uint8_t* blob, uint32_t len, uint64_t uaddr, uint64_t usize) {
	if (usize < 8) return -34;                                   // ERANGE
	if (!blob) { uint8_t z[8] = { 0 }; return safe_write(uaddr, z, 8) == 8 ? 0 : -D_EFAULT; }   // sin derechos
	if (usize < len) {
		uint8_t hdr[8]; memcpy(hdr, blob, 4); uint32_t bl = htonl(len); memcpy(hdr + 4, &bl, 4);
		return safe_write(uaddr, hdr, 8) == 8 ? -34 : -D_EFAULT;
	}
	return safe_write(uaddr, blob, len) == (ssize_t)len ? 0 : -D_EFAULT;
}

// Núcleo común de csops y csops_audittoken. pid 0 = el propio proceso.
static long cs_ops(int pid, int op, uint64_t uaddr, uint64_t usize) {
	switch (op) {
	case 0: {                                                    // CS_OPS_STATUS: sin banderas (como un binario sin restricciones)
		uint32_t zero = 0;
		if (usize < 4) return -D_EINVAL;
		return safe_write(uaddr, &zero, 4) == 4 ? 0 : -D_EFAULT;
	}
	case 7: case 16: {                                           // ENTITLEMENTS_BLOB (XML, ranura 5) / DER_ENTITLEMENTS_BLOB (ranura 7)
		uint32_t len = 0;
		uint8_t* b = cs_blob(pid, op == 7 ? 5 : 7, &len);
		long r = copy_token(b, len, uaddr, usize);
		free(b);
		return r;
	}
	default:
		logf_("    csops: operación %d sin implementar\n", op);
		return -D_EINVAL;
	}
}

static long bsd_csops(struct ctx* c) { return cs_ops((int)c->a[0], (int)c->a[1], c->a[2], c->a[3]); }
// csops_audittoken(pid, operación, búfer, tamaño, token*)
static long bsd_csops_audittoken(struct ctx* c) { return cs_ops((int)c->a[0], (int)c->a[1], c->a[2], c->a[3]); }

void emu_cs_init(void) { reg_bsd(169, bsd_csops); reg_bsd(170, bsd_csops_audittoken); }
