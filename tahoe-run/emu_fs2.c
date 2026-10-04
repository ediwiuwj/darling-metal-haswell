// Llamadas de sistema de archivos que modifican el árbol (mkdir, unlink, rename...) y varias de E/S sencillas.
// Las rutas se resuelven SIEMPRE dentro de TAHOE_ROOT (nunca se toca el árbol real del host).
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include "tahoe.h"

static long err(void) { return -darwin_errno(errno); }
#define RET(r) do { long r_ = (r); return r_ < 0 ? err() : r_; } while (0)

// Ruta del programa -> ruta bajo TAHOE_ROOT. Devuelve 0 o un errno negativo.
static long rpath(uint64_t addr, char* out, size_t cap) {
	char g[4096];
	if (safe_string(addr, g, sizeof g) != 0) return -D_EFAULT;
	if (tahoe_root && g[0] == '/') snprintf(out, cap, "%s%s", tahoe_root, g);
	else snprintf(out, cap, "%s", g);
	return 0;
}
#define PATH1(var, argi) char var[4400]; { long e_ = rpath(c->a[argi], var, sizeof var); if (e_) return e_; }

static long bsd_mkdir(struct ctx* c)  { PATH1(p, 0); RET(mkdir(p, (mode_t)c->a[1])); }
static long bsd_rmdir(struct ctx* c)  { PATH1(p, 0); RET(rmdir(p)); }
static long bsd_unlink(struct ctx* c) { PATH1(p, 0); RET(unlink(p)); }
static long bsd_chmod(struct ctx* c)  { PATH1(p, 0); RET(chmod(p, (mode_t)c->a[1])); }
static long bsd_chown(struct ctx* c)  { PATH1(p, 0); RET(chown(p, (uid_t)c->a[1], (gid_t)c->a[2])); }
static long bsd_lchown(struct ctx* c) { PATH1(p, 0); RET(lchown(p, (uid_t)c->a[1], (gid_t)c->a[2])); }
static long bsd_truncate(struct ctx* c) { PATH1(p, 0); RET(truncate(p, (off_t)c->a[1])); }
static long bsd_mkfifo(struct ctx* c) { PATH1(p, 0); RET(mkfifo(p, (mode_t)c->a[1])); }
static long bsd_rename(struct ctx* c) { PATH1(a, 0); PATH1(b, 1); RET(rename(a, b)); }
static long bsd_link(struct ctx* c)   { PATH1(a, 0); PATH1(b, 1); RET(link(a, b)); }
static long bsd_symlink(struct ctx* c) {      // el destino del enlace se guarda tal cual; solo la ruta del enlace va a la raíz
	char tgt[4096];
	if (safe_string(c->a[0], tgt, sizeof tgt) != 0) return -D_EFAULT;
	PATH1(l, 1);
	RET(symlink(tgt, l));
}
static long bsd_fchmod(struct ctx* c) { RET(fchmod((int)c->a[0], (mode_t)c->a[1])); }
static long bsd_fchown(struct ctx* c) { RET(fchown((int)c->a[0], (uid_t)c->a[1], (gid_t)c->a[2])); }
static long bsd_ftruncate(struct ctx* c) { RET(ftruncate((int)c->a[0], (off_t)c->a[1])); }
static long bsd_fsync(struct ctx* c)  { RET(fsync((int)c->a[0])); }
static long bsd_flock(struct ctx* c) {        // LOCK_SH 1, LOCK_EX 2, LOCK_NB 4, LOCK_UN 8 en Darwin
	int op = (int)c->a[1], l = 0;
	if (op & 1) l |= LOCK_SH;
	if (op & 2) l |= LOCK_EX;
	if (op & 4) l |= LOCK_NB;
	if (op & 8) l |= LOCK_UN;
	RET(flock((int)c->a[0], l));
}
static long bsd_getdtablesize(struct ctx* c) { (void)c; return 10240; }
static long bsd_readv(struct ctx* c)  { RET(readv((int)c->a[0], (const struct iovec*)c->a[1], (int)c->a[2])); }
static long bsd_writev(struct ctx* c) { RET(writev((int)c->a[0], (const struct iovec*)c->a[1], (int)c->a[2])); }
static long bsd_utimes(struct ctx* c) {       // struct timeval de Darwin: {i64 segundos, i32 microsegundos, pad}
	PATH1(p, 0);
	struct timespec ts[2];
	if (c->a[1]) {
		uint8_t tv[32];
		if (safe_read(c->a[1], tv, 32) != 32) return -D_EFAULT;
		for (int i = 0; i < 2; i++) {
			int64_t s; int32_t us;
			memcpy(&s, tv + i * 16, 8); memcpy(&us, tv + i * 16 + 8, 4);
			ts[i].tv_sec = s; ts[i].tv_nsec = us * 1000L;
		}
		RET(utimensat(AT_FDCWD, p, ts, 0));
	}
	RET(utimensat(AT_FDCWD, p, NULL, 0));
}
static long bsd_gettid(struct ctx* c) { (void)c; return -D_EINVAL; }   // sin uid/gid por hilo
static long bsd_getgroups(struct ctx* c) {
	int n = (int)c->a[0];
	gid_t g[64];
	int r = getgroups(n > 64 ? 64 : n, n ? g : NULL);
	if (r < 0) return err();
	if (n && safe_write(c->a[1], g, r * 4) != (ssize_t)(r * 4)) return -D_EFAULT;
	return r;
}
static long bsd_ok(struct ctx* c) { (void)c; return 0; }                // setgroups/setuid/setgid...: ya somos el usuario efectivo
// select(nfds, readfds, writefds, exceptfds, timeval*)
static long bsd_select(struct ctx* c) {
	int n = (int)c->a[0];
	if (n < 0 || n > 1024) return -D_EINVAL;
	size_t bytes = ((size_t)n + 7) / 8;
	fd_set sets[3];
	int have[3];
	FD_ZERO(&sets[0]); FD_ZERO(&sets[1]); FD_ZERO(&sets[2]);
	for (int i = 0; i < 3; i++) {
		have[i] = c->a[1 + i] != 0;
		if (have[i] && bytes && safe_read(c->a[1 + i], &sets[i], bytes) != (ssize_t)bytes) return -D_EFAULT;
	}
	struct timeval tv, *tp = NULL;
	if (c->a[4]) {
		uint8_t t[16];
		if (safe_read(c->a[4], t, 16) != 16) return -D_EFAULT;
		int64_t s; int32_t us;
		memcpy(&s, t, 8); memcpy(&us, t + 8, 4);
		tv.tv_sec = s; tv.tv_usec = us; tp = &tv;
	}
	int r = select(n, have[0] ? &sets[0] : NULL, have[1] ? &sets[1] : NULL, have[2] ? &sets[2] : NULL, tp);
	if (r < 0) return err();
	for (int i = 0; i < 3; i++)
		if (have[i] && bytes && safe_write(c->a[1 + i], &sets[i], bytes) != (ssize_t)bytes) return -D_EFAULT;
	return r;
}

void emu_fs2_init(void) {
	reg_bsd(136, bsd_mkdir); reg_bsd(137, bsd_rmdir); reg_bsd(10, bsd_unlink); reg_bsd(15, bsd_chmod);
	reg_bsd(16, bsd_chown); reg_bsd(254, bsd_lchown); reg_bsd(200, bsd_truncate); reg_bsd(132, bsd_mkfifo);
	reg_bsd(128, bsd_rename); reg_bsd(9, bsd_link); reg_bsd(57, bsd_symlink);
	reg_bsd(124, bsd_fchmod); reg_bsd(123, bsd_fchown); reg_bsd(201, bsd_ftruncate); reg_bsd(95, bsd_fsync);
	reg_bsd(131, bsd_flock); reg_bsd(89, bsd_getdtablesize); reg_bsd(120, bsd_readv); reg_bsd(121, bsd_writev);
	reg_bsd(138, bsd_utimes); reg_bsd(286, bsd_gettid); reg_bsd(79, bsd_getgroups); reg_bsd(93, bsd_select);
	reg_bsd(80, bsd_ok); reg_bsd(23, bsd_ok); reg_bsd(181, bsd_ok); reg_bsd(182, bsd_ok); reg_bsd(183, bsd_ok);
}
