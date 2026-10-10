// Memoria, archivos e identidad: las syscalls BSD de macOS más directas, traducidas a Linux.
//
// Las constantes y el diseño de las estructuras vienen de los encabezados de XNU 12377
// (bsd/sys/mman.h, fcntl.h, stat.h) y se escriben aquí a mano: no se usa código de Darling.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <linux/falloc.h>
#include "tahoe.h"

static long err(void) { return -darwin_errno(errno); }
#define RET(r) do { long r_ = (r); return r_ < 0 ? err() : r_; } while (0)

// Resuelve una ruta del programa: si TAHOE_ROOT existe y contiene el archivo, se usa esa; si no, la del host.
static const char* resolve(const char* guest, char* buf, size_t cap) {
	if (tahoe_root && guest[0] == '/') {
		snprintf(buf, cap, "%s%s", tahoe_root, guest);
		if (access(buf, F_OK) == 0) return buf;
	}
	return guest;
}

// ---------------------------------------------------------------- memoria
static long bsd_munmap(struct ctx* c) { RET(munmap((void*)c->a[0], c->a[1])); }
static long bsd_mprotect(struct ctx* c) { RET(mprotect((void*)c->a[0], c->a[1], (int)c->a[2] & 7)); }
static long bsd_madvise(struct ctx* c) { (void)c; return 0; }   // solo es una pista

static long bsd_mmap(struct ctx* c) {
	uint64_t addr = c->a[0], len = c->a[1], flags = c->a[3], off = c->a[5];
	int prot = (int)c->a[2] & 7, fd = (int)c->a[4], lf = 0;
	if (flags & 0x0001) lf |= MAP_SHARED;
	if (flags & 0x0002) lf |= MAP_PRIVATE;
	if (flags & 0x0010) lf |= MAP_FIXED;
	if (flags & 0x0040) lf |= MAP_NORESERVE;
	if (flags & 0x1000) { lf |= MAP_ANONYMOUS; fd = -1; }          // MAP_ANON; el "fd" puede llevar una etiqueta de VM
	void* p = mmap((void*)addr, len, prot, lf, fd, off);
	if (p == MAP_FAILED) return err();
	return (long)p;
}

// ---------------------------------------------------------------- ficheros
static long bsd_lseek(struct ctx* c) {
	int wh = (int)c->a[2];
	if (wh == 3) wh = SEEK_HOLE; else if (wh == 4) wh = SEEK_DATA;   // Darwin: HOLE=3, DATA=4 (en Linux al revés)
	RET(lseek((int)c->a[0], (off_t)c->a[1], wh));
}
static long bsd_pread(struct ctx* c) { RET(syscall(SYS_pread64, c->a[0], c->a[1], c->a[2], c->a[3])); }
static long bsd_pwrite(struct ctx* c) { RET(syscall(SYS_pwrite64, c->a[0], c->a[1], c->a[2], c->a[3])); }

static long bsd_access(struct ctx* c) {
	char p[4096], b[4200];
	if (safe_string(c->a[0], p, sizeof p) != 0) return -D_EFAULT;
	RET(access(resolve(p, b, sizeof b), (int)c->a[1] & 7));          // R_OK/W_OK/X_OK/F_OK coinciden
}
static long bsd_readlink(struct ctx* c) {
	char p[4096], b[4200], out[4096];
	if (safe_string(c->a[0], p, sizeof p) != 0) return -D_EFAULT;
	ssize_t n = readlink(resolve(p, b, sizeof b), out, c->a[2] < sizeof out ? c->a[2] : sizeof out);
	if (n < 0) return err();
	return safe_write(c->a[1], out, n) == n ? n : -D_EFAULT;
}

// Banderas BSD (st_flags: SF_RESTRICTED, UF_HIDDEN...): Linux no las tiene; se guardan como atributo extendido del archivo.
// Hacen falta porque libsystem comprueba que rootless_mkdir_protected() dejó el directorio protegido.
#include <sys/xattr.h>
uint32_t tahoe_flags_fd(int fd) { uint32_t v = 0; if (fgetxattr(fd, "user.tahoe.flags", &v, 4) != 4) v = 0; return v; }
uint32_t tahoe_flags_path(const char* p) { uint32_t v = 0; if (lgetxattr(p, "user.tahoe.flags", &v, 4) != 4) v = 0; return v; }

// struct stat de Darwin con inodos de 64 bits (144 bytes)
static void put_stat(uint64_t out, const struct stat* s, uint32_t flags) {
	uint8_t d[144];
	memset(d, 0, sizeof d);
#define W(type, off, v) do { type t_ = (type)(v); memcpy(d + (off), &t_, sizeof t_); } while (0)
	W(int32_t, 0, (major(s->st_dev) << 24) | (minor(s->st_dev) & 0xffffff));
	W(uint16_t, 4, s->st_mode);
	W(uint16_t, 6, s->st_nlink);
	W(uint64_t, 8, s->st_ino);
	W(uint32_t, 16, s->st_uid);
	W(uint32_t, 20, s->st_gid);
	W(int32_t, 24, (major(s->st_rdev) << 24) | (minor(s->st_rdev) & 0xffffff));
	W(int64_t, 32, s->st_atim.tv_sec);  W(int64_t, 40, s->st_atim.tv_nsec);
	W(int64_t, 48, s->st_mtim.tv_sec);  W(int64_t, 56, s->st_mtim.tv_nsec);
	W(int64_t, 64, s->st_ctim.tv_sec);  W(int64_t, 72, s->st_ctim.tv_nsec);
	W(int64_t, 80, s->st_ctim.tv_sec);  W(int64_t, 88, s->st_ctim.tv_nsec);   // birthtime: se usa ctime
	W(int64_t, 96, s->st_size);
	W(int64_t, 104, s->st_blocks);
	W(int32_t, 112, s->st_blksize);
	W(uint32_t, 116, flags);
#undef W
	safe_write(out, d, sizeof d);
}
static long do_stat(struct ctx* c, int follow) {
	char p[4096], b[4200];
	struct stat s;
	if (safe_string(c->a[0], p, sizeof p) != 0) return -D_EFAULT;
	const char* path = resolve(p, b, sizeof b);
	if ((follow ? stat(path, &s) : lstat(path, &s)) != 0) {
		if (trace_all) logf_("    stat(\"%s\") -> %s\n", p, strerror(errno));
		return err();
	}
	put_stat(c->a[1], &s, follow ? tahoe_flags_path(path) : tahoe_flags_path(path));
	return 0;
}
static long bsd_stat64(struct ctx* c) { return do_stat(c, 1); }
static long bsd_lstat64(struct ctx* c) { return do_stat(c, 0); }
static long bsd_fstat64(struct ctx* c) {
	struct stat s;
	if (fstat((int)c->a[0], &s) != 0) return err();
	put_stat(c->a[1], &s, tahoe_flags_fd((int)c->a[0]));
	return 0;
}


static long bsd_dup(struct ctx* c)  { RET(dup((int)c->a[0])); }
static long bsd_dup2(struct ctx* c) { RET(dup2((int)c->a[0], (int)c->a[1])); }

// fstatat64(fd, ruta, búfer, flags): AT_FDCWD = -2 y AT_SYMLINK_NOFOLLOW = 0x20 en Darwin
static long bsd_fstatat64(struct ctx* c) {
	char p[4096], b[4200];
	struct stat s;
	if (safe_string(c->a[1], p, sizeof p) != 0) return -D_EFAULT;
	int dfd = (int)c->a[0];
	if (dfd == -2) dfd = AT_FDCWD;
	int flags = ((int)c->a[3] & 0x20) ? AT_SYMLINK_NOFOLLOW : 0;
	if (p[0] == '\0') flags |= AT_EMPTY_PATH;
	const char* path = (dfd == AT_FDCWD || p[0] == '/') ? resolve(p, b, sizeof b) : p;
	if (fstatat(dfd, path, &s, flags) != 0) {
		if (trace_all) logf_("    fstatat(%d, \"%s\") -> %s\n", (int)c->a[0], p, strerror(errno));
		return err();
	}
	uint32_t fl = 0;
	if (dfd == AT_FDCWD || p[0] == '/') fl = tahoe_flags_path(path);
	else if (p[0] == '\0') fl = tahoe_flags_fd(dfd);
	else { int tf = openat(dfd, path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC); if (tf >= 0) { fl = tahoe_flags_fd(tf); close(tf); } }
	put_stat(c->a[2], &s, fl);
	return 0;
}

// fcntl de Darwin: solo los comandos que usa el arranque
static long bsd_fcntl(struct ctx* c) {
	int fd = (int)c->a[0], cmd = (int)c->a[1];
	switch (cmd) {
	case 0:  RET(fcntl(fd, F_DUPFD, (int)c->a[2]));
	case 1:  RET(fcntl(fd, F_GETFD));
	case 2:  RET(fcntl(fd, F_SETFD, (int)c->a[2]));
	case 67: RET(fcntl(fd, F_DUPFD_CLOEXEC, (int)c->a[2]));
	case 3: { int f = fcntl(fd, F_GETFL); if (f < 0) return err(); return (f & 3) | ((f & O_NONBLOCK) ? 4 : 0) | ((f & O_APPEND) ? 8 : 0); }
	case 4: { int f = (int)c->a[2], lf = 0; if (f & 4) lf |= O_NONBLOCK; if (f & 8) lf |= O_APPEND; RET(fcntl(fd, F_SETFL, lf)); }
	case 45: case 48: case 51: return 0;                  // F_RDAHEAD, F_NOCACHE, F_FULLFSYNC: sin efecto
	case 50: {                                            // F_GETPATH: ruta del descriptor
		char link[64], path[4096];
		snprintf(link, sizeof link, "/proc/thread-self/fd/%d", fd);
		ssize_t n = readlink(link, path, sizeof path - 1);
		if (n < 0) { if (trace_all) logf_("    F_GETPATH(fd=%d) fallo: %s\n", fd, strerror(errno)); return err(); }
		path[n] = 0;
		const char* p = path;
		size_t rl = tahoe_root ? strlen(tahoe_root) : 0;
		if (rl && !strncmp(path, tahoe_root, rl) && (path[rl] == '/' || path[rl] == '\0')) p = path[rl] ? path + rl : "/";    // quitar la raíz de macOS
		if (trace_all) logf_("    F_GETPATH(fd=%d) = \"%s\"\n", fd, p);
		return safe_write(c->a[2], p, strlen(p) + 1) > 0 ? 0 : -D_EFAULT;
	}
	case 102: { struct ctx c2 = *c; c2.a[1] = 50; return bsd_fcntl(&c2); }   // F_GETPATH_NOFIRMLINK: sin firmlinks aquí
	case 7: case 8: case 9: case 90: case 91: case 92: case 93: {   // F_GETLK/SETLK/SETLKW y sus versiones OFD (por descripción abierta)
		// struct flock de Darwin: l_start, l_len (off_t), l_pid, l_type, l_whence (short). La de Linux tiene otro orden.
		uint8_t df[24];
		if (safe_read(c->a[2], df, 24) != 24) return -D_EFAULT;
		struct flock lf = { 0 };
		int16_t dt, dw; memcpy(&lf.l_start, df, 8); memcpy(&lf.l_len, df + 8, 8); memcpy(&dt, df + 20, 2); memcpy(&dw, df + 22, 2);
		lf.l_type = dt == 1 ? F_RDLCK : dt == 3 ? F_WRLCK : F_UNLCK;   // Darwin: F_RDLCK 1, F_UNLCK 2, F_WRLCK 3
		lf.l_whence = dw;
		int lc = cmd == 7 ? F_GETLK : cmd == 8 ? F_SETLK : cmd == 9 ? F_SETLKW : cmd == 92 ? F_OFD_GETLK : cmd == 90 ? F_OFD_SETLK : F_OFD_SETLKW;
		if (fcntl(fd, lc, &lf) != 0) return err();
		if (cmd == 7 || cmd == 92) {                       // devolver el cerrojo que estorba (o F_UNLCK)
			int16_t ot = lf.l_type == F_RDLCK ? 1 : lf.l_type == F_WRLCK ? 3 : 2, ow = (int16_t)lf.l_whence;
			int32_t opid = lf.l_pid;
			memcpy(df, &lf.l_start, 8); memcpy(df + 8, &lf.l_len, 8); memcpy(df + 16, &opid, 4); memcpy(df + 20, &ot, 2); memcpy(df + 22, &ow, 2);
			if (safe_write(c->a[2], df, 24) != 24) return -D_EFAULT;
		}
		return 0;
	}
	case 61: case 83: case 103: case 104: case 113: return 0;   // F_ADDFILESIGS*: no hay validación de firmas que hacer
	case 97: {                                              // F_ADDFILESIGS_RETURN: la firma "cubre" todo el archivo
		struct stat st;
		if (fstat(fd, &st) != 0) return err();
		int64_t end = st.st_size;
		return safe_write(c->a[2], &end, 8) == 8 ? 0 : -D_EFAULT;   // fs_file_start de salida: fin cubierto
	}
	case 98: case 62: case 76: case 100: case 101: return 0;   // CHECK_LV, NODIRECT, SINGLE_WRITER, TRIM_ACTIVE_FILE, SPECULATIVE_READ
	case 73: return 0;                                      // F_SETNOSIGPIPE: el emulador ya evita SIGPIPE en los envíos
	case 74: case 63: case 77: return 0;                    // F_GETNOSIGPIPE, F_GETPROTECTIONCLASS, F_GETPROTECTIONLEVEL: 0
	case 64: return 0;                                      // F_SETPROTECTIONCLASS: sin clases de protección
	case 85: RET(fdatasync(fd));                            // F_BARRIERFSYNC
	case 99: {                                              // F_PUNCHHOLE(fpunchhole_t: flags, reservado, offset, length)
		uint64_t ph[3]; uint8_t raw[24];
		if (safe_read(c->a[2], raw, 24) != 24) return -D_EFAULT;
		memcpy(&ph[1], raw + 8, 8); memcpy(&ph[2], raw + 16, 8);
		RET(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, (off_t)ph[1], (off_t)ph[2]));
	}
	case 106: RET(fcntl(fd, F_SETLEASE, (int)c->a[2] == 1 ? F_RDLCK : (int)c->a[2] == 3 ? F_WRLCK : F_UNLCK));
	case 107: { int l = fcntl(fd, F_GETLEASE); if (l < 0) return err(); return l == F_RDLCK ? 1 : l == F_WRLCK ? 3 : 2; }
	default:
		logf_("    fcntl: comando %d (fd=%d) sin implementar\n", cmd, fd);
		return -D_EINVAL;
	}
}



// struct statfs de Darwin (64 bits de inodo): 2168 bytes
#include <sys/statfs.h>
static void put_statfs(uint64_t out, const struct statfs* s, const char* mnt) {
	uint8_t d[2168];
	memset(d, 0, sizeof d);
#define W(type, off, v) do { type t_ = (type)(v); memcpy(d + (off), &t_, sizeof t_); } while (0)
	W(uint32_t, 0, s->f_bsize);
	W(int32_t, 4, s->f_bsize);
	W(uint64_t, 8, s->f_blocks);
	W(uint64_t, 16, s->f_bfree);
	W(uint64_t, 24, s->f_bavail);
	W(uint64_t, 32, s->f_files);
	W(uint64_t, 40, s->f_ffree);
	W(uint32_t, 48, s->f_fsid.__val[0]);
	W(uint32_t, 52, s->f_fsid.__val[1]);
	W(uint32_t, 60, 0x18);                              // f_type: APFS
	W(uint32_t, 64, 0x14000 | 0x1000);                  // f_flags: MNT_ROOTFS | MNT_LOCAL | MNT_JOURNALED...
	memcpy(d + 72, "apfs", 5);
	strncpy((char*)d + 88, mnt, 1023);
	strncpy((char*)d + 1112, "/dev/disk1s1", 1023);
#undef W
	safe_write(out, d, sizeof d);
}
// Solo se anuncia un sistema de archivos: la raíz.
static long bsd_getfsstat64(struct ctx* c) {
	if (!c->a[0]) return 1;                              // sin búfer: solo el recuento
	if (c->a[1] < 2168) return 0;
	struct statfs s;
	if (statfs(tahoe_root ? tahoe_root : "/", &s) != 0) return err();
	put_statfs(c->a[0], &s, "/");
	return 1;
}
static long bsd_statfs64(struct ctx* c) {
	char p[4096], b[4200];
	struct statfs s;
	if (safe_string(c->a[0], p, sizeof p) != 0) return -D_EFAULT;
	if (statfs(resolve(p, b, sizeof b), &s) != 0) return err();
	put_statfs(c->a[1], &s, p);
	return 0;
}
static long bsd_fstatfs64(struct ctx* c) {
	struct statfs s;
	if (fstatfs((int)c->a[0], &s) != 0) return err();
	put_statfs(c->a[1], &s, "/");
	return 0;
}


// getattrlist(ruta, attrlist*, búfer, tamaño, opciones): atributos del volumen y del objeto.
// Solo se soportan los que usa el arranque: comunes DEVID (0x2) y FSID (0x4), y de volumen CAPABILITIES
// (0x20000) y UUID (0x40000). El búfer lleva primero su longitud total y luego los atributos en orden de bit.
#define ATTR_CMN_DEVID 0x00000002u
#define ATTR_CMN_FSID  0x00000004u
#define ATTR_CMN_FULLPATH 0x08000000u
#define ATTR_VOL_INFO  0x80000000u
#define ATTR_VOL_CAPABILITIES 0x00020000u
#define ATTR_VOL_UUID  0x00040000u
static size_t pack_entry(uint8_t* o, uint32_t common, uint32_t dir, uint32_t file, uint32_t cmnext, const char* name, const char* fullpath, const struct stat* s, int pack_inval);
static long bsd_getattrlist(struct ctx* c) {
	char p[4096], b[4200];
	uint32_t al[6] = { 0 };
	struct stat s;
	if (safe_string(c->a[0], p, sizeof p) != 0 || safe_read(c->a[1], al, sizeof al) != sizeof al) return -D_EFAULT;
	uint32_t common = al[1], vol = al[2];
	if (!vol) {                                           // atributos del objeto: empaquetado general
		int nofollow = (c->a[4] & 1) != 0;
		struct stat st;
		const char* rpth = resolve(p, b, sizeof b);
		if ((nofollow ? lstat(rpth, &st) : stat(rpth, &st)) != 0) return err();
		char real[4096], gp2[4096];
		const char* rp = realpath(rpth, real) ? real : p;
		size_t rl = tahoe_root ? strlen(tahoe_root) : 0;
		if (rl && !strncmp(rp, tahoe_root, rl) && (rp[rl] == '/' || rp[rl] == '\0')) rp += rl;
		snprintf(gp2, sizeof gp2, "%s", rp[0] ? rp : "/");
		const char* base = strrchr(gp2, '/');
		base = base && base[1] ? base + 1 : gp2;
		static uint8_t buf[8192];
		size_t n = pack_entry(buf, common, al[3], al[4], (c->a[4] & 0x20) ? al[5] : 0, base, gp2, &st, (c->a[4] & 8) != 0);
		if (n > c->a[3]) { uint32_t tot = (uint32_t)n; safe_write(c->a[2], &tot, c->a[3] >= 4 ? 4 : 0); return 0; }
		return safe_write(c->a[2], buf, n) == (ssize_t)n ? 0 : -D_EFAULT;
	}
	// Atributos de volumen (con algunos comunes). Orden de sys/attr.h: longitud, returned_attrs (si se pidió), comunes y de
	// volumen por orden de bit. Las cadenas van al final y se señalan con attrreference_t {desplazamiento desde la propia
	// referencia, longitud con el NUL}. El volumen se presenta como el APFS de arranque montado en "/".
	uint32_t known_c = ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_FULLPATH | 0x80000000u /*RETURNED_ATTRS*/;
	uint32_t known_v = 0xF0FFFFFFu;                               // ATTR_VOL_VALIDMASK
	if ((common & ~known_c) || (vol & ~known_v) || al[3] || al[4] || al[5]) {
		logf_("    getattrlist(\"%s\"): atributos sin implementar common=0x%x vol=0x%x dir=0x%x file=0x%x fork=0x%x\n", p, common, vol, al[3], al[4], al[5]);
		return -45;                                       // ENOTSUP
	}
	const char* rpv = resolve(p, b, sizeof b);
	if (stat(rpv, &s) != 0) return err();
	struct statfs sf; if (statfs(rpv, &sf) != 0) memset(&sf, 0, sizeof sf);
	uint8_t out[1024];
	size_t n = 4;                                         // el primer campo es la longitud total
	struct { size_t pos; const char* str; } refs[8]; int nrefs = 0;
#define PUT(v, len) do { memcpy(out + n, (v), (len)); n += (len); } while (0)
#define PUTU32(x) do { uint32_t _v = (uint32_t)(x); PUT(&_v, 4); } while (0)
#define PUTU64(x) do { uint64_t _v = (uint64_t)(x); PUT(&_v, 8); } while (0)
#define PUTREF(sv) do { refs[nrefs].pos = n; refs[nrefs++].str = (sv); n += 8; } while (0)
	if (common & 0x80000000u) {                           // attribute_set_t: lo que se devuelve (todo lo pedido)
		uint32_t rs[5] = { common, vol, 0, 0, 0 };
		PUT(rs, 20);
	}
	char gpath[4096] = "";
	if (common & ATTR_CMN_DEVID) { uint32_t d = (major(s.st_dev) << 24) | (minor(s.st_dev) & 0xffffff); PUT(&d, 4); }
	if (common & ATTR_CMN_FSID) { uint32_t f2[2] = { (uint32_t)s.st_dev, 0x18 }; PUT(f2, 8); }
	if (common & ATTR_CMN_FULLPATH) {                     // ruta absoluta tal como la ve macOS (sin la raíz del host)
		char real[4096];
		const char* rp = realpath(rpv, real) ? real : p;
		size_t rl = tahoe_root ? strlen(tahoe_root) : 0;
		if (rl && !strncmp(rp, tahoe_root, rl) && (rp[rl] == '/' || rp[rl] == '\0')) rp += rl;
		snprintf(gpath, sizeof gpath, "%s", rp[0] ? rp : "/");
		PUTREF(gpath);
	}
	uint64_t bs = sf.f_bsize ? (uint64_t)sf.f_bsize : 4096;
	if (vol & 0x1) PUTU32(0x1c);                           // FSTYPE (número de vfs; apfs)
	if (vol & 0x2) PUTU32(0x4244);                         // SIGNATURE
	if (vol & 0x4) PUTU64(sf.f_blocks * bs);               // SIZE
	if (vol & 0x8) PUTU64(sf.f_bfree * bs);                // SPACEFREE
	if (vol & 0x10) PUTU64(sf.f_bavail * bs);              // SPACEAVAIL
	if (vol & 0x20) PUTU64(bs);                            // MINALLOCATION
	if (vol & 0x40) PUTU64(bs);                            // ALLOCATIONCLUMP
	if (vol & 0x80) PUTU32(bs);                            // IOBLOCKSIZE
	if (vol & 0x100) PUTU32(sf.f_files - sf.f_ffree);      // OBJCOUNT
	if (vol & 0x200) PUTU32(sf.f_files - sf.f_ffree);      // FILECOUNT
	if (vol & 0x400) PUTU32(0);                            // DIRCOUNT
	if (vol & 0x800) PUTU32(sf.f_files);                   // MAXOBJCOUNT
	if (vol & 0x1000) PUTREF("/");                         // MOUNTPOINT
	if (vol & 0x2000) PUTREF("Macintosh HD");              // NAME
	if (vol & 0x4000) PUTU32(0x1000 | 0x4000);             // MOUNTFLAGS: MNT_LOCAL | MNT_ROOTFS
	if (vol & 0x8000) PUTREF("/dev/disk1s1");              // MOUNTEDDEVICE
	if (vol & 0x10000) PUTU64(0);                          // ENCODINGSUSED
	if (vol & ATTR_VOL_CAPABILITIES) {
		// vol_capabilities_attr_t: capabilities[4] y valid[4] (formato, interfaces, reservados)
		uint32_t caps[8] = {
			0x1 | 0x2 | 0x4 | 0x40 | 0x80 | 0x200 | 0x400 | 0x800 | 0x2000 | 0x4000 | 0x20000,   // formato (como APFS)
			0x2 | 0x10 | 0x20 | 0x40 | 0x100 | 0x200 | 0x400 | 0x800 | 0x4000 | 0x10000,         // interfaces
			0, 0,
			0x03ffffff, 0x000fffff, 0, 0,                                                          // bits válidos
		};
		PUT(caps, 32);
	}
	if (vol & ATTR_VOL_UUID) {
		static const uint8_t uuid[16] = { 0x74, 0x61, 0x68, 0x6f, 0x65, 0x2d, 0x72, 0x75, 0x6e, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x01 };
		PUT(uuid, 16);
	}
	if (vol & 0x80000) PUTU32(0);                          // MOUNTEXTFLAGS
	if (vol & 0x100000) PUTREF("apfs");                    // FSTYPENAME
	if (vol & 0x200000) PUTU32(0);                         // FSSUBTYPE
	if (vol & 0x400000) PUTU32(0);                         // OWNER (root)
	if (vol & 0x800000) PUTU64((sf.f_blocks - sf.f_bfree) * bs);   // SPACEUSED
	if (vol & 0x10000000) PUTU64(0);                       // QUOTA_SIZE
	if (vol & 0x20000000) PUTU64(0);                       // RESERVED_SIZE
	if (vol & 0x40000000) {                                // ATTRIBUTES: vol_attributes_attr_t (válidos y nativos)
		uint32_t va[10] = { 0xffffffff, 0xF0FFFFFF, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xF0FFFFFF, 0xffffffff, 0xffffffff, 0xffffffff };
		PUT(va, 40);
	}
	for (int i = 0; i < nrefs; i++) {                       // cadenas al final
		uint32_t len = (uint32_t)strlen(refs[i].str) + 1;
		if (n + len + 4 > sizeof out) return -D_ENOMEM;
		int32_t off = (int32_t)(n - refs[i].pos);
		memcpy(out + refs[i].pos, &off, 4);
		memcpy(out + refs[i].pos + 4, &len, 4);
		memcpy(out + n, refs[i].str, len);
		n += (len + 3) & ~3u;
	}
#undef PUT
#undef PUTU32
#undef PUTU64
#undef PUTREF
	uint32_t total = (uint32_t)n;
	memcpy(out, &total, 4);
	if (n > c->a[3]) { safe_write(c->a[2], &total, c->a[3] >= 4 ? 4 : 0); return 0; }   // no cabe: solo la longitud
	return safe_write(c->a[2], out, n) == (ssize_t)n ? 0 : -D_EFAULT;
}


// chdir / fchdir: el directorio de trabajo es real (dentro de TAHOE_ROOT), así las rutas relativas funcionan solas.
static long bsd_chdir(struct ctx* c) {
	char p[4096], b[4200];
	if (safe_string(c->a[0], p, sizeof p) != 0) return -D_EFAULT;
	RET(chdir(resolve(p, b, sizeof b)));
}
static long bsd_fchdir(struct ctx* c) { RET(fchdir((int)c->a[0])); }

// getdirentries64(fd, búfer, tamaño, base*): entradas de directorio. struct dirent de Darwin (64 bits de inodo):
// {u64 d_ino, u64 d_seekoff, u16 d_reclen, u16 d_namlen, u8 d_type, char d_name[]}, registros alineados a 8.
static long bsd_getdirentries64(struct ctx* c) {
	int fd = (int)c->a[0];
	uint64_t gbuf = c->a[1], gsize = c->a[2];
	uint8_t lin[16384];
	off_t start = lseek(fd, 0, SEEK_CUR);
	size_t want = gsize * 2 / 3 < sizeof lin ? gsize * 2 / 3 : sizeof lin;
	if (want < 512) want = 512 < sizeof lin ? 512 : sizeof lin;
	long n = syscall(SYS_getdents64, fd, lin, want);
	if (n < 0) return err();
	uint8_t* out = malloc(gsize);
	size_t used = 0;
	off_t prev = start;
	for (long pos = 0; pos < n;) {
		uint64_t ino = *(uint64_t*)(lin + pos);
		int64_t off = *(int64_t*)(lin + pos + 8);
		uint16_t reclen = *(uint16_t*)(lin + pos + 16);
		uint8_t type = lin[pos + 18];
		const char* name = (const char*)lin + pos + 19;
		size_t nl = strlen(name);
		size_t dr = (21 + nl + 1 + 7) & ~7UL;
		if (used + dr > gsize) { lseek(fd, prev, SEEK_SET); break; }     // no cabe: devolver la entrada al directorio
		uint8_t* e = out + used;
		memset(e, 0, dr);
		memcpy(e, &ino, 8);
		memcpy(e + 8, &off, 8);
		uint16_t drl = (uint16_t)dr, nlen = (uint16_t)nl;
		memcpy(e + 16, &drl, 2);
		memcpy(e + 18, &nlen, 2);
		e[20] = type;
		memcpy(e + 21, name, nl + 1);
		used += dr;
		prev = off;
		pos += reclen;
	}
	long rc = (long)used;
	if (used && safe_write(gbuf, out, used) != (ssize_t)used) rc = -D_EFAULT;
	free(out);
	if (rc >= 0 && c->a[3]) { int64_t base = lseek(fd, 0, SEEK_CUR); safe_write(c->a[3], &base, 8); }
	return rc;
}


// getattrlistbulk: lectura de directorios con atributos. Sin implementar: ENOTSUP (45) hace que fts() use readdir.
#define A_CMN_NAME 0x00000001u
#define A_CMN_DEVID 0x00000002u
#define A_CMN_FSID 0x00000004u
#define A_CMN_OBJTYPE 0x00000008u
#define A_CMN_CRTIME 0x00000200u
#define A_CMN_MODTIME 0x00000400u
#define A_CMN_CHGTIME 0x00000800u
#define A_CMN_ACCTIME 0x00001000u
#define A_CMN_OWNERID 0x00008000u
#define A_CMN_GRPID 0x00010000u
#define A_CMN_ACCESSMASK 0x00020000u
#define A_CMN_FLAGS 0x00040000u
#define A_CMN_FILEID 0x02000000u
#define A_CMN_RETURNED 0x80000000u
#define A_FILE_LINKCOUNT 0x1u
#define A_FILE_TOTALSIZE 0x2u
#define A_FILE_ALLOCSIZE 0x4u
#define A_FILE_IOBLOCKSIZE 0x8u
#define A_FILE_DEVTYPE 0x20u
#define A_FILE_DATALENGTH 0x200u

static uint32_t vtype_of(mode_t m) {                       // fsobj_type_t
	switch (m & S_IFMT) {
	case S_IFREG: return 1; case S_IFDIR: return 2; case S_IFBLK: return 3; case S_IFCHR: return 4;
	case S_IFLNK: return 5; case S_IFSOCK: return 6; case S_IFIFO: return 7; default: return 0;
	}
}

// Empaqueta los atributos de un objeto (getattrlist y getattrlistbulk). El orden es el de sys/attr.h: primero
// returned_attrs si se pidió, luego comunes, de directorio y de archivo, cada grupo por orden de bit. Los
// atributos que no valen para el objeto (de archivo en un directorio y viceversa) se omiten, o quedan a cero sin
// marcar en returned_attrs si se pidió FSOPT_PACK_INVAL_ATTRS.
#define A_CMN_OBJTAG 0x10u
#define A_CMN_OBJID 0x20u
#define A_CMN_PAROBJID 0x80u
#define A_CMN_FNDRINFO 0x4000u
#define A_CMN_GENCOUNT 0x80000u
#define A_CMN_DOCID 0x100000u
#define A_CMN_USERACCESS 0x200000u
#define A_CMN_PARENTID 0x4000000u
#define A_CMN_FULLPATH2 0x08000000u
#define A_CMN_ADDEDTIME 0x10000000u
#define A_CMN_DPFLAGS 0x40000000u
#define A_DIR_LINKCOUNT 0x1u
#define A_DIR_ENTRYCOUNT 0x2u
#define A_DIR_MOUNTSTATUS 0x4u
// cmnext: atributos comunes extendidos (FSOPT_ATTR_CMN_EXTENDED: viajan en el campo forkattr), después de los de archivo.
static size_t pack_entry(uint8_t* o, uint32_t common, uint32_t dir, uint32_t file, uint32_t cmnext, const char* name, const char* fullpath, const struct stat* s, int pack_inval) {
	size_t n = 4;                                            // longitud total, se rellena al final
	size_t ret_at = n;
	if (common & A_CMN_RETURNED) n += 20;                    // attribute_set_t returned_attrs
	uint32_t rc = 0, rd = 0, rf = 0;
	int isdir = S_ISDIR(s->st_mode);
	size_t name_ref = 0, path_ref = 0;
#define P32(v) do { uint32_t t_ = (uint32_t)(v); memcpy(o + n, &t_, 4); n += 4; } while (0)
#define P64(v) do { uint64_t t_ = (uint64_t)(v); memcpy(o + n, &t_, 8); n += 8; } while (0)
#define PTS(ts) do { P64((ts).tv_sec); P64((ts).tv_nsec); } while (0)
	if (common & A_CMN_NAME) { name_ref = n; n += 8; rc |= A_CMN_NAME; }
	if (common & A_CMN_DEVID) { P32((major(s->st_dev) << 24) | (minor(s->st_dev) & 0xffffff)); rc |= A_CMN_DEVID; }
	if (common & A_CMN_FSID) { P32((uint32_t)s->st_dev); P32(0x18); rc |= A_CMN_FSID; }
	if (common & A_CMN_OBJTYPE) { P32(vtype_of(s->st_mode)); rc |= A_CMN_OBJTYPE; }
	if (common & A_CMN_OBJTAG) { P32(0x17); rc |= A_CMN_OBJTAG; }                         // VT_APFS
	if (common & A_CMN_OBJID) { P32((uint32_t)s->st_ino); P32((uint32_t)(s->st_ino >> 32)); rc |= A_CMN_OBJID; }
	if (common & A_CMN_PAROBJID) { P32(0); P32(0); rc |= A_CMN_PAROBJID; }
	if (common & A_CMN_CRTIME) { PTS(s->st_ctim); rc |= A_CMN_CRTIME; }
	if (common & A_CMN_MODTIME) { PTS(s->st_mtim); rc |= A_CMN_MODTIME; }
	if (common & A_CMN_CHGTIME) { PTS(s->st_ctim); rc |= A_CMN_CHGTIME; }
	if (common & A_CMN_ACCTIME) { PTS(s->st_atim); rc |= A_CMN_ACCTIME; }
	if (common & A_CMN_FNDRINFO) { memset(o + n, 0, 32); n += 32; rc |= A_CMN_FNDRINFO; }
	if (common & A_CMN_OWNERID) { P32(s->st_uid); rc |= A_CMN_OWNERID; }
	if (common & A_CMN_GRPID) { P32(s->st_gid); rc |= A_CMN_GRPID; }
	if (common & A_CMN_ACCESSMASK) { P32(s->st_mode & 07777); rc |= A_CMN_ACCESSMASK; }
	if (common & A_CMN_FLAGS) { P32(0); rc |= A_CMN_FLAGS; }
	if (common & A_CMN_GENCOUNT) { P32(0); rc |= A_CMN_GENCOUNT; }
	if (common & A_CMN_DOCID) { P32(0); rc |= A_CMN_DOCID; }
	if (common & A_CMN_USERACCESS) {                                                      // R_OK 4, W_OK 2, X_OK 1 de Darwin = bits 4,2,1... se calcula por permisos del propietario/otros
		uint32_t ua = 0; uid_t u = geteuid();
		mode_t m = s->st_mode;
		int sh = (u == s->st_uid) ? 6 : 0;
		if (u == 0 || (m >> sh) & 4) ua |= 4;
		if (u == 0 || (m >> sh) & 2) ua |= 2;
		if (u == 0 || (m >> sh) & 1) ua |= 1;
		P32(ua); rc |= A_CMN_USERACCESS;
	}
	if (common & A_CMN_FILEID) { P64(s->st_ino); rc |= A_CMN_FILEID; }
	if (common & A_CMN_PARENTID) { P64(0); rc |= A_CMN_PARENTID; }
	if (common & A_CMN_FULLPATH2) { path_ref = n; n += 8; rc |= A_CMN_FULLPATH2; }
	if (common & A_CMN_ADDEDTIME) { PTS(s->st_ctim); rc |= A_CMN_ADDEDTIME; }
	if (common & 0x20000000u) { P32(0); rc |= 0x20000000u; }                              // ATTR_CMN_ERROR: sin error
	if (common & A_CMN_DPFLAGS) { P32(0); rc |= A_CMN_DPFLAGS; }
	// directorio: solo valen para directorios
	if (dir) {
		if (dir & A_DIR_LINKCOUNT) { P32(isdir ? s->st_nlink : 0); if (isdir) rd |= A_DIR_LINKCOUNT; }
		if (dir & A_DIR_ENTRYCOUNT) { P32(0); if (isdir) rd |= A_DIR_ENTRYCOUNT; }
		if (dir & A_DIR_MOUNTSTATUS) { P32(0); if (isdir) rd |= A_DIR_MOUNTSTATUS; }
	}
	// archivo: solo valen para no directorios
	if (file & A_FILE_LINKCOUNT) { P32(isdir ? 0 : s->st_nlink); if (!isdir) rf |= A_FILE_LINKCOUNT; }
	if (file & A_FILE_TOTALSIZE) { P64(isdir ? 0 : s->st_size); if (!isdir) rf |= A_FILE_TOTALSIZE; }
	if (file & A_FILE_ALLOCSIZE) { P64(isdir ? 0 : (uint64_t)s->st_blocks * 512); if (!isdir) rf |= A_FILE_ALLOCSIZE; }
	if (file & A_FILE_IOBLOCKSIZE) { P32(isdir ? 0 : s->st_blksize); if (!isdir) rf |= A_FILE_IOBLOCKSIZE; }
	if (file & A_FILE_DEVTYPE) { P32(isdir ? 0 : (uint32_t)s->st_rdev); if (!isdir) rf |= A_FILE_DEVTYPE; }
	if (file & A_FILE_DATALENGTH) { P64(isdir ? 0 : s->st_size); if (!isdir) rf |= A_FILE_DATALENGTH; }
	if (file & 0x400u) { P64(isdir ? 0 : (uint64_t)s->st_blocks * 512); if (!isdir) rf |= 0x400u; }   // DATAALLOCSIZE
	if (file & 0x1000u) { P64(0); if (!isdir) rf |= 0x1000u; }                                         // RSRCLENGTH
	if (file & 0x2000u) { P64(0); if (!isdir) rf |= 0x2000u; }                                         // RSRCALLOCSIZE
	uint32_t rx = 0;
	size_t relpath_ref = 0, nofirm_ref = 0;
	if (cmnext & 0x4) { relpath_ref = n; n += 8; rx |= 0x4; }                          // RELPATH
	if (cmnext & 0x8) { P64(0); rx |= 0x8; }                                             // PRIVATESIZE
	if (cmnext & 0x10) { P64(s->st_ino); rx |= 0x10; }                                   // LINKID
	if (cmnext & 0x20) { nofirm_ref = n; n += 8; rx |= 0x20; }                         // NOFIRMLINKPATH
	if (cmnext & 0x40) { P32((major(s->st_dev) << 24) | (minor(s->st_dev) & 0xffffff)); rx |= 0x40; }   // REALDEVID
	if (cmnext & 0x80) { P32((uint32_t)s->st_dev); P32(0x18); rx |= 0x80; }             // REALFSID
	if (cmnext & 0x100) { P64(s->st_ino); rx |= 0x100; }                                 // CLONEID
	if (cmnext & 0x200) { P64(0); rx |= 0x200; }                                         // EXT_FLAGS
	if (cmnext & 0x400) { P64(0); rx |= 0x400; }                                         // RECURSIVE_GENCOUNT
	if (cmnext & 0x800) { P64(0); rx |= 0x800; }                                         // ATTRIBUTION_TAG
	if (cmnext & 0x1000) { P32(1); rx |= 0x1000; }                                       // CLONE_REFCNT
	(void)pack_inval;
	// cadenas de longitud variable al final, en el orden de sus referencias
	if (common & A_CMN_NAME) {
		size_t nl = strlen(name) + 1;
		int32_t off = (int32_t)(n - name_ref);
		uint32_t len = (uint32_t)nl;
		memcpy(o + name_ref, &off, 4);
		memcpy(o + name_ref + 4, &len, 4);
		memcpy(o + n, name, nl);
		n += (nl + 3) & ~3UL;
	}
	if (common & A_CMN_FULLPATH2) {
		size_t pl = strlen(fullpath) + 1;
		int32_t off = (int32_t)(n - path_ref);
		uint32_t len = (uint32_t)pl;
		memcpy(o + path_ref, &off, 4);
		memcpy(o + path_ref + 4, &len, 4);
		memcpy(o + n, fullpath, pl);
		n += (pl + 3) & ~3UL;
	}
	const char* rel_or_path[2] = { fullpath, fullpath };
	size_t refs2[2] = { relpath_ref, nofirm_ref };
	for (int i = 0; i < 2; i++) {
		if (!refs2[i]) continue;
		size_t pl = strlen(rel_or_path[i]) + 1;
		int32_t off = (int32_t)(n - refs2[i]);
		uint32_t len = (uint32_t)pl;
		memcpy(o + refs2[i], &off, 4);
		memcpy(o + refs2[i] + 4, &len, 4);
		memcpy(o + n, rel_or_path[i], pl);
		n += (pl + 3) & ~3UL;
	}
	if (common & A_CMN_RETURNED) {
		uint32_t ret[5] = { rc | A_CMN_RETURNED, 0, rd, rf, rx };    // commonattr, volattr, dirattr, fileattr, forkattr (cmnext)
		memcpy(o + ret_at, ret, 20);
	}
	uint32_t total = (uint32_t)n;
	memcpy(o, &total, 4);
	return n;
#undef P32
#undef P64
#undef PTS
}
static uint32_t dir_attrs_g;                              // dirattr de la petición en curso (getattrlistbulk)
static size_t pack_bulk_entry(uint8_t* o, uint32_t common, uint32_t file, const char* name, const struct stat* s) {
	return pack_entry(o, common, dir_attrs_g, file, 0, name, "", s, 1);
}

// getattrlistbulk(fd, attrlist*, búfer, tamaño, opciones): devuelve cuántas entradas empaquetó (0 = fin).
static long bsd_getattrlistbulk(struct ctx* c) {
	int fd = (int)c->a[0];
	uint32_t al[6] = { 0 };
	if (safe_read(c->a[1], al, sizeof al) != sizeof al) return -D_EFAULT;
	uint32_t common = al[1], dir = al[3], file = al[4];
	uint32_t known_c = A_CMN_NAME | A_CMN_DEVID | A_CMN_FSID | A_CMN_OBJTYPE | A_CMN_OBJTAG | A_CMN_OBJID | A_CMN_PAROBJID | A_CMN_CRTIME | A_CMN_MODTIME |
		A_CMN_CHGTIME | A_CMN_ACCTIME | A_CMN_FNDRINFO | A_CMN_OWNERID | A_CMN_GRPID | A_CMN_ACCESSMASK | A_CMN_FLAGS | A_CMN_GENCOUNT | A_CMN_DOCID |
		A_CMN_USERACCESS | A_CMN_FILEID | A_CMN_PARENTID | A_CMN_ADDEDTIME | 0x20000000u /*ERROR*/ | A_CMN_DPFLAGS | A_CMN_RETURNED;
	uint32_t known_f = A_FILE_LINKCOUNT | A_FILE_TOTALSIZE | A_FILE_ALLOCSIZE | A_FILE_IOBLOCKSIZE | A_FILE_DEVTYPE | A_FILE_DATALENGTH | 0x400u | 0x1000u | 0x2000u;
	if ((common & ~known_c) || (file & ~known_f) || (dir & ~7u) || al[2] || al[5]) {
		logf_("    getattrlistbulk: atributos sin implementar common=0x%x dir=0x%x file=0x%x\n", common, dir, file);
		return -45;
	}
	dir_attrs_g = dir;
	uint64_t gbuf = c->a[2], gsize = c->a[3];
	uint8_t lin[16384];
	uint8_t* out = malloc(gsize);
	if (!out) return -D_ENOMEM;
	size_t used = 0;
	long count = 0, rc = 0;
	for (;;) {
		off_t start = lseek(fd, 0, SEEK_CUR);
		long n = syscall(SYS_getdents64, fd, lin, 4096);
		if (n < 0) { rc = err(); break; }
		if (n == 0) break;
		int full = 0;
		off_t prev = start;
		for (long pos = 0; pos < n;) {
			int64_t off = *(int64_t*)(lin + pos + 8);
			uint16_t reclen = *(uint16_t*)(lin + pos + 16);
			const char* name = (const char*)lin + pos + 19;
			if (!strcmp(name, ".") || !strcmp(name, "..")) { prev = off; pos += reclen; continue; }   // el kernel no las devuelve
			struct stat s;
			if (fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) != 0) { prev = off; pos += reclen; continue; }
			uint8_t e[2048];
			size_t en = pack_bulk_entry(e, common, file, name, &s);
			if (used + en > gsize) { lseek(fd, prev, SEEK_SET); full = 1; break; }
			memcpy(out + used, e, en);
			used += en;
			count++;
			prev = off;
			pos += reclen;
		}
		if (full || count > 0) break;                         // con una pasada con resultados basta
	}
	if (rc < 0) { free(out); return rc; }
	if (used && safe_write(gbuf, out, used) != (ssize_t)used) { free(out); return -D_EFAULT; }
	free(out);
	return count;
}


// fsctl(ruta, comando, datos, opciones): ioctls de sistema de archivos. 0x40084a6a ('J', 106) es una consulta privada de
// APFS del estado del dispositivo raíz que lanza launchd; devuelve 8 bytes. Se responde sin banderas.
static long bsd_fsctl(struct ctx* c) {
	if (c->a[1] == 0x40084a6aUL) { uint64_t z = 0; return safe_write(c->a[2], &z, 8) == 8 ? 0 : -D_EFAULT; }
	logf_("    fsctl: comando 0x%lx sin implementar\n", c->a[1]);
	return -45;
}

// openat: AT_FDCWD vale -2 en Darwin
static long bsd_openat(struct ctx* c) {
	char path[4096], full[4200];
	if (safe_string(c->a[1], path, sizeof path) != 0) return -D_EFAULT;
	int dfd = (int)c->a[0];
	if (dfd == -2) dfd = AT_FDCWD;
	int flags = darwin_open_flags((int)c->a[2]);
	long fd = -1;
	if (tahoe_root && path[0] == '/') {
		snprintf(full, sizeof full, "%s%s", tahoe_root, path);
		fd = syscall(SYS_openat, dfd, full, flags, (int)c->a[3]);
	}
	if (fd < 0) fd = syscall(SYS_openat, dfd, path, flags, (int)c->a[3]);
	if (trace_all || fd < 0) logf_("    openat(%d, \"%s\") -> %ld%s%s\n", (int)c->a[0], path, fd, fd < 0 ? " " : "", fd < 0 ? strerror(errno) : "");
	return fd < 0 ? err() : fd;
}

// fsgetpath(búfer, tamaño, fsid*, objid): ruta a partir de un identificador de archivo. Solo se conoce la
// caché de dyld, cuyo identificador se publicó en la región dinámica (inodo en objid).
static long bsd_fsgetpath(struct ctx* c) {
	if (cache_guest_path[0] && (uint32_t)c->a[3] == (uint32_t)cache_ino) {
		size_t n = strlen(cache_guest_path) + 1;
		if (n > c->a[1]) return -D_ENOMEM;
		return safe_write(c->a[0], cache_guest_path, n) == (ssize_t)n ? (long)n : -D_EFAULT;
	}
	logf_("    fsgetpath: identificador desconocido (objid=0x%lx)\n", c->a[3]);
	return -D_ENOENT;
}

// ---------------------------------------------------------------- identidad y políticas
static long bsd_getuid(struct ctx* c)  { (void)c; return getuid(); }
static long bsd_geteuid(struct ctx* c) { (void)c; return geteuid(); }
static long bsd_getgid(struct ctx* c)  { (void)c; return getgid(); }
static long bsd_getegid(struct ctx* c) { (void)c; return getegid(); }

// __mac_syscall(política, llamada, argumento): sandbox, AMFI... Se registra y se acepta.
static long bsd_mac_syscall(struct ctx* c) {
	char pol[64];
	if (safe_string(c->a[0], pol, sizeof pol) != 0) strcpy(pol, "?");
	logf_("    __mac_syscall(\"%s\", llamada=%d) -> aceptada\n", pol, (int)c->a[1]);
	return 0;
}

void emu_fs_init(void) {
	reg_bsd(73, bsd_munmap);   reg_bsd(74, bsd_mprotect); reg_bsd(75, bsd_madvise); reg_bsd(197, bsd_mmap);
	reg_bsd(199, bsd_lseek);   reg_bsd(153, bsd_pread);   reg_bsd(154, bsd_pwrite);
	reg_bsd(33, bsd_access);   reg_bsd(58, bsd_readlink); reg_bsd(92, bsd_fcntl);
	reg_bsd(338, bsd_stat64);  reg_bsd(339, bsd_fstat64); reg_bsd(340, bsd_lstat64);
	reg_bsd(24, bsd_getuid);   reg_bsd(25, bsd_geteuid);  reg_bsd(47, bsd_getgid); reg_bsd(43, bsd_getegid);
	reg_bsd(381, bsd_mac_syscall);
	reg_bsd(347, bsd_getfsstat64); reg_bsd(345, bsd_statfs64); reg_bsd(346, bsd_fstatfs64);
	reg_bsd(242, bsd_fsctl); reg_bsd(220, bsd_getattrlist); reg_bsd(12, bsd_chdir); reg_bsd(13, bsd_fchdir); reg_bsd(344, bsd_getdirentries64); reg_bsd(461, bsd_getattrlistbulk);
	reg_bsd(41, bsd_dup);      reg_bsd(90, bsd_dup2);     reg_bsd(470, bsd_fstatat64);
	reg_bsd(463, bsd_openat); reg_bsd(464, bsd_openat);   /* openat_nocancel */     reg_bsd(427, bsd_fsgetpath);
}
