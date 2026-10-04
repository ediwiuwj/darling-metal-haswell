// Sockets de macOS sobre los de Linux: traducción de sockaddr, opciones, banderas y mensajes con descriptores.
// Solo AF_UNIX, AF_INET y AF_INET6; el resto de dominios (AF_SYSTEM, AF_ROUTE...) responde EAFNOSUPPORT.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "tahoe.h"

#define D_EAFNOSUPPORT 47
#define D_ENOPROTOOPT 42

static long err(void) { return -darwin_errno(errno); }
static int dom_to_linux(int d) { return d == 30 ? AF_INET6 : d; }

// sockaddr de Darwin (len, familia u8) -> Linux. Los sockets Unix se ubican bajo TAHOE_ROOT.
static int sa_in(const uint8_t* d, uint32_t len, uint8_t* out, socklen_t* outlen) {
	if (len < 2) return -D_EINVAL;
	uint8_t fam = d[1];
	if (fam == 1) {                                   // AF_UNIX: {len, familia, ruta[104]}
		struct sockaddr_un un = { .sun_family = AF_UNIX };
		size_t pl = len - 2 < sizeof un.sun_path - 1 ? len - 2 : sizeof un.sun_path - 1;
		char g[128] = { 0 };
		memcpy(g, d + 2, pl);
		if (g[0] == '/' && tahoe_root) snprintf(un.sun_path, sizeof un.sun_path, "%s%s", tahoe_root, g);
		else memcpy(un.sun_path, g, pl);
		memcpy(out, &un, sizeof un);
		*outlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path) + 1);
		return 0;
	}
	if (fam == 2 && len >= 8) {                       // AF_INET: {len, fam, port, addr, zero[8]}
		struct sockaddr_in in = { .sin_family = AF_INET };
		memcpy(&in.sin_port, d + 2, 2); memcpy(&in.sin_addr, d + 4, 4);
		memcpy(out, &in, sizeof in); *outlen = sizeof in;
		return 0;
	}
	if (fam == 30 && len >= 24) {                     // AF_INET6: {len, fam, port, flowinfo, addr[16], scope}
		struct sockaddr_in6 in6 = { .sin6_family = AF_INET6 };
		memcpy(&in6.sin6_port, d + 2, 2); memcpy(&in6.sin6_flowinfo, d + 4, 4); memcpy(&in6.sin6_addr, d + 8, 16);
		if (len >= 28) memcpy(&in6.sin6_scope_id, d + 24, 4);
		memcpy(out, &in6, sizeof in6); *outlen = sizeof in6;
		return 0;
	}
	return -D_EAFNOSUPPORT;
}
// Linux -> Darwin
static uint32_t sa_out(const uint8_t* l, socklen_t llen, uint8_t* d) {
	uint16_t fam; memcpy(&fam, l, 2);
	memset(d, 0, 128);
	if (fam == AF_UNIX) {
		const char* p = (const char*)l + 2;
		size_t rl = tahoe_root ? strlen(tahoe_root) : 0;
		if (rl && !strncmp(p, tahoe_root, rl)) p += rl;
		size_t pl = llen > 2 ? strnlen(p, llen - 2) : 0;
		d[1] = 1; memcpy(d + 2, p, pl > 103 ? 103 : pl);
		d[0] = (uint8_t)(2 + pl + 1);
		return d[0];
	}
	if (fam == AF_INET && llen >= 8) { d[0] = 16; d[1] = 2; memcpy(d + 2, l + 2, 2); memcpy(d + 4, l + 4, 4); return 16; }
	if (fam == AF_INET6 && llen >= 24) { d[0] = 28; d[1] = 30; memcpy(d + 2, l + 2, 2); memcpy(d + 4, l + 4, 4); memcpy(d + 8, l + 8, 16); if (llen >= 28) memcpy(d + 24, l + 24, 4); return 28; }
	return 0;
}

static int msg_flags(int f) {                         // MSG_* de Darwin -> Linux
	int l = MSG_NOSIGNAL;
	if (f & 0x1) l |= MSG_OOB;
	if (f & 0x2) l |= MSG_PEEK;
	if (f & 0x4) l |= MSG_DONTROUTE;
	if (f & 0x8) l |= MSG_EOR;
	if (f & 0x20) l |= MSG_TRUNC;
	if (f & 0x40) l |= MSG_WAITALL;
	if (f & 0x80) l |= MSG_DONTWAIT;
	return l;
}

static long net_socket(struct ctx* c) {
	int dom = dom_to_linux((int)c->a[0]);
	if (dom != AF_UNIX && dom != AF_INET && dom != AF_INET6) return -D_EAFNOSUPPORT;
	int type = (int)c->a[1] & 0xff;
	long r = syscall(SYS_socket, dom, type | SOCK_CLOEXEC * 0, (int)c->a[2]);
	return r < 0 ? err() : r;
}
static long net_socketpair(struct ctx* c) {
	int fds[2];
	if (socketpair(dom_to_linux((int)c->a[0]), (int)c->a[1], (int)c->a[2], fds) < 0) return err();
	return safe_write(c->a[3], fds, 8) == 8 ? 0 : -D_EFAULT;
}
static long net_bind(struct ctx* c) {
	uint8_t sa[128], ls[128]; socklen_t ll;
	uint32_t len = (uint32_t)c->a[2];
	if (len > sizeof sa || safe_read(c->a[1], sa, len) != (ssize_t)len) return -D_EFAULT;
	int e = sa_in(sa, len, ls, &ll);
	if (e) return e;
	long r = bind((int)c->a[0], (struct sockaddr*)ls, ll);
	if (trace_all || r < 0) logf_("    bind(%s) -> %s\n", ((struct sockaddr_un*)ls)->sun_family == AF_UNIX ? ((struct sockaddr_un*)ls)->sun_path : "inet", r < 0 ? strerror(errno) : "ok");
	return r < 0 ? err() : 0;
}
static long net_connect(struct ctx* c) {
	uint8_t sa[128], ls[128]; socklen_t ll;
	uint32_t len = (uint32_t)c->a[2];
	if (len > sizeof sa || safe_read(c->a[1], sa, len) != (ssize_t)len) return -D_EFAULT;
	int e = sa_in(sa, len, ls, &ll);
	if (e) return e;
	long r = connect((int)c->a[0], (struct sockaddr*)ls, ll);
	if (trace_all || (r < 0 && errno != EINPROGRESS)) logf_("    connect(%s) -> %s\n", ((struct sockaddr_un*)ls)->sun_family == AF_UNIX ? ((struct sockaddr_un*)ls)->sun_path : "inet", r < 0 ? strerror(errno) : "ok");
	return r < 0 ? err() : 0;
}
static long net_listen(struct ctx* c) { long r = listen((int)c->a[0], (int)c->a[1]); return r < 0 ? err() : 0; }
static long write_name(uint64_t nameaddr, uint64_t lenaddr, const uint8_t* l, socklen_t ll) {
	if (!nameaddr || !lenaddr) return 0;
	uint8_t d[128]; uint32_t dl = sa_out(l, ll, d), cap = 0;
	safe_read(lenaddr, &cap, 4);
	if (dl && safe_write(nameaddr, d, dl < cap ? dl : cap) < 0) return -D_EFAULT;
	safe_write(lenaddr, &dl, 4);
	return 0;
}
static long net_accept(struct ctx* c) {
	uint8_t l[128]; socklen_t ll = sizeof l;
	long r = accept((int)c->a[0], (struct sockaddr*)l, &ll);
	if (r < 0) return err();
	write_name(c->a[1], c->a[2], l, ll);
	return r;
}
static long net_getsockname(struct ctx* c) {
	uint8_t l[128]; socklen_t ll = sizeof l;
	if (getsockname((int)c->a[0], (struct sockaddr*)l, &ll) < 0) return err();
	return write_name(c->a[1], c->a[2], l, ll);
}
static long net_getpeername(struct ctx* c) {
	uint8_t l[128]; socklen_t ll = sizeof l;
	if (getpeername((int)c->a[0], (struct sockaddr*)l, &ll) < 0) return err();
	return write_name(c->a[1], c->a[2], l, ll);
}
static long net_shutdown(struct ctx* c) { long r = shutdown((int)c->a[0], (int)c->a[1]); return r < 0 ? err() : 0; }

// setsockopt/getsockopt: SOL_SOCKET de Darwin es 0xffff; las opciones usan otros números.
static int opt_to_linux(int o) {
	switch (o) {
	case 0x4: return SO_REUSEADDR; case 0x8: return SO_KEEPALIVE; case 0x10: return SO_DONTROUTE; case 0x20: return SO_BROADCAST;
	case 0x80: return SO_LINGER; case 0x100: return SO_OOBINLINE; case 0x200: return SO_REUSEPORT;
	case 0x1001: return SO_SNDBUF; case 0x1002: return SO_RCVBUF; case 0x1005: return SO_SNDTIMEO; case 0x1006: return SO_RCVTIMEO;
	case 0x1007: return SO_ERROR; case 0x1008: return SO_TYPE; case 0x1009: return SO_PEERCRED * 0 - 1;
	default: return -1;
	}
}
static long net_setsockopt(struct ctx* c) {
	int fd = (int)c->a[0], level = (int)c->a[1], opt = (int)c->a[2];
	uint8_t v[64]; uint32_t len = (uint32_t)c->a[4];
	if (len > sizeof v || (len && safe_read(c->a[3], v, len) != (ssize_t)len)) return -D_EFAULT;
	if (level == 0xffff) {
		if (opt == 0x1022) return 0;                                  // SO_NOSIGPIPE: ya se usa MSG_NOSIGNAL
		int lo = opt_to_linux(opt);
		if (lo < 0) return 0;                                         // opción sin equivalente: se acepta
		if ((opt == 0x1005 || opt == 0x1006) && len >= 16) {          // timeval de Darwin {i64, i32, pad}
			struct timeval tv; int64_t s; int32_t us; memcpy(&s, v, 8); memcpy(&us, v + 8, 4); tv.tv_sec = s; tv.tv_usec = us;
			return setsockopt(fd, SOL_SOCKET, lo, &tv, sizeof tv) < 0 ? err() : 0;
		}
		return setsockopt(fd, SOL_SOCKET, lo, v, len) < 0 ? err() : 0;
	}
	if (level == 0 /*IPPROTO_IP*/ || level == 6 /*TCP*/ || level == 41) return 0;   // ajustes de red: se aceptan sin efecto
	return -D_ENOPROTOOPT;
}
static long net_getsockopt(struct ctx* c) {
	int fd = (int)c->a[0], level = (int)c->a[1], opt = (int)c->a[2];
	uint32_t cap = 0;
	if (safe_read(c->a[4], &cap, 4) != 4) return -D_EFAULT;
	uint8_t v[64] = { 0 };
	socklen_t l = sizeof v;
	if (level == 0xffff) {
		int lo = opt_to_linux(opt);
		if (opt == 0x1007) {                                          // SO_ERROR: errno traducido a Darwin
			int e = 0; socklen_t el = sizeof e;
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &el) < 0) return err();
			e = e ? darwin_errno(e) : 0;
			memcpy(v, &e, 4); l = 4;
		} else if (lo < 0 || getsockopt(fd, SOL_SOCKET, lo, v, &l) < 0) { if (lo >= 0) return err(); memset(v, 0, 4); l = 4; }
	} else { memset(v, 0, 4); l = 4; }
	uint32_t n = l < cap ? l : cap;
	if (n && safe_write(c->a[3], v, n) < 0) return -D_EFAULT;
	safe_write(c->a[4], &n, 4);
	return 0;
}

static long net_sendto(struct ctx* c) {              // (fd, buf, len, flags, to*, tolen)
	uint8_t sa[128], ls[128]; socklen_t ll = 0;
	void* tp = NULL;
	if (c->a[4] && c->a[5]) {
		uint32_t len = (uint32_t)c->a[5];
		if (len > sizeof sa || safe_read(c->a[4], sa, len) != (ssize_t)len) return -D_EFAULT;
		int e = sa_in(sa, len, ls, &ll);
		if (e) return e;
		tp = ls;
	}
	long r = sendto((int)c->a[0], (const void*)c->a[1], c->a[2], msg_flags((int)c->a[3]), tp, ll);
	return r < 0 ? err() : r;
}
static long net_recvfrom(struct ctx* c) {            // (fd, buf, len, flags, from*, fromlen*)
	uint8_t l[128]; socklen_t ll = sizeof l;
	long r = recvfrom((int)c->a[0], (void*)c->a[1], c->a[2], msg_flags((int)c->a[3]) & ~MSG_NOSIGNAL, c->a[4] ? (struct sockaddr*)l : NULL, c->a[4] ? &ll : NULL);
	if (r < 0) return err();
	if (c->a[4]) write_name(c->a[4], c->a[5], l, ll);
	return r;
}

// sendmsg/recvmsg: msghdr de Darwin = {name*, namelen u32, iov*, iovlen i32, control*, controllen u32, flags i32}; los
// mensajes de control (cmsghdr {len u32, level i32, type i32}) solo se traducen para SCM_RIGHTS.
struct dmsghdr { uint64_t name; uint32_t namelen; uint32_t pad0; uint64_t iov; int32_t iovlen; int32_t pad1; uint64_t control; uint32_t controllen; int32_t flags; };
static long net_sendmsg(struct ctx* c) {
	struct dmsghdr d;
	if (safe_read(c->a[1], &d, sizeof d) != sizeof d) return -D_EFAULT;
	struct msghdr m = { 0 };
	uint8_t ls[128], sa[128]; socklen_t ll = 0;
	if (d.name && d.namelen) {
		if (d.namelen > sizeof sa || safe_read(d.name, sa, d.namelen) != (ssize_t)d.namelen) return -D_EFAULT;
		int e = sa_in(sa, d.namelen, ls, &ll);
		if (e) return e;
		m.msg_name = ls; m.msg_namelen = ll;
	}
	m.msg_iov = (struct iovec*)d.iov; m.msg_iovlen = (size_t)d.iovlen;
	uint8_t cbuf[256] = { 0 };
	if (d.control && d.controllen >= 12) {
		uint8_t dc[256];
		uint32_t cl = d.controllen < sizeof dc ? d.controllen : sizeof dc;
		if (safe_read(d.control, dc, cl) != (ssize_t)cl) return -D_EFAULT;
		uint32_t clen; int32_t lvl, typ; memcpy(&clen, dc, 4); memcpy(&lvl, dc + 4, 4); memcpy(&typ, dc + 8, 4);
		if (lvl == 0xffff && typ == 1 && clen >= 12) {                           // SCM_RIGHTS
			size_t dl = clen - 12;
			struct cmsghdr* ch = (struct cmsghdr*)cbuf;
			ch->cmsg_len = CMSG_LEN(dl); ch->cmsg_level = SOL_SOCKET; ch->cmsg_type = SCM_RIGHTS;
			memcpy(CMSG_DATA(ch), dc + 12, dl);
			m.msg_control = cbuf; m.msg_controllen = CMSG_SPACE(dl);
		}
	}
	long r = sendmsg((int)c->a[0], &m, msg_flags((int)c->a[2]));
	return r < 0 ? err() : r;
}
static long net_recvmsg(struct ctx* c) {
	struct dmsghdr d;
	if (safe_read(c->a[1], &d, sizeof d) != sizeof d) return -D_EFAULT;
	struct msghdr m = { 0 };
	uint8_t l[128], cbuf[256];
	m.msg_name = d.name ? l : NULL; m.msg_namelen = d.name ? sizeof l : 0;
	m.msg_iov = (struct iovec*)d.iov; m.msg_iovlen = (size_t)d.iovlen;
	m.msg_control = d.control ? cbuf : NULL; m.msg_controllen = d.control ? sizeof cbuf : 0;
	long r = recvmsg((int)c->a[0], &m, msg_flags((int)c->a[2]) & ~MSG_NOSIGNAL);
	if (r < 0) return err();
	if (d.name) { uint8_t dd[128]; uint32_t dl = sa_out(l, m.msg_namelen, dd); if (dl) safe_write(d.name, dd, dl < d.namelen ? dl : d.namelen); d.namelen = dl; }
	uint32_t used = 0;
	if (d.control) {
		for (struct cmsghdr* ch = CMSG_FIRSTHDR(&m); ch; ch = CMSG_NXTHDR(&m, ch)) {
			if (ch->cmsg_level == SOL_SOCKET && ch->cmsg_type == SCM_RIGHTS) {
				size_t dl = ch->cmsg_len - CMSG_LEN(0);
				uint8_t o[256]; uint32_t clen = (uint32_t)(12 + dl); int32_t lvl = 0xffff, typ = 1;
				if (used + ((clen + 3) & ~3u) > d.controllen) break;
				memcpy(o, &clen, 4); memcpy(o + 4, &lvl, 4); memcpy(o + 8, &typ, 4); memcpy(o + 12, CMSG_DATA(ch), dl);
				safe_write(d.control + used, o, clen);
				used += (clen + 3) & ~3u;
			}
		}
	}
	d.controllen = used;
	int fl = 0;
	if (m.msg_flags & MSG_TRUNC) fl |= 0x10; if (m.msg_flags & MSG_CTRUNC) fl |= 0x20; if (m.msg_flags & MSG_EOR) fl |= 0x8;
	d.flags = fl;
	safe_write(c->a[1], &d, sizeof d);
	return r;
}

// pathconf / fpathconf: valores típicos de APFS
static long pc_value(int name) {
	switch (name) {
	case 1: return 32767; case 2: return 1024; case 3: return 1024; case 4: return 255; case 5: return 1024; case 6: return 512;
	case 7: return 1; case 8: return 1; case 9: return 255; case 18: return 64; case 13: return 1; case 14: return 1; case 15: return 1;
	default: return -1;
	}
}
static long net_pathconf(struct ctx* c) { long v = pc_value((int)c->a[1]); return v < 0 ? -D_EINVAL : v; }

// coalition(op, id*, tipo, flags): solo se emula la creación (id sintético) y la consulta
static long net_coalition(struct ctx* c) {
	static uint64_t next = 100;
	if ((int)c->a[0] == 1 /* CREATE */) { uint64_t id = ++next; if (c->a[1]) safe_write(c->a[1], &id, 8); return 0; }
	return 0;
}

void emu_net_init(void) {
	reg_bsd(97, net_socket); reg_bsd(98, net_connect); reg_bsd(409, net_connect);
	reg_bsd(104, net_bind); reg_bsd(106, net_listen); reg_bsd(30, net_accept); reg_bsd(404, net_accept);
	reg_bsd(32, net_getsockname); reg_bsd(31, net_getpeername); reg_bsd(134, net_shutdown); reg_bsd(135, net_socketpair);
	reg_bsd(105, net_setsockopt); reg_bsd(118, net_getsockopt);
	reg_bsd(133, net_sendto); reg_bsd(413, net_sendto); reg_bsd(29, net_recvfrom); reg_bsd(403, net_recvfrom);
	reg_bsd(28, net_sendmsg); reg_bsd(402, net_sendmsg); reg_bsd(27, net_recvmsg); reg_bsd(401, net_recvmsg);
	reg_bsd(191, net_pathconf); reg_bsd(192, net_pathconf);
	reg_bsd(458, net_coalition); reg_bsd(459, net_coalition); reg_bsd(532, net_coalition);   // coalition, coalition_info, coalition_ledger
}
