// IOKit: el servidor MIG de device.defs (ids 2800-2890) con un registro de E/S completo.
//
// Se incluye desde emu_mach.c (usa sus ayudas estáticas: struct hdr, reply_begin, reply_port, NDR_LE).
//
// Qué hay aquí:
//   - un árbol de entradas (clase, superclases, nombre, ubicación, propiedades) que imita el de un Mac real y que se
//     rellena con lo que Linux sabe de la máquina (DMI y GPU de /sys);
//   - dos planos (IOService, IODeviceTree) sobre ese árbol, rutas "Plano:/a/b@loc", iteradores (recursivos, hacia los
//     padres, con entrar/salir);
//   - propiedades serializadas en el formato binario de OSSerialize (el que lee IOKit.framework) y en XML;
//   - diccionarios de coincidencia (XML, binario o de la ruta OOL) y su evaluación: IOProviderClass con herencia,
//     IONameMatch, IOPropertyMatch, IOResourceMatch, IOPathMatch y claves sueltas;
//   - notificaciones (add_notification / interest): mensaje de despertar id 53 al puerto del cliente;
//   - conexiones (user clients): ganchos por clase para que el puente a DRM/Metal los atienda; sin gancho,
//     los métodos devuelven kIOReturnUnsupported.

#include <dirent.h>
#include <limits.h>

#define IOKIT_RET(x) ((int32_t)(0xe0000000u | (x)))
#define kIOReturnError        IOKIT_RET(0x2bc)
#define kIOReturnNoMemory     IOKIT_RET(0x2bd)
#define kIOReturnBadArgument  IOKIT_RET(0x2c2)
#define kIOReturnNotPrivileged IOKIT_RET(0x2c1)
#define kIOReturnUnsupported  IOKIT_RET(0x2c7)
#define kIOReturnNotFound     IOKIT_RET(0x2f0)
#define kIOReturnNoDevice     IOKIT_RET(0x2c0)
#define kIOReturnBadMedia     IOKIT_RET(0x2d0)

static size_t reply_port(uint8_t* r, const struct hdr* req, uint32_t name, uint8_t disposition);

// ------------------------------------------------------------------ valores (plist en memoria)
enum { V_DICT = 1, V_ARRAY, V_STR, V_NUM, V_BOOL, V_DATA, V_SYM };
struct val {
	int t;
	char* s;                     // cadena / datos
	size_t slen;                 // longitud de datos
	uint64_t n;                  // número / booleano
	int bits;                    // anchura del número
	int cnt, cap;                // hijos
	struct val** kid;
	char** key;                  // solo diccionarios
};
static struct val* v_new(int t) { struct val* v = calloc(1, sizeof *v); v->t = t; return v; }
static struct val* v_str(const char* s) { struct val* v = v_new(V_STR); v->s = strdup(s); v->slen = strlen(s); return v; }
static struct val* v_num(uint64_t n, int bits) { struct val* v = v_new(V_NUM); v->n = n; v->bits = bits; return v; }
static struct val* v_bool(int b) { struct val* v = v_new(V_BOOL); v->n = b != 0; return v; }
static struct val* v_data(const void* d, size_t len) { struct val* v = v_new(V_DATA); v->s = malloc(len ? len : 1); memcpy(v->s, d, len); v->slen = len; return v; }
static void v_add(struct val* c, const char* key, struct val* kid) {
	if (c->cnt == c->cap) {
		c->cap = c->cap ? c->cap * 2 : 8;
		c->kid = realloc(c->kid, c->cap * sizeof *c->kid);
		c->key = realloc(c->key, c->cap * sizeof *c->key);
	}
	c->kid[c->cnt] = kid; c->key[c->cnt] = key ? strdup(key) : NULL; c->cnt++;
}
static struct val* v_get(const struct val* d, const char* key) {
	if (!d || d->t != V_DICT) return NULL;
	for (int i = 0; i < d->cnt; i++) if (!strcmp(d->key[i], key)) return d->kid[i];
	return NULL;
}
static void v_set(struct val* d, const char* key, struct val* kid) {
	for (int i = 0; i < d->cnt; i++) if (!strcmp(d->key[i], key)) { d->kid[i] = kid; return; }
	v_add(d, key, kid);
}
static int v_equal(const struct val* a, const struct val* b) {
	if (!a || !b) return 0;
	int ta = a->t == V_SYM ? V_STR : a->t, tb = b->t == V_SYM ? V_STR : b->t;
	if (ta != tb) return 0;
	switch (ta) {
	case V_STR: return a->slen == b->slen && !memcmp(a->s, b->s, a->slen);
	case V_DATA: return a->slen == b->slen && !memcmp(a->s, b->s, a->slen);
	case V_NUM: case V_BOOL: return a->n == b->n;
	case V_ARRAY: if (a->cnt != b->cnt) return 0; for (int i = 0; i < a->cnt; i++) if (!v_equal(a->kid[i], b->kid[i])) return 0; return 1;
	case V_DICT: for (int i = 0; i < b->cnt; i++) if (!v_equal(v_get(a, b->key[i]), b->kid[i])) return 0; return 1;   // subconjunto
	}
	return 0;
}

// ---- serialización binaria (libkern/c++/OSSerializeBinary.cpp)
struct sbuf { uint8_t* p; size_t n, cap; };
static void sb_put(struct sbuf* b, const void* d, size_t len) {
	if (b->n + len > b->cap) { b->cap = (b->n + len) * 2 + 256; b->p = realloc(b->p, b->cap); }
	memcpy(b->p + b->n, d, len); b->n += len;
}
static void sb_u32(struct sbuf* b, uint32_t v) { sb_put(b, &v, 4); }
static void sb_pad(struct sbuf* b, size_t len) { static const uint8_t z[4] = { 0 }; if (len & 3) sb_put(b, z, 4 - (len & 3)); }
#define OSS_DICT 0x01000000u
#define OSS_ARRAY 0x02000000u
#define OSS_NUMBER 0x04000000u
#define OSS_SYMBOL 0x08000000u
#define OSS_STRING 0x09000000u
#define OSS_DATA 0x0a000000u
#define OSS_BOOL 0x0b000000u
#define OSS_END 0x80000000u
static void bin_ser(struct sbuf* b, const struct val* v, int last) {
	uint32_t e = last ? OSS_END : 0;
	switch (v->t) {
	case V_DICT:
		sb_u32(b, OSS_DICT | (uint32_t)v->cnt | e);
		for (int i = 0; i < v->cnt; i++) {
			uint32_t kl = (uint32_t)strlen(v->key[i]) + 1;
			sb_u32(b, OSS_SYMBOL | kl); sb_put(b, v->key[i], kl); sb_pad(b, kl);
			bin_ser(b, v->kid[i], i == v->cnt - 1);
		}
		break;
	case V_ARRAY:
		sb_u32(b, OSS_ARRAY | (uint32_t)v->cnt | e);
		for (int i = 0; i < v->cnt; i++) bin_ser(b, v->kid[i], i == v->cnt - 1);
		break;
	case V_NUM: sb_u32(b, OSS_NUMBER | (uint32_t)v->bits | e); sb_put(b, &v->n, 8); break;
	case V_BOOL: sb_u32(b, OSS_BOOL | (uint32_t)v->n | e); break;
	case V_STR: case V_SYM: sb_u32(b, OSS_STRING | (uint32_t)v->slen | e); sb_put(b, v->s, v->slen); sb_pad(b, v->slen); break;
	case V_DATA: sb_u32(b, OSS_DATA | (uint32_t)v->slen | e); sb_put(b, v->s, v->slen); sb_pad(b, v->slen); break;
	}
}
static void bin_ser_top(struct sbuf* b, const struct val* v) { static const uint8_t sig[4] = { 0xd3, 0, 0, 0 }; sb_put(b, sig, 4); bin_ser(b, v, 1); }

// ---- serialización XML (OSSerialize clásico)
static void sb_str(struct sbuf* b, const char* s) { sb_put(b, s, strlen(s)); }
static void sb_esc(struct sbuf* b, const char* s, size_t n) {
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '<') sb_str(b, "&lt;"); else if (s[i] == '>') sb_str(b, "&gt;"); else if (s[i] == '&') sb_str(b, "&amp;"); else sb_put(b, s + i, 1);
	}
}
static void xml_ser(struct sbuf* b, const struct val* v) {
	char t[64];
	switch (v->t) {
	case V_DICT:
		sb_str(b, "<dict>");
		for (int i = 0; i < v->cnt; i++) { sb_str(b, "<key>"); sb_esc(b, v->key[i], strlen(v->key[i])); sb_str(b, "</key>"); xml_ser(b, v->kid[i]); }
		sb_str(b, "</dict>");
		break;
	case V_ARRAY: sb_str(b, "<array>"); for (int i = 0; i < v->cnt; i++) xml_ser(b, v->kid[i]); sb_str(b, "</array>"); break;
	case V_NUM: snprintf(t, sizeof t, "<integer size=\"%d\">0x%llx</integer>", v->bits, (unsigned long long)v->n); sb_str(b, t); break;
	case V_BOOL: sb_str(b, v->n ? "<true/>" : "<false/>"); break;
	case V_STR: case V_SYM: sb_str(b, "<string>"); sb_esc(b, v->s, v->slen); sb_str(b, "</string>"); break;
	case V_DATA: {
		static const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		sb_str(b, "<data>");
		for (size_t i = 0; i < v->slen; i += 3) {
			uint32_t x = (uint8_t)v->s[i] << 16 | (i + 1 < v->slen ? (uint8_t)v->s[i + 1] << 8 : 0) | (i + 2 < v->slen ? (uint8_t)v->s[i + 2] : 0);
			char o[4] = { a[x >> 18 & 63], a[x >> 12 & 63], i + 1 < v->slen ? a[x >> 6 & 63] : '=', i + 2 < v->slen ? a[x & 63] : '=' };
			sb_put(b, o, 4);
		}
		sb_str(b, "</data>");
		break;
	}
	}
}

// ---- lectura: binario (los contadores de cada colección bastan; la marca END se ignora)
static struct val* bin_parse(const uint8_t* p, size_t len) {
	if (len < 8 || p[0] != 0xd3) return NULL;
	size_t pos = 4;
	struct { struct val* v; int left; int isdict; char* key; } st[64];
	int sp = 0; struct val* root = NULL;
	for (;;) {
		if (pos + 4 > len) return root;
		uint32_t k; memcpy(&k, p + pos, 4); pos += 4;
		uint32_t type = k & 0x7f000000u, n = k & 0x00ffffffu;
		struct val* o = NULL; int coll = 0;
		switch (type) {
		case OSS_DICT: o = v_new(V_DICT); coll = 1; break;
		case OSS_ARRAY: case 0x03000000u: o = v_new(V_ARRAY); coll = 1; break;
		case OSS_NUMBER: { if (pos + 8 > len) return root; uint64_t x; memcpy(&x, p + pos, 8); pos += 8; o = v_num(x, (int)n); break; }
		case OSS_SYMBOL: case OSS_STRING: {
			if (pos + ((n + 3) & ~3u) > len) return root;
			size_t ln = (type == OSS_SYMBOL && n) ? n - 1 : n;
			o = v_new(type == OSS_SYMBOL ? V_SYM : V_STR); o->s = strndup((const char*)p + pos, ln); o->slen = ln; pos += (n + 3) & ~3u; break;
		}
		case OSS_DATA: if (pos + ((n + 3) & ~3u) > len) return root; o = v_data(p + pos, n); pos += (n + 3) & ~3u; break;
		case OSS_BOOL: o = v_bool(n != 0); break;
		case 0x0c000000u: o = v_bool(0); break;                  // referencia a un objeto anterior: no se usa en las consultas
		default: return root;
		}
		if (!root) root = o;
		else if (sp) {
			if (st[sp - 1].isdict && !st[sp - 1].key) { st[sp - 1].key = o->s ? o->s : strdup(""); continue; }   // clave
			v_add(st[sp - 1].v, st[sp - 1].isdict ? st[sp - 1].key : NULL, o);
			st[sp - 1].key = NULL; st[sp - 1].left--;
		}
		if (coll && n) { if (sp == 64) return root; st[sp].v = o; st[sp].left = (int)n; st[sp].isdict = type == OSS_DICT; st[sp].key = NULL; sp++; }
		while (sp && st[sp - 1].left <= 0) sp--;
		if (!sp) return root;
	}
}

// ---- lectura: XML (subconjunto suficiente para diccionarios de coincidencia)
struct xp { const char* p; const char* e; };
static void xp_ws(struct xp* x) { while (x->p < x->e && (*x->p == ' ' || *x->p == '\n' || *x->p == '\t' || *x->p == '\r')) x->p++; }
static int xp_tag(struct xp* x, char* name, size_t nl, int* closing, int* selfclose, const char** attrs) {
	xp_ws(x);
	if (x->p >= x->e || *x->p != '<') return 0;
	x->p++;
	*closing = 0; *selfclose = 0; *attrs = NULL;
	if (x->p < x->e && *x->p == '/') { *closing = 1; x->p++; }
	if (x->p < x->e && (*x->p == '?' || *x->p == '!')) { while (x->p < x->e && *x->p != '>') x->p++; if (x->p < x->e) x->p++; name[0] = 0; return 1; }
	size_t i = 0;
	while (x->p < x->e && *x->p != '>' && *x->p != ' ' && *x->p != '/' ) { if (i + 1 < nl) name[i++] = *x->p; x->p++; }
	name[i] = 0;
	if (x->p < x->e && *x->p == ' ') *attrs = x->p;
	while (x->p < x->e && *x->p != '>') { if (*x->p == '/') *selfclose = 1; x->p++; }
	if (x->p < x->e) x->p++;
	return 1;
}
static char* xp_text(struct xp* x) {
	const char* s = x->p;
	while (x->p < x->e && *x->p != '<') x->p++;
	size_t n = (size_t)(x->p - s);
	char* o = malloc(n + 1); size_t j = 0;
	for (size_t i = 0; i < n; i++) {
		if (s[i] == '&') {
			if (!strncmp(s + i, "&lt;", 4)) { o[j++] = '<'; i += 3; } else if (!strncmp(s + i, "&gt;", 4)) { o[j++] = '>'; i += 3; }
			else if (!strncmp(s + i, "&amp;", 5)) { o[j++] = '&'; i += 4; } else o[j++] = s[i];
		} else o[j++] = s[i];
	}
	o[j] = 0; return o;
}
static struct val* xml_value(struct xp* x, const char* tagname, const char* attrs, int selfclose);
static struct val* xml_next(struct xp* x) {
	char nm[32]; int cl, sc; const char* at;
	for (;;) { if (!xp_tag(x, nm, sizeof nm, &cl, &sc, &at)) return NULL; if (nm[0] && !cl) break; if (cl) return NULL; }
	return xml_value(x, nm, at, sc);
}
static struct val* xml_value(struct xp* x, const char* t, const char* attrs, int sc) {
	char nm[32]; int cl, sc2; const char* at;
	if (!strcmp(t, "true")) return v_bool(1);
	if (!strcmp(t, "false")) return v_bool(0);
	if (!strcmp(t, "dict") || !strcmp(t, "array") || !strcmp(t, "set")) {
		int isd = !strcmp(t, "dict");
		struct val* c = v_new(isd ? V_DICT : V_ARRAY);
		if (sc) return c;
		for (;;) {
			xp_ws(x);
			const char* save = x->p;
			if (!xp_tag(x, nm, sizeof nm, &cl, &sc2, &at)) return c;
			if (cl) return c;                                           // </dict>
			if (isd) {
				if (strcmp(nm, "key")) { x->p = save; return c; }
				char* k = xp_text(x); xp_tag(x, nm, sizeof nm, &cl, &sc2, &at);   // </key>
				struct val* v = xml_next(x);
				if (!v) { free(k); return c; }
				v_add(c, k, v); free(k);
			} else { struct val* v = xml_value(x, nm, at, sc2); if (!v) return c; v_add(c, NULL, v); }
		}
	}
	char* txt = sc ? strdup("") : xp_text(x);
	if (!sc) xp_tag(x, nm, sizeof nm, &cl, &sc2, &at);                 // cierre
	struct val* v = NULL;
	if (!strcmp(t, "string") || !strcmp(t, "key")) { v = v_str(txt); }
	else if (!strcmp(t, "integer") || !strcmp(t, "number")) {
		int bits = 64; const char* sz = attrs ? strstr(attrs, "size=\"") : NULL;
		if (sz) bits = atoi(sz + 6);
		v = v_num(strtoull(txt, NULL, 0), bits);
	} else if (!strcmp(t, "data")) {
		uint8_t* o = malloc(strlen(txt) + 1); size_t j = 0; uint32_t acc = 0; int nb = 0;
		for (char* c = txt; *c; c++) {
			int d = (*c >= 'A' && *c <= 'Z') ? *c - 'A' : (*c >= 'a' && *c <= 'z') ? *c - 'a' + 26 : (*c >= '0' && *c <= '9') ? *c - '0' + 52 : *c == '+' ? 62 : *c == '/' ? 63 : -1;
			if (d < 0) continue;
			acc = acc << 6 | (uint32_t)d; nb += 6;
			if (nb >= 8) { nb -= 8; o[j++] = (uint8_t)(acc >> nb); }
		}
		v = v_data(o, j); free(o);
	} else v = v_str(txt);
	free(txt);
	return v;
}
static struct val* xml_parse(const char* s, size_t len) { struct xp x = { s, s + len }; return xml_next(&x); }
static struct val* any_parse(const uint8_t* p, size_t len) {
	if (len && p[0] == 0xd3) return bin_parse(p, len);
	return xml_parse((const char*)p, len);
}

// ------------------------------------------------------------------ el registro
#define IO_MAXENT 96
enum { PL_SERVICE = 1, PL_DT = 2 };
struct ioent {
	const char* name; const char* cls; const char* supers;   // supers: nombres separados por espacios, de la más cercana a la raíz
	char loc[24];
	int parent; int planes; int uc;                          // uc: admite conexiones (user client)
	uint64_t id; struct val* props; int busy;
};
static struct ioent io_e[IO_MAXENT];
static int io_ne;
static int io_inited;
static uint64_t io_next_id = 0x100000100ULL;

static int ent_add(int parent, const char* name, const char* cls, const char* supers, const char* loc, int planes, int uc) {
	int i = io_ne++;
	struct ioent* e = &io_e[i];
	e->name = name; e->cls = cls; e->supers = supers; e->parent = parent; e->planes = planes; e->uc = uc;
	snprintf(e->loc, sizeof e->loc, "%s", loc ? loc : "");
	e->id = io_next_id; io_next_id += 0x10;
	e->props = v_new(V_DICT);
	return i;
}
static void p_str(int i, const char* k, const char* v) { v_set(io_e[i].props, k, v_str(v)); }
static void p_num(int i, const char* k, uint64_t v, int bits) { v_set(io_e[i].props, k, v_num(v, bits)); }
static void p_bool(int i, const char* k, int v) { v_set(io_e[i].props, k, v_bool(v)); }
static void p_data(int i, const char* k, const void* d, size_t n) { v_set(io_e[i].props, k, v_data(d, n)); }
static void p_cstr(int i, const char* k, const char* v) { p_data(i, k, v, strlen(v) + 1); }   // dato con cadena y NUL (estilo árbol de dispositivos)
static void p_u32(int i, const char* k, uint32_t v) { p_data(i, k, &v, 4); }

static int rd_sys(const char* path, char* out, size_t n) {
	FILE* f = fopen(path, "r");
	if (!f) return 0;
	if (!fgets(out, (int)n, f)) { fclose(f); return 0; }
	fclose(f);
	out[strcspn(out, "\n")] = 0;
	return 1;
}

static void io_init(void) {
	if (io_inited) return;
	io_inited = 1;
	char gv[32] = "0x8086", gd[32] = "0x0a16", dmi[64] = "";
	rd_sys("/sys/class/drm/card0/device/vendor", gv, sizeof gv);
	rd_sys("/sys/class/drm/card0/device/device", gd, sizeof gd);
	rd_sys("/sys/class/dmi/id/product_name", dmi, sizeof dmi);
	uint32_t vendor = (uint32_t)strtoul(gv, NULL, 0), device = (uint32_t)strtoul(gd, NULL, 0);
	long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	uint64_t mem = (uint64_t)sysconf(_SC_PHYS_PAGES) * (uint64_t)sysconf(_SC_PAGESIZE);

	int root = ent_add(-1, "Root", "IORegistryEntry", "", "", PL_SERVICE | PL_DT, 0);
	p_str(root, "IORegistryPlanes", "IOService");
	int plat = ent_add(root, "MacBookPro16,1", "IOPlatformExpertDevice", "IORegistryEntry IOService", "", PL_SERVICE | PL_DT, 1);
	p_cstr(plat, "name", "/");
	p_cstr(plat, "model", "MacBookPro16,1");
	p_data(plat, "compatible", "MacBookPro16,1\0J152F\0AppleACPI", 28);
	p_cstr(plat, "manufacturer", "Apple Inc.");
	p_cstr(plat, "board-id", "Mac-E1008331FDC96864");
	p_cstr(plat, "product-name", "MacBookPro16,1");
	p_cstr(plat, "target-type", "J152F");
	p_cstr(plat, "device_type", "bridge");
	p_str(plat, "IOPlatformUUID", "00000000-0000-1000-8000-000000000001");
	p_str(plat, "IOPlatformSerialNumber", "C02TAHOE0001");
	p_str(plat, "serial-number-string", "C02TAHOE0001");
	p_str(plat, "IOPlatformSystemSleepPolicy", "none");
	p_str(plat, "IOBusyInterest", "IOCommand is not serializable");
	p_bool(plat, "IOKitDiagnostics", 0);
	p_u32(plat, "clock-frequency", 0);
	p_u32(plat, "#address-cells", 2); p_u32(plat, "#size-cells", 2);
	p_str(plat, "IOPolledInterface", "none");
	v_set(io_e[plat].props, "IOPlatformUUID", v_str("00000000-0000-1000-8000-000000000001"));
	(void)dmi;

	int acpi = ent_add(plat, "AppleACPIPlatformExpert", "AppleACPIPlatformExpert", "IORegistryEntry IOService IOPlatformExpert", "", PL_SERVICE, 1);
	p_str(acpi, "IOClass", "AppleACPIPlatformExpert");
	int pm = ent_add(acpi, "IOPMrootDomain", "IOPMrootDomain", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(pm, "IOClass", "IOPMrootDomain");
	int res = ent_add(root, "IOResources", "IOResources", "IORegistryEntry IOService", "", PL_SERVICE, 0);
	p_str(res, "IOClass", "IOResources");
	for (int i = 0; i < 0; i++) {}

	int opt = ent_add(plat, "options", "IODTNVRAM", "IORegistryEntry IOService", "", PL_SERVICE | PL_DT, 1);
	p_cstr(opt, "name", "options");
	p_data(opt, "boot-args", "", 1);
	int chosen = ent_add(plat, "chosen", "IOService", "IORegistryEntry", "", PL_SERVICE | PL_DT, 0);
	p_cstr(chosen, "name", "chosen");
	p_data(chosen, "boot-uuid", "00000000-0000-1000-8000-000000000002", 37);
	int cpus = ent_add(plat, "cpus", "IOService", "IORegistryEntry", "", PL_DT, 0);
	p_cstr(cpus, "name", "cpus");
	for (long c = 0; c < ncpu && c < 16; c++) {
		static char names[16][8], locs[16][8];
		snprintf(names[c], sizeof names[c], "CPU%ld", c); snprintf(locs[c], sizeof locs[c], "%lx", c);
		int ci = ent_add(cpus, names[c], "IOCPU", "IORegistryEntry IOService", locs[c], PL_DT, 0);
		p_cstr(ci, "device_type", "cpu");
		p_u32(ci, "clock-frequency", 2400000000u);
	}
	int memory = ent_add(plat, "memory", "IOService", "IORegistryEntry", "", PL_DT, 0);
	p_cstr(memory, "device_type", "memory");
	p_data(memory, "size", &mem, 8);

	int pci = ent_add(acpi, "PCI0", "IOPCIBridge", "IORegistryEntry IOService", "", PL_SERVICE | PL_DT, 0);
	p_cstr(pci, "device_type", "pci");
	int gpu = ent_add(pci, "IGPU", "IOPCIDevice", "IORegistryEntry IOService", "20000", PL_SERVICE | PL_DT, 1);
	p_u32(gpu, "vendor-id", vendor); p_u32(gpu, "device-id", device);
	p_u32(gpu, "class-code", 0x030000);
	p_cstr(gpu, "IOName", "display"); p_cstr(gpu, "name", "display"); p_cstr(gpu, "device_type", "display");
	p_cstr(gpu, "model", vendor == 0x8086 ? "Intel Graphics" : "GPU");
	char compat[64]; snprintf(compat, sizeof compat, "pci%x,%x", vendor, device);
	p_cstr(gpu, "compatible", compat);
	p_str(gpu, "IOPCIClassMatch", "0x03000000&0xff000000");
	p_str(gpu, "IOPCIMatch", compat);
	p_bool(gpu, "IOPCIExpressLinkStatus", 1);
	p_str(gpu, "IOProviderClass", "IOPCIDevice");
	int accel = ent_add(gpu, "AppleIntelFramebuffer", "AppleIntelFramebuffer", "IORegistryEntry IOService IOFramebuffer", "0", PL_SERVICE, 1);
	p_str(accel, "IOClass", "AppleIntelFramebuffer");
	p_str(accel, "IOProviderClass", "IOPCIDevice");
	int accl = ent_add(gpu, "IOAccelerator", "IOAccelerator", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(accl, "IOClass", "IOAccelerator");
	p_str(accl, "IOVARendererID", "0x00000000");
	int disp = ent_add(accel, "AppleDisplay", "IODisplay", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(disp, "IOClass", "AppleDisplay");
	int wr = ent_add(plat, "IODisplayWrangler", "IODisplayWrangler", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(wr, "IOClass", "IODisplayWrangler");

	int hid = ent_add(res, "IOHIDSystem", "IOHIDSystem", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(hid, "IOClass", "IOHIDSystem");
	int kbd = ent_add(acpi, "AppleACPIPS2Keyboard", "IOHIDDevice", "IORegistryEntry IOService", "", PL_SERVICE, 0);
	p_num(kbd, "PrimaryUsagePage", 1, 32); p_num(kbd, "PrimaryUsage", 6, 32); p_num(kbd, "DeviceUsagePage", 1, 32); p_num(kbd, "DeviceUsage", 6, 32);
	p_str(kbd, "Product", "Apple Internal Keyboard / Trackpad");
	p_num(kbd, "VendorID", 0x5ac, 32); p_num(kbd, "ProductID", 0x27e, 32); p_str(kbd, "Transport", "USB");
	int ptr = ent_add(acpi, "AppleACPIPS2Mouse", "IOHIDDevice", "IORegistryEntry IOService", "", PL_SERVICE, 0);
	p_num(ptr, "PrimaryUsagePage", 1, 32); p_num(ptr, "PrimaryUsage", 2, 32); p_num(ptr, "DeviceUsagePage", 1, 32); p_num(ptr, "DeviceUsage", 2, 32);
	p_str(ptr, "Product", "Apple Internal Keyboard / Trackpad");
	p_num(ptr, "VendorID", 0x5ac, 32); p_num(ptr, "ProductID", 0x27e, 32); p_str(ptr, "Transport", "USB");

	int batt = ent_add(acpi, "AppleSmartBattery", "AppleSmartBattery", "IORegistryEntry IOService IOPMPowerSource", "", PL_SERVICE, 1);
	p_bool(batt, "ExternalConnected", 1); p_bool(batt, "IsCharging", 0); p_bool(batt, "FullyCharged", 1);
	p_num(batt, "CurrentCapacity", 100, 32); p_num(batt, "MaxCapacity", 100, 32); p_num(batt, "CycleCount", 1, 32);
	int keys = ent_add(res, "AppleKeyStore", "AppleKeyStore", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(keys, "IOClass", "AppleKeyStore");
	int smc = ent_add(acpi, "AppleSMC", "AppleSMC", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(smc, "IOClass", "AppleSMC");
	int media = ent_add(root, "Macintosh HD", "IOMedia", "IORegistryEntry IOService", "", PL_SERVICE, 0);
	p_str(media, "BSD Name", "disk1s1"); p_bool(media, "Leaf", 1); p_bool(media, "Whole", 0); p_bool(media, "Writable", 0);
	p_str(media, "Content", "41504653-0000-11AA-AA11-00306543ECAC"); p_num(media, "Size", 0x3b9aca00ULL, 64);
	int whole = ent_add(root, "Tahoe Disk", "IOMedia", "IORegistryEntry IOService", "", PL_SERVICE, 0);
	p_str(whole, "BSD Name", "disk0"); p_bool(whole, "Whole", 1); p_bool(whole, "Leaf", 0); p_bool(whole, "Writable", 0);
	int cred = ent_add(res, "AppleCredentialManager", "AppleCredentialManager", "IORegistryEntry IOService", "", PL_SERVICE, 1);
	p_str(cred, "IOClass", "AppleCredentialManager");
	int usbc = ent_add(pci, "XHC1", "IOPCIDevice", "IORegistryEntry IOService", "140000", PL_SERVICE | PL_DT, 0);
	p_cstr(usbc, "name", "XHC1"); p_u32(usbc, "class-code", 0x0c0330);
	(void)gpu;
}

static int ent_in(int i, int plane) { return io_e[i].planes & plane; }
static int ent_parent(int i, int plane) { int p = io_e[i].parent; while (p >= 0 && !ent_in(p, plane)) p = io_e[p].parent; return p; }
static int ent_conforms(int i, const char* cls) {
	if (!strcmp(io_e[i].cls, cls)) return 1;
	const char* s = io_e[i].supers;
	size_t cl = strlen(cls);
	while (*s) {
		const char* e = strchr(s, ' ');
		size_t n = e ? (size_t)(e - s) : strlen(s);
		if (n == cl && !strncmp(s, cls, n)) return 1;
		if (!e) break;
		s = e + 1;
	}
	return 0;
}
static int plane_of(const char* name) { return !strcmp(name, "IODeviceTree") ? PL_DT : !strcmp(name, "IOService") ? PL_SERVICE : 0; }
static const char* ent_name_in_plane(int i, int plane) {
	if (plane == PL_DT && io_e[i].parent == -1) return "Root";
	if (plane == PL_DT) { struct val* n = v_get(io_e[i].props, "name"); if (n && n->t == V_DATA) return n->s; }
	return io_e[i].name;
}

// ruta completa en el plano: "IOService:/MacBookPro16,1/AppleACPIPlatformExpert/..."; en IODeviceTree "/" es la plataforma
static void ent_path(int i, int plane, char* out, size_t n) {
	int top = plane == PL_DT ? 1 : 0;
	snprintf(out, n, "%s:", plane == PL_DT ? "IODeviceTree" : "IOService");
	size_t len = strlen(out);
	int chain[32], k = 0;
	for (int c = i; c >= 0 && c != top && k < 32; c = ent_parent(c, plane)) chain[k++] = c;
	if (!k) { snprintf(out + len, n - len, "/"); return; }
	for (int j = k - 1; j >= 0 && len < n; j--) {
		int c = chain[j];
		len += snprintf(out + len, n - len, "/%s%s%s", ent_name_in_plane(c, plane), io_e[c].loc[0] ? "@" : "", io_e[c].loc);
	}
}
static int ent_child_match(int parent, int plane, const char* comp) {
	for (int i = 0; i < io_ne; i++) {
		if (!ent_in(i, plane) || ent_parent(i, plane) != parent) continue;
		char full[96]; snprintf(full, sizeof full, "%s%s%s", ent_name_in_plane(i, plane), io_e[i].loc[0] ? "@" : "", io_e[i].loc);
		if (!strcmp(full, comp) || !strcmp(ent_name_in_plane(i, plane), comp)) return i;
	}
	return -1;
}
static int ent_from_path(const char* path) {
	io_init();
	const char* colon = strchr(path, ':');
	int plane = PL_SERVICE;
	if (colon) {
		char pn[32]; size_t n = (size_t)(colon - path); if (n >= sizeof pn) return -1;
		memcpy(pn, path, n); pn[n] = 0;
		plane = plane_of(pn);
		if (!plane) return -1;
		path = colon + 1;
	}
	int cur = plane == PL_DT ? 1 : 0;                                  // Root, o la plataforma en IODeviceTree
	char buf[512]; snprintf(buf, sizeof buf, "%s", path);
	char* sv = NULL;
	for (char* c = strtok_r(buf, "/", &sv); c; c = strtok_r(NULL, "/", &sv)) {
		if (!*c) continue;
		int nx = ent_child_match(cur, plane, c);
		if (nx < 0) return -1;
		cur = nx;
	}
	return cur;
}

// ------------------------------------------------------------------ objetos (puertos del cliente)
enum { K_ENTRY = 1, K_ITER, K_NOTIF, K_CONNECT };
struct ioiter { int* list; int n, pos; int plane; int cur; struct { int* list; int n, pos; } stk[8]; int depth; int valid; };
struct ioobj {
	uint32_t port; int kind;
	int ent;
	struct ioiter* it;
	struct val* match; int notif_type; uint32_t wake; uint64_t ref[8]; int nref;   // notificaciones
	int ctype; int closed;                                                         // conexiones
};
#define IO_MAXOBJ 2048
static struct ioobj io_o[IO_MAXOBJ];
static int io_no;
static uint32_t io_ent_port[IO_MAXENT];

static struct ioobj* obj_by_port(uint32_t p) { for (int i = 0; i < io_no; i++) if (io_o[i].port == p) return &io_o[i]; return NULL; }
static struct ioobj* obj_new(int kind) {
	if (io_no == IO_MAXOBJ) return NULL;
	struct ioobj* o = &io_o[io_no++];
	memset(o, 0, sizeof *o);
	o->port = alloc_port(); o->kind = kind; o->ent = -1;
	return o;
}
static uint32_t ent_handle(int i) {
	if (!io_ent_port[i]) { struct ioobj* o = obj_new(K_ENTRY); if (!o) return 0; o->ent = i; io_ent_port[i] = o->port; }
	return io_ent_port[i];
}
static int obj_ent(uint32_t port) { struct ioobj* o = obj_by_port(port); return (o && (o->kind == K_ENTRY || o->kind == K_CONNECT) && o->ent >= 0) ? o->ent : -1; }

// ------------------------------------------------------------------ coincidencias
static int name_matches(int i, const char* want) {
	if (!strcmp(io_e[i].name, want)) return 1;
	struct val* n = v_get(io_e[i].props, "IOName");
	if (n && n->t == V_STR && !strcmp(n->s, want)) return 1;
	n = v_get(io_e[i].props, "name");
	if (n && n->t == V_DATA && !strcmp(n->s, want)) return 1;
	n = v_get(io_e[i].props, "compatible");
	if (n && n->t == V_DATA) for (size_t o = 0; o < n->slen; o += strlen(n->s + o) + 1) if (!strcmp(n->s + o, want)) return 1;
	return 0;
}
static int match_entry(int i, const struct val* m);
static int match_one(int i, const char* key, const struct val* v) {
	if (!strcmp(key, "IOProviderClass")) return v->t == V_STR ? ent_conforms(i, v->s) : 0;
	if (!strcmp(key, "IONameMatch")) {
		if (v->t == V_STR) return name_matches(i, v->s);
		if (v->t == V_ARRAY) { for (int k = 0; k < v->cnt; k++) if (v->kid[k]->t == V_STR && name_matches(i, v->kid[k]->s)) return 1; return 0; }
		return 0;
	}
	if (!strcmp(key, "IOPropertyMatch")) {
		if (v->t != V_DICT) return 1;
		for (int k = 0; k < v->cnt; k++) if (!v_equal(v_get(io_e[i].props, v->key[k]), v->kid[k])) return 0;
		return 1;
	}
	if (!strcmp(key, "IOResourceMatch")) return !strcmp(io_e[i].cls, "IOResources");
	if (!strcmp(key, "IOPathMatch")) return v->t == V_STR && ent_from_path(v->s) == i;
	if (!strcmp(key, "IOParentMatch")) { int p = io_e[i].parent; return p >= 0 && (v->t != V_DICT || match_entry(p, v)); }
	// claves de arranque / control que no restringen
	static const char* ign[] = { "IOMatchCategory", "IOProbeScore", "IOUserClientClass", "IOUserClass", "CFBundleIdentifier", "IOKitDebug", "IOPCIMatch",
		"IOPCIPrimaryMatch", "IOPCISecondaryMatch", "IOPCIClassMatch", "IOProviderClassMatch", "IOPassiveMatch", "IOMatchedAtBoot", "IOPersonalityPublisher", "IOSupportedConnect", NULL };
	for (int k = 0; ign[k]; k++) if (!strcmp(key, ign[k])) return 1;
	return v_equal(v_get(io_e[i].props, key), v);                      // clave suelta: debe coincidir como propiedad
}
static int match_entry(int i, const struct val* m) {
	if (!m || m->t != V_DICT) return 0;
	for (int k = 0; k < m->cnt; k++) if (!match_one(i, m->key[k], m->kid[k])) return 0;
	return 1;
}
static int match_all(const struct val* m, int* out, int max) {
	int n = 0;
	for (int i = 0; i < io_ne && n < max; i++) if (ent_in(i, PL_SERVICE) && match_entry(i, m)) out[n++] = i;
	return n;
}

// ------------------------------------------------------------------ iteradores
static void iter_collect(int ent, int plane, int options, int** out, int* n) {
	int cap = 16; *out = malloc(cap * sizeof(int)); *n = 0;
#define PUSH(x) do { if (*n == cap) { cap *= 2; *out = realloc(*out, cap * sizeof(int)); } (*out)[(*n)++] = (x); } while (0)
	if (options & 2) {                                                  // hacia los padres
		for (int p = ent_parent(ent, plane); p >= 0; p = ent_parent(p, plane)) { PUSH(p); if (!(options & 1)) break; }
		return;
	}
	int stack[64], sp = 0, depthmax = (options & 1) ? 64 : 1;
	// DFS con profundidad: recorrido en preorden
	struct { int e, d; } st[256]; int top = 0;
	for (int i = io_ne - 1; i >= 0; i--) if (ent_in(i, plane) && ent_parent(i, plane) == ent && top < 256) { st[top].e = i; st[top].d = 1; top++; }
	(void)stack; (void)sp;
	while (top) {
		top--; int e = st[top].e, d = st[top].d;
		PUSH(e);
		if (d < depthmax) for (int i = io_ne - 1; i >= 0; i--) if (ent_in(i, plane) && ent_parent(i, plane) == e && top < 256) { st[top].e = i; st[top].d = d + 1; top++; }
	}
}
static struct ioobj* iter_new(int* list, int n, int plane) {
	struct ioobj* o = obj_new(K_ITER);
	if (!o) return NULL;
	o->it = calloc(1, sizeof *o->it);
	o->it->list = list; o->it->n = n; o->it->plane = plane; o->it->valid = 1; o->it->cur = -1;
	return o;
}

// ------------------------------------------------------------------ lectura de peticiones
struct rq { const uint8_t* b; size_t p, len; uint32_t port[4]; int nport; uint64_t ool_addr[2]; uint32_t ool_size[2]; int nool; };
static void rq_init(struct rq* r, const struct hdr* h, const uint8_t* req) {
	memset(r, 0, sizeof *r);
	r->b = req; r->p = 24; r->len = h->size;
	if (h->bits & 0x80000000u) {
		uint32_t cnt; memcpy(&cnt, req + 24, 4);
		r->p = 28;
		for (uint32_t i = 0; i < cnt && r->p + 12 <= r->len; i++) {
			uint8_t type = req[r->p + 11];
			if (type == 0) { if (r->nport < 4) memcpy(&r->port[r->nport++], req + r->p, 4); r->p += 12; }
			else { if (r->nool < 2) { memcpy(&r->ool_addr[r->nool], req + r->p, 8); memcpy(&r->ool_size[r->nool], req + r->p + 12, 4); r->nool++; } r->p += 16; }
		}
	}
}
static void rq_ndr(struct rq* r) { r->p += 8; }
static uint32_t rq_u32(struct rq* r) { uint32_t v = 0; if (r->p + 4 <= r->len) memcpy(&v, r->b + r->p, 4); r->p += 4; return v; }
static uint64_t rq_u64(struct rq* r) { uint64_t v = 0; if (r->p + 8 <= r->len) memcpy(&v, r->b + r->p, 8); r->p += 8; return v; }
static const char* rq_str(struct rq* r) {                                // c_string[*:N]: desplazamiento, cuenta y bytes
	static __thread char tmp[4100];
	rq_u32(r); uint32_t n = rq_u32(r);
	if (n > 4096 || r->p + n > r->len) { tmp[0] = 0; r->p = r->len; return tmp; }
	memcpy(tmp, r->b + r->p, n); tmp[n] = 0;
	r->p += (n + 3) & ~3u;
	return tmp;
}
static const uint8_t* rq_bytes(struct rq* r, uint32_t* n) {              // array[*:N] of char: cuenta y bytes
	*n = rq_u32(r);
	if (*n > 4096 || r->p + *n > r->len) { *n = 0; return (const uint8_t*)""; }
	const uint8_t* p = r->b + r->p; r->p += (*n + 3) & ~3u; return p;
}
static struct val* rq_match_ool(struct rq* r) {                          // io_buf_ptr_t: la memoria está en este proceso
	if (!r->nool || !r->ool_size[0]) return NULL;
	return any_parse((const uint8_t*)r->ool_addr[0], r->ool_size[0]);
}

// ------------------------------------------------------------------ construcción de respuestas
static size_t rp_str(uint8_t* r, size_t off, const char* s) {
	uint32_t cnt = (uint32_t)strlen(s) + 1, z = 0;
	memcpy(r + off, &z, 4); memcpy(r + off + 4, &cnt, 4);
	memset(r + off + 8, 0, (cnt + 3) & ~3u); memcpy(r + off + 8, s, cnt);
	return off + 8 + ((cnt + 3) & ~3u);
}
static size_t rp_u32(uint8_t* r, const struct hdr* h, uint32_t v) { size_t n = reply_begin(r, h, KERN_SUCCESS_); memcpy(r + n, &v, 4); return n + 4; }
static size_t rp_u64(uint8_t* r, const struct hdr* h, uint64_t v) { size_t n = reply_begin(r, h, KERN_SUCCESS_); memcpy(r + n, &v, 8); return n + 8; }
static size_t rp_err(uint8_t* r, const struct hdr* h, int32_t kr) { return reply_begin(r, h, kr); }
// objeto de salida + resultado explícito (out result : kern_return_t; out obj : io_object_t): descriptor, NDR, resultado
static size_t rp_port_res(uint8_t* r, const struct hdr* h, uint32_t port, int32_t res) {
	size_t n = reply_port(r, h, port, 17);
	memcpy(r + n, NDR_LE, 8); memcpy(r + n + 8, &res, 4);
	return n + 12;
}
// respuesta con un descriptor OOL (io_buf_ptr_t): cabecera, cuerpo, descriptor (16), NDR, cuenta. Con `res_present` añade el resultado.
static size_t rp_ool(uint8_t* r, const struct hdr* h, const void* data, size_t len, int res_present, int32_t res) {
	struct hdr nh = { .bits = 0x80000000u, .size = 0, .remote = 0, .local = 0, .voucher = 0, .id = h->id + 100 };
	memcpy(r, &nh, sizeof nh);
	uint32_t one = 1; memcpy(r + 24, &one, 4);
	uint64_t addr = 0;
	if (len) {
		void* m = mmap(NULL, (len + 4095) & ~4095ul, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m != MAP_FAILED) { memcpy(m, data, len); addr = (uint64_t)m; } else len = 0;
	}
	uint8_t d[16] = { 0 };
	memcpy(d, &addr, 8); d[8] = 1; d[9] = 1; d[11] = 1; uint32_t l32 = (uint32_t)len; memcpy(d + 12, &l32, 4);   // dealloc, copia virtual, tipo OOL
	memcpy(r + 28, d, 16);
	memcpy(r + 44, NDR_LE, 8);
	size_t n = 52;
	if (res_present) { memcpy(r + n, &res, 4); n += 4; }
	memcpy(r + n, &l32, 4);
	return n + 4;
}
static size_t rp_props(uint8_t* r, const struct hdr* h, struct val* v, int xml) {
	struct sbuf b = { 0 };
	if (xml) { xml_ser(&b, v); sb_put(&b, "\0", 1); } else bin_ser_top(&b, v);
	size_t n = rp_ool(r, h, b.p, b.n, 0, 0);
	free(b.p);
	return n;
}

// ------------------------------------------------------------------ búsqueda de una propiedad
static struct val* prop_search(int ent, int plane, const char* key, int options) {
	struct val* v = v_get(io_e[ent].props, key);
	if (v) return v;
	if (options & 2) { for (int p = ent_parent(ent, plane); p >= 0; p = ent_parent(p, plane)) if ((v = v_get(io_e[p].props, key))) return v; }
	if (options & 1) {
		int* l; int n; iter_collect(ent, plane, 1, &l, &n);
		for (int i = 0; i < n && !v; i++) v = v_get(io_e[l[i]].props, key);
		free(l);
	}
	return v;
}
static struct val* props_with_extras(int ent) {
	struct val* d = v_new(V_DICT);
	for (int i = 0; i < io_e[ent].props->cnt; i++) v_add(d, io_e[ent].props->key[i], io_e[ent].props->kid[i]);
	if (!v_get(d, "IOClass")) v_set(d, "IOClass", v_str(io_e[ent].cls));
	return d;
}

// ------------------------------------------------------------------ notificaciones
static void notif_send(struct ioobj* o, int type) {
	if (!o->wake) return;
	uint8_t m[24 + 8 + 64] = { 0 };
	struct hdr h = { .bits = 0x11 /* send-once */ , .size = sizeof m, .remote = o->wake, .local = 0, .voucher = 0, .id = 53 };
	memcpy(m, &h, sizeof h);
	uint32_t sz = 0, ty = (uint32_t)type; memcpy(m + 24, &sz, 4); memcpy(m + 28, &ty, 4);
	for (int i = 0; i < 8; i++) { uint64_t v = i < o->nref ? o->ref[i] : 0; memcpy(m + 32 + i * 8, &v, 8); }
	port_send(o->wake, m, sizeof m);
}

// ------------------------------------------------------------------ user clients: ganchos por clase
// Un gancho recibe la conexión y la llamada y devuelve kIOReturn*. Aquí no hay ninguno (los registran el puente DRM/Metal).
struct uc_call { int ent; uint32_t selector; const uint64_t* sin; uint32_t nsin; const uint8_t* inband; uint32_t ninband; uint64_t* sout; uint32_t* nsout; uint8_t* outband; uint32_t* noutband; };
typedef int32_t (*uc_method_fn)(struct uc_call*);
// AppleSMC: selector 2 (kSMCHandleYPCEvent) con SMCKeyData_t de 80 bytes; el resultado va en el byte 40. Sin SMC real, toda clave
// responde "no encontrada" (0x84), que es lo que esperan los clientes ante una clave ausente.
static int32_t uc_smc(struct uc_call* c) {
	if (c->selector != 2 || c->ninband < 80) return kIOReturnBadArgument;
	memcpy(c->outband, c->inband, 80); c->outband[40] = 0x84; *c->noutband = 80; *c->nsout = 0;
	return 0;
}
static uc_method_fn uc_hook_for(const char* cls) { return !strcmp(cls, "AppleSMC") ? uc_smc : NULL; }

// ------------------------------------------------------------------ el servidor
static size_t mig_iokit(const struct hdr* h, const uint8_t* req, uint8_t* rep, int* handled) {
	*handled = 1;
	io_init();
	struct rq q;
	rq_init(&q, h, req);
	int ent = obj_ent(h->remote);
	struct ioobj* self = obj_by_port(h->remote);
	switch (h->id) {
	case 2877: return rp_u64(rep, h, 0x1);                                              // io_server_version
	case 2827: return reply_port(rep, h, ent_handle(0), 17);                            // io_registry_get_root_entry

	case 2809: { rq_ndr(&q); const char* p = rq_str(&q); int e = ent_from_path(p); if (e < 0) return rp_err(rep, h, kIOReturnNotFound); return reply_port(rep, h, ent_handle(e), 17); }
	case 2886: {                                                                        // from_path_ool: ruta inband o en memoria
		rq_ndr(&q); const char* p = rq_str(&q); char tmp[4100];
		if (!*p && q.nool) { snprintf(tmp, sizeof tmp, "%.*s", (int)q.ool_size[0], (const char*)q.ool_addr[0]); p = tmp; }
		int e = ent_from_path(p);
		return rp_port_res(rep, h, e < 0 ? 0 : ent_handle(e), e < 0 ? kIOReturnNotFound : 0);
	}
	case 2800: case 2810: case 2843: case 2854: {
		if (!self || (self->kind != K_ENTRY && self->kind != K_CONNECT)) return rp_err(rep, h, kIOReturnBadArgument);
		const char* s;
		if (h->id == 2800) s = io_e[ent].cls;
		else if (h->id == 2810) s = io_e[ent].name;
		else {
			rq_ndr(&q); const char* pl = rq_str(&q); int plane = plane_of(pl);
			if (!plane || !ent_in(ent, plane)) return rp_err(rep, h, kIOReturnBadArgument);
			s = h->id == 2843 ? ent_name_in_plane(ent, plane) : io_e[ent].loc;
			if (h->id == 2854 && !io_e[ent].loc[0]) return rp_err(rep, h, kIOReturnNotFound);
		}
		size_t n = reply_begin(rep, h, KERN_SUCCESS_);
		return rp_str(rep, n, s);
	}
	case 2801: { if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument); rq_ndr(&q); const char* c = rq_str(&q); return rp_u32(rep, h, ent_conforms(ent, c)); }
	case 2871: if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument); return rp_u64(rep, h, io_e[ent].id);
	case 2830: return rp_u32(rep, h, 1);
	case 2826: case 2885: {                                                             // get_path / get_path_ool
		if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument);
		rq_ndr(&q); int plane = plane_of(rq_str(&q));
		if (!plane || !ent_in(ent, plane)) return rp_err(rep, h, kIOReturnNotFound);
		char p[512]; ent_path(ent, plane, p, sizeof p);
		if (h->id == 2826) { size_t n = reply_begin(rep, h, KERN_SUCCESS_); return rp_str(rep, n, p); }
		// path (inband) + path_ool: la ruta cabe siempre inband; el OOL va vacío
		size_t n = rp_ool(rep, h, "", 0, 0, 0);
		(void)n;
		struct hdr nh = { .bits = 0x80000000u, .size = 0, .id = h->id + 100 };
		memcpy(rep, &nh, sizeof nh);
		uint32_t one = 1; memcpy(rep + 24, &one, 4);
		uint8_t d[16] = { 0 }; d[8] = 1; d[9] = 1; d[11] = 1; memcpy(rep + 28, d, 16);
		memcpy(rep + 44, NDR_LE, 8);
		size_t o = rp_str(rep, 52, p);
		uint32_t z = 0; memcpy(rep + o, &z, 4);
		return o + 4;
	}
	case 2829: { if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument); rq_ndr(&q); int plane = plane_of(rq_str(&q)); return rp_u32(rep, h, plane && ent_in(ent, plane)); }
	case 2887: {                                                                        // device_tree_entry_exists_with_name
		rq_ndr(&q); const char* nm = rq_str(&q); int ok = 0;
		for (int i = 0; i < io_ne; i++) if (ent_in(i, PL_DT) && !strcmp(ent_name_in_plane(i, PL_DT), nm)) ok = 1;
		return rp_u32(rep, h, ok);
	}

	// ---- propiedades
	case 2805: case 2811: case 2878: case 2888: case 2879: case 2889: case 2855: case 2812: {
		if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument);
		rq_ndr(&q);
		int xml = (h->id == 2805 || h->id == 2811 || h->id == 2855);
		if (h->id == 2811 || h->id == 2878 || h->id == 2888) {                          // todas las propiedades
			struct val* d = props_with_extras(ent);
			uint64_t buf = 0, bufsz = 0;
			if (h->id == 2888) { buf = rq_u64(&q); bufsz = rq_u64(&q); }
			struct sbuf b = { 0 };
			if (xml) { xml_ser(&b, d); sb_put(&b, "\0", 1); } else bin_ser_top(&b, d);
			free(d->kid); free(d->key); free(d);
			size_t n;
			if (h->id == 2888 && buf && b.n <= bufsz) {                                // cabe en el búfer del cliente: sin OOL
				memcpy((void*)buf, b.p, b.n);
				n = rp_ool(rep, h, "", 0, 0, 0);
				uint64_t used = b.n; memcpy(rep + n, &used, 8); n += 8;                // bufsize (salida)
			} else {
				n = rp_ool(rep, h, b.p, b.n, 0, 0);
				if (h->id == 2888) { uint64_t used = b.n; memcpy(rep + n, &used, 8); n += 8; }
			}
			free(b.p);
			return n;
		}
		int plane = PL_SERVICE, options = 0;
		const char* key;
		if (h->id == 2879 || h->id == 2889 || h->id == 2855) {
			plane = plane_of(rq_str(&q)); key = rq_str(&q); options = (int)rq_u32(&q);
			if (!plane) plane = PL_SERVICE;
		} else key = rq_str(&q);
		uint64_t buf = 0, bufsz = 0;
		if (h->id == 2889) { buf = rq_u64(&q); bufsz = rq_u64(&q); }
		struct val* v = prop_search(ent, plane, key, options);
		if (!v && !strcmp(key, "IOClass")) v = v_str(io_e[ent].cls);
		if (!v) return rp_err(rep, h, kIOReturnNotFound);
		if (h->id == 2812) {                                                            // get_property_bytes: datos crudos inband
			const uint8_t* d = (const uint8_t*)v->s; size_t ln = v->t == V_DATA ? v->slen : v->t == V_STR ? v->slen + 1 : 0;
			if (v->t == V_NUM) { d = (const uint8_t*)&v->n; ln = (size_t)v->bits / 8; }
			size_t n = reply_begin(rep, h, KERN_SUCCESS_);
			uint32_t c = (uint32_t)ln; memcpy(rep + n, &c, 4); memset(rep + n + 4, 0, (ln + 3) & ~3ul); memcpy(rep + n + 4, d, ln);
			return n + 4 + ((ln + 3) & ~3ul);
		}
		if (h->id == 2889) {
			struct sbuf b = { 0 }; bin_ser_top(&b, v);
			size_t n;
			if (buf && b.n <= bufsz) { memcpy((void*)buf, b.p, b.n); n = rp_ool(rep, h, "", 0, 0, 0); } else n = rp_ool(rep, h, b.p, b.n, 0, 0);
			uint64_t used = b.n; memcpy(rep + n, &used, 8); n += 8;
			free(b.p);
			return n;
		}
		return rp_props(rep, h, v, xml);
	}
	case 2828: case 2821: {                                                             // set_properties (entrada / conexión)
		rq_ndr(&q);
		int ok = h->id == 2821 || (ent >= 0 && !strcmp(io_e[ent].cls, "IODTNVRAM"));
		size_t n = reply_begin(rep, h, KERN_SUCCESS_); int32_t res = ok ? 0 : kIOReturnNotPrivileged; memcpy(rep + n, &res, 4); return n + 4;
	}

	// ---- iteradores
	case 2806: {                                                                        // io_registry_create_iterator(main, plane, options)
		rq_ndr(&q); int plane = plane_of(rq_str(&q)); uint32_t opt = rq_u32(&q);
		if (!plane) return rp_err(rep, h, kIOReturnBadArgument);
		int start = 0;
		int* l; int n; iter_collect(start, plane, (int)opt, &l, &n);
		struct ioobj* it = iter_new(l, n, plane); if (!it) return rp_err(rep, h, kIOReturnNoMemory);
		it->ent = start;
		return reply_port(rep, h, it->port, 17);
	}
	case 2833: case 2813: case 2814: {                                                  // create_iterator(entry, plane, options) / child / parent
		if (ent < 0) return rp_err(rep, h, kIOReturnBadArgument);
		rq_ndr(&q); int plane = plane_of(rq_str(&q));
		uint32_t opt = h->id == 2833 ? rq_u32(&q) : h->id == 2814 ? 2 : 0;
		if (!plane || !ent_in(ent, plane)) return rp_err(rep, h, kIOReturnBadArgument);
		int* l; int n; iter_collect(ent, plane, (int)opt, &l, &n);
		struct ioobj* it = iter_new(l, n, plane); if (!it) return rp_err(rep, h, kIOReturnNoMemory);
		it->ent = ent;
		return reply_port(rep, h, it->port, 17);
	}
	case 2802: {                                                                        // io_iterator_next
		if (!self || !self->it) return rp_err(rep, h, kIOReturnBadArgument);
		struct ioiter* it = self->it;
		if (it->pos >= it->n) return reply_port(rep, h, 0, 17);
		int e = it->list[it->pos++]; it->cur = e;
		return reply_port(rep, h, ent_handle(e), 17);
	}
	case 2803: if (self && self->it) { self->it->pos = 0; self->it->valid = 1; } return rp_err(rep, h, KERN_SUCCESS_);
	case 2834: return rp_u32(rep, h, self && self->it ? self->it->valid : 0);
	case 2807: {                                                                        // enter_entry: recorre los hijos de la última entrada
		struct ioiter* it = self ? self->it : NULL;
		if (!it || it->cur < 0 || it->depth >= 8) return rp_err(rep, h, kIOReturnBadArgument);
		it->stk[it->depth].list = it->list; it->stk[it->depth].n = it->n; it->stk[it->depth].pos = it->pos; it->depth++;
		int* l; int n; iter_collect(it->cur, it->plane, 0, &l, &n); it->list = l; it->n = n; it->pos = 0;
		return rp_err(rep, h, KERN_SUCCESS_);
	}
	case 2808: {
		struct ioiter* it = self ? self->it : NULL;
		if (!it || !it->depth) return rp_err(rep, h, kIOReturnBadArgument);
		it->depth--; free(it->list); it->list = it->stk[it->depth].list; it->n = it->stk[it->depth].n; it->pos = it->stk[it->depth].pos;
		return rp_err(rep, h, KERN_SUCCESS_);
	}

	// ---- búsqueda de servicios
	case 2804: case 2873: case 2857: case 2874: case 2881: case 2880: {
		struct val* m = NULL; int many = (h->id == 2804 || h->id == 2857 || h->id == 2881), res_exp = (h->id == 2857 || h->id == 2874);
		rq_ndr(&q);
		if (h->id == 2804 || h->id == 2873) { const char* s = rq_str(&q); m = xml_parse(s, strlen(s)); }
		else if (h->id == 2857 || h->id == 2874) m = rq_match_ool(&q);
		else { uint32_t n; const uint8_t* b = rq_bytes(&q, &n); m = any_parse(b, n); }
		int list[IO_MAXENT]; int n = m ? match_all(m, list, IO_MAXENT) : 0;
		if (!m) return res_exp ? rp_port_res(rep, h, 0, kIOReturnBadArgument) : rp_err(rep, h, kIOReturnBadArgument);
		if (many) {
			int* l = malloc((n ? n : 1) * sizeof(int)); memcpy(l, list, n * sizeof(int));
			struct ioobj* it = iter_new(l, n, PL_SERVICE); if (!it) return rp_err(rep, h, kIOReturnNoMemory);
			return res_exp ? rp_port_res(rep, h, it->port, 0) : reply_port(rep, h, it->port, 17);
		}
		if (!n) return res_exp ? rp_port_res(rep, h, 0, kIOReturnNotFound) : rp_err(rep, h, kIOReturnNotFound);
		return res_exp ? rp_port_res(rep, h, ent_handle(list[0]), 0) : reply_port(rep, h, ent_handle(list[0]), 17);
	}
	case 2844: case 2858: case 2882: {                                                  // service_match_property_table
		struct val* m = NULL; rq_ndr(&q);
		if (h->id == 2844) { const char* s = rq_str(&q); m = xml_parse(s, strlen(s)); }
		else if (h->id == 2858) m = rq_match_ool(&q);
		else { uint32_t n; const uint8_t* b = rq_bytes(&q, &n); m = any_parse(b, n); }
		if (ent < 0 || !m) return rp_err(rep, h, kIOReturnBadArgument);
		int ok = match_entry(ent, m);
		if (h->id == 2858) { size_t n = reply_begin(rep, h, KERN_SUCCESS_); int32_t r = 0; memcpy(rep + n, &r, 4); memcpy(rep + n + 4, &ok, 4); return n + 8; }
		return rp_u32(rep, h, ok);
	}

	// ---- notificaciones
	case 2868: case 2870: case 2884: {                                                  // add_notification(type, matching, wake_port, reference)
		rq_ndr(&q);
		const char* ty = rq_str(&q);
		struct val* m = NULL;
		if (h->id == 2868) { const char* s = rq_str(&q); m = xml_parse(s, strlen(s)); }
		else if (h->id == 2870) m = rq_match_ool(&q);
		else { uint32_t n; const uint8_t* b = rq_bytes(&q, &n); m = any_parse(b, n); }
		int res_exp = h->id == 2870;
		uint32_t nref = rq_u32(&q);
		struct ioobj* o = m ? obj_new(K_NOTIF) : NULL;
		if (!o) return res_exp ? rp_port_res(rep, h, 0, kIOReturnBadArgument) : rp_err(rep, h, kIOReturnBadArgument);
		o->match = m; o->wake = q.nport ? q.port[0] : 0;
		o->notif_type = !strcmp(ty, "IOServiceTerminate") ? 102 : !strcmp(ty, "IOServiceFirstMatch") || !strcmp(ty, "IOServiceMatched") ? 101 : 100;
		o->nref = nref > 8 ? 8 : (int)nref;
		for (int i = 0; i < o->nref; i++) o->ref[i] = rq_u64(&q);
		int list[IO_MAXENT]; int n = (o->notif_type == 102) ? 0 : match_all(m, list, IO_MAXENT);   // nada se retira: no hay terminaciones
		int* l = malloc((n ? n : 1) * sizeof(int)); memcpy(l, list, n * sizeof(int));
		o->it = calloc(1, sizeof *o->it); o->it->list = l; o->it->n = n; o->it->plane = PL_SERVICE; o->it->valid = 1; o->it->cur = -1;
		if (n) notif_send(o, o->notif_type);                                           // ya hay coincidencias: avisar al cliente
		return res_exp ? rp_port_res(rep, h, o->port, 0) : reply_port(rep, h, o->port, 17);
	}
	case 2869: {                                                                        // add_interest_notification(service, type, wake, ref)
		rq_ndr(&q); (void)rq_str(&q);
		uint32_t nref = rq_u32(&q);
		struct ioobj* o = obj_new(K_NOTIF);
		if (!o) return rp_err(rep, h, kIOReturnNoMemory);
		o->wake = q.nport ? q.port[0] : 0; o->notif_type = 160; o->ent = ent;
		o->nref = nref > 8 ? 8 : (int)nref; for (int i = 0; i < o->nref; i++) o->ref[i] = rq_u64(&q);
		return reply_port(rep, h, o->port, 17);
	}
	case 2861: case 2860: {                                                             // bundle_identifier / superclass (por nombre de clase)
		rq_ndr(&q); const char* cn = rq_str(&q);
		if (trace_all) logf_("    iokit: %s(\"%s\")\n", h->id == 2860 ? "superclass" : "bundle", cn);
		if (!strcmp(cn, "OSObject")) return rp_err(rep, h, kIOReturnNotFound);
		for (int i = 0; i < io_ne; i++) {
			// cadena de herencia de la entrada: clase, últimas superclases primero, ..., OSObject
			char chain[16][48]; int k = 0;
			snprintf(chain[k++], sizeof chain[0], "%s", io_e[i].cls);
			char tok[16][48]; int nt = 0; const char* s = io_e[i].supers;
			while (*s && nt < 16) { const char* e = strchr(s, ' '); size_t l = e ? (size_t)(e - s) : strlen(s); snprintf(tok[nt++], sizeof tok[0], "%.*s", (int)l, s); if (!e) break; s = e + 1; }
			for (int t = nt - 1; t >= 0 && k < 16; t--) snprintf(chain[k++], sizeof chain[0], "%s", tok[t]);
			if (k < 16) snprintf(chain[k++], sizeof chain[0], "OSObject");
			for (int c = 0; c < k; c++) if (!strcmp(chain[c], cn)) {
				if (trace_all) logf_("      -> %s (entrada %d, pos %d de %d)\n", c + 1 < k ? chain[c + 1] : "OSObject", i, c, k);
				size_t n = reply_begin(rep, h, KERN_SUCCESS_);
				return rp_str(rep, n, h->id == 2861 ? "com.apple.iokit.IOKit" : (c + 1 < k ? chain[c + 1] : "OSObject"));
			}
		}
		return rp_err(rep, h, kIOReturnNotFound);
	}

	// ---- estado del servicio
	case 2831: return rp_u32(rep, h, 0);                                                // busy_state
	case 2832: case 2890: case 2842: return rp_err(rep, h, KERN_SUCCESS_);              // wait_quiet / request_probe
	case 2856: {                                                                        // get_state: registrado | emparejado | primera publicación | primer emparejamiento
		size_t n = reply_begin(rep, h, KERN_SUCCESS_);
		uint64_t st = 0x1e, bt = 0; uint32_t busy = 0;
		memcpy(rep + n, &st, 8); memcpy(rep + n + 8, &busy, 4); memcpy(rep + n + 12, &bt, 8);
		return n + 20;
	}
	case 2875: return rp_u64(rep, h, 0);
	case 2876: return rp_err(rep, h, KERN_SUCCESS_);

	// ---- catálogo
	case 2836: case 2837: case 2840: case 2841: {
		size_t n = reply_begin(rep, h, KERN_SUCCESS_);
		if (h->id == 2836) { int32_t r = 0; memcpy(rep + n, &r, 4); n += 4; }
		return n;
	}
	case 2838: return rp_ool(rep, h, "", 0, 0, 0);
	case 2839: return rp_u32(rep, h, 1);

	// ---- conexiones (user clients)
	case 2862: {                                                                        // io_service_open_extended
		if (ent < 0) return rp_port_res(rep, h, 0, kIOReturnBadArgument);
		rq_ndr(&q);
		uint32_t ctype = rq_u32(&q);
		if (!io_e[ent].uc) return rp_port_res(rep, h, 0, kIOReturnUnsupported);
		struct ioobj* c = obj_new(K_CONNECT); if (!c) return rp_port_res(rep, h, 0, kIOReturnNoMemory);
		c->ent = ent; c->ctype = (int)ctype;
		return rp_port_res(rep, h, c->port, 0);
	}
	case 2816: if (self && self->kind == K_CONNECT) self->closed = 1; return rp_err(rep, h, KERN_SUCCESS_);
	case 2817: if (!self || self->kind != K_CONNECT) return rp_err(rep, h, kIOReturnBadArgument); return reply_port(rep, h, ent_handle(self->ent), 17);
	case 2820: case 2867: return rp_err(rep, h, KERN_SUCCESS_);                         // add_client / set_notification_port
	case 2852: case 2815: case 2863: case 2864: case 2866: case 2872: case 2865: {
		// 2865 io_connect_method: scalar_input[], inband_input, ool_input; salidas inband/scalar/ool. Sin gancho de clase: no soportado.
		if (!self || self->kind != K_CONNECT || self->closed) return rp_err(rep, h, kIOReturnNoDevice);
		uc_method_fn fn = uc_hook_for(io_e[self->ent].cls);
		if (!fn || h->id != 2865) { logf_("    iokit: %s selector sin gancho (id=%d clase=%s)\n", "user client", h->id, io_e[self->ent].cls); return rp_err(rep, h, kIOReturnUnsupported); }
		struct uc_call uc = { .ent = self->ent };
		rq_ndr(&q); uc.selector = rq_u32(&q);
		uint32_t nsin = rq_u32(&q); uint64_t sin[16] = { 0 }; for (uint32_t i = 0; i < nsin && i < 16; i++) sin[i] = rq_u64(&q);
		uc.sin = sin; uc.nsin = nsin; uc.inband = rq_bytes(&q, &uc.ninband);
		uint64_t sout[16] = { 0 }; uint32_t nsout = 16, nout = 4096; static __thread uint8_t outband[4096];
		uc.sout = sout; uc.nsout = &nsout; uc.outband = outband; uc.noutband = &nout;
		int32_t r = fn(&uc);
		if (r) return rp_err(rep, h, r);
		size_t n = reply_begin(rep, h, KERN_SUCCESS_);
		memcpy(rep + n, &nout, 4); memcpy(rep + n + 4, outband, nout); n += 4 + ((nout + 3) & ~3u);
		memcpy(rep + n, &nsout, 4); memcpy(rep + n + 4, sout, nsout * 8); n += 4 + nsout * 8;
		uint64_t osz = 0; memcpy(rep + n, &osz, 8);
		return n + 8;
	}
	}
	logf_("    iokit: id=%d sin implementar\n", h->id);
	*handled = 0;
	return 0;
}
