#define _GNU_SOURCE
#include "corehttpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <jansson.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* =====================================================================
 * arena
 * ===================================================================== */
void arena_init(Arena *a, size_t sz) {
    a->base = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (a->base == MAP_FAILED) { perror("mmap"); exit(1); }
    a->size = sz; a->used = 0;
}
void *arena_alloc(Arena *a, size_t n) {
    if (n > a->size) return NULL;
    n = (n + 15) & ~(size_t)15;
    if (n > a->size - a->used) return NULL;
    void *p = a->base + a->used;
    a->used += n;
    return p;
}
char *arena_strdup(Arena *a, const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = arena_alloc(a, n);
    if (p) memcpy(p, s, n);
    return p;
}
void arena_reset(Arena *a) { a->used = 0; }

/* error logging (defined in the logging section below) */
static int g_errfd;
static void log_err(const char *fmt, ...);
static void log_warn(const char *fmt, ...);
static void log_info(const char *fmt, ...);
static void log_debug(const char *fmt, ...);

/* =====================================================================
 * jsonc – strip comments but preserve strings
 * ===================================================================== */
static char *strip_jsonc(Arena *a, const char *s) {
    size_t n = strlen(s);
    char *out = arena_alloc(a, n + 1);
    if (!out) return NULL;
    size_t o = 0; size_t i = 0;
    while (i < n) {
        if (s[i] == '"') {
            out[o++] = s[i++];
            while (i < n && s[i] != '"') {
                if (s[i] == '\\' && i + 1 < n) out[o++] = s[i++];
                out[o++] = s[i++];
            }
            if (i < n) out[o++] = s[i++];
        } else if (s[i] == '/' && i + 1 < n && s[i+1] == '/') {
            i += 2; while (i < n && s[i] != '\n') i++;
        } else if (s[i] == '/' && i + 1 < n && s[i+1] == '*') {
            i += 2; while (i + 1 < n && !(s[i] == '*' && s[i+1] == '/')) i++;
            if (i + 1 < n) i += 2;
        } else out[o++] = s[i++];
    }
    out[o] = 0;
    return out;
}

/* =====================================================================
 * config helpers
 * ===================================================================== */
static int j_int(json_t *o, const char *k, int def) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    return json_is_integer(v) ? (int)json_integer_value(v) : def;
}

/* timeouts in seconds, clamped to a sane range: a negative value would
 * make poll() wait forever (slowloris) and a huge one would overflow
 * the millisecond multiplication */
static int j_timeout(json_t *o, const char *k, int def) {
    int v = j_int(o, k, def);
    if (v < 1) v = 1;
    if (v > 86400) v = 86400;
    return v;
}
static const char *j_str(json_t *o, const char *k) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    return json_is_string(v) ? json_string_value(v) : NULL;
}

/* file mode: a string of octal digits ("0640") or a plain integer */
static int j_mode(json_t *o, const char *k, int def) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    if (json_is_string(v)) {
        const char *s = json_string_value(v);
        if (!s[0]) return def;
        char *end = NULL;
        long m = strtol(s, &end, 8);
        if (!*end && m >= 0 && m <= 07777) return (int)m;
        return def;
    }
    if (json_is_integer(v)) return (int)json_integer_value(v);
    return def;
}

static Acl *parse_acl(Arena *a, json_t *arr, int *n_out) {
    *n_out = 0;
    if (!json_is_array(arr)) return NULL;
    size_t len = json_array_size(arr);
    Acl *out = arena_alloc(a, sizeof(Acl) * len);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        const char *s = json_string_value(json_array_get(arr, i));
        if (!s) continue;
        char buf[80]; strncpy(buf, s, sizeof(buf) - 1); buf[79] = 0;
        char *slash = strchr(buf, '/');
        int bits = 32;
        if (slash) { *slash = 0; bits = atoi(slash + 1); }
        if (bits < 0) bits = 0;
	if (bits > 32) bits = 32;
        struct in_addr ia;
        if (inet_pton(AF_INET, buf, &ia) != 1) continue;
        uint32_t host = ntohl(ia.s_addr);
        uint32_t mask = bits == 0 ? 0u
                      : bits == 32 ? 0xffffffffu
                      : (0xffffffffu << (32 - bits));
        out[*n_out].net  = host & mask;
        out[*n_out].mask = mask;
        (*n_out)++;
    }
    return out;
}

/* intersect two ACL lists; result denies nothing that both allow */
static int acl_intersect(Arena *a,
                         const Acl *x, int nx, const Acl *y, int ny,
                         Acl **out) {
    if (nx == 0) { *out = (Acl*)y; return ny; }
    if (ny == 0) { *out = (Acl*)x; return nx; }
    if ((size_t)nx * (size_t)ny > a->size / sizeof(Acl)) return 0;
    Acl *o = arena_alloc(a, sizeof(Acl) * (size_t)nx * (size_t)ny);
    if (!o) return 0;
    int k = 0;
    for (int i = 0; i < nx; i++)
        for (int j = 0; j < ny; j++) {
            uint32_t mask = x[i].mask & y[j].mask;
            uint32_t net  = (x[i].net & y[j].net) & mask;
            if (mask == 0 && net != 0) continue;
            o[k].net = net; o[k].mask = mask; k++;
        }
    *out = o;
    return k;
}

static DirCfg *parse_dir(Arena *a, json_t *j, DirCfg *parent,
                         const Config *cfg, const char *forced_name) {
    if (!json_is_object(j)) return NULL;
    DirCfg *d = arena_alloc(a, sizeof(*d));
    memset(d, 0, sizeof(*d));

    const char *nm = forced_name ? forced_name : j_str(j, "name");
    d->name = nm ? arena_strdup(a, nm) : NULL;

    /* ---- filesystem path ---- */
    const char *dr = j_str(j, "documentroot");
    if (dr) {
        d->path = arena_strdup(a, dr);
    } else if (parent && parent->path &&
               !(nm && (strchr(nm, '*') || strchr(nm, '?')))) {
        size_t pl = strlen(parent->path), nl = nm ? strlen(nm) : 0;
        char *p = arena_alloc(a, pl + nl + 2);
        if (!p) return NULL;
        memcpy(p, parent->path, pl);
        p[pl] = '/';
        if (nl) memcpy(p + pl + 1, nm, nl);
        p[pl + nl + 1] = 0;
        d->path = p;
    } else if (parent) {
        /* glob name (or a child of one): the real filesystem path is
         * derived per request from the matched URL component */
        d->path = NULL;
    } else d->path = arena_strdup(a, "/");

    /* ---- auth: monotonic ---- */
    json_t *jauth = json_object_get(j, "auth");
    if (jauth) {
        const char *au = j_str(jauth, "user");
        const char *ap = j_str(jauth, "pass");
        /* empty credentials would let a client authenticate with an
         * empty "Basic :" header — refuse them at config load */
        if (!au || !*au || !ap || !*ap) {
            fprintf(stderr, "config: auth needs a non-empty user and pass\n");
            return NULL;
        }
        d->auth_required = 1;
        d->auth_user = arena_strdup(a, au);
        d->auth_pass = arena_strdup(a, ap);
    } else if (parent) {
        d->auth_required = parent->auth_required;
        d->auth_user     = parent->auth_user;
        d->auth_pass     = parent->auth_pass;
    }

    /* ---- ip ACL: intersection ---- */
    int n_own = 0; Acl *own = parse_acl(a, json_object_get(j, "ip_allow"), &n_own);
    if (parent && parent->n_allow) {
        if (!n_own) { d->allow = parent->allow; d->n_allow = parent->n_allow; }
        else        d->n_allow = acl_intersect(a, parent->allow, parent->n_allow,
                                              own, n_own, &d->allow);
    } else { d->allow = own; d->n_allow = n_own; }

    /* ---- timeouts: free ---- */
    d->header_timeout    = j_timeout(j, "header_timeout",
                                 parent ? parent->header_timeout    : cfg->def_header_timeout);
    d->body_timeout      = j_timeout(j, "body_timeout",
                                 parent ? parent->body_timeout      : cfg->def_body_timeout);
    d->keepalive_timeout = j_timeout(j, "keepalive_timeout",
                                 parent ? parent->keepalive_timeout : cfg->def_keepalive);

    /* ---- cgi: per-directory only, not inherited from the parent ---- */
    json_t *jcgi = json_object_get(j, "cgi");
    if (json_is_array(jcgi)) {
        size_t nadd = json_array_size(jcgi);
        d->cgi = arena_alloc(a, sizeof(CgiProgram) * (nadd ? nadd : 1));
        if (!d->cgi) return NULL;
        for (size_t i = 0; i < nadd; i++) {
            json_t *e = json_array_get(jcgi, i);
            const char *name = j_str(e, "name");
            if (!name) continue;
            CgiProgram *slot = &d->cgi[d->n_cgi++];
            memset(slot, 0, sizeof(*slot));
            slot->name = arena_strdup(a, name);
            const char *pp = j_str(e, "path");
            slot->path = pp ? arena_strdup(a, pp) : NULL;
            const char *uu = j_str(e, "user");
            slot->user = uu ? arena_strdup(a, uu) : NULL;
        }
    }

    /* ---- subdirs ---- */
    json_t *subs = json_object_get(j, "subdirs");
    if (json_is_array(subs)) {
        size_t n = json_array_size(subs);
        d->subdirs = arena_alloc(a, sizeof(DirCfg *) * n);
        if (!d->subdirs) return NULL;
        for (size_t i = 0; i < n; i++) {
            DirCfg *cd = parse_dir(a, json_array_get(subs, i), d, cfg, NULL);
            if (!cd) return NULL;      /* config errors must be loud */
            d->subdirs[d->n_subdirs++] = cd;
        }
    }
    return d;
}

/* (cert,key) filename pair -> loaded key; dedupes shared certificates so
 * the master arena is not wasted on duplicates */
struct KeyEnt { const char *cf, *kf; TlsKey *key; };

static TlsKey *key_load_cached(Arena *a, const char *cf, const char *kf,
                               struct KeyEnt *keys, size_t *nkeys) {
    for (size_t i = 0; i < *nkeys; i++)
        if (!strcmp(keys[i].cf, cf) && !strcmp(keys[i].kf, kf))
            return keys[i].key;
    TlsKey *k = tls_load_key(a, cf, kf);
    if (!k) return NULL;
    if (*nkeys < 128) {
        keys[*nkeys].cf = cf;
        keys[*nkeys].kf = kf;
        keys[*nkeys].key = k;
        (*nkeys)++;
    }
    return k;
}

static int file_exists(const char *p) {
    struct stat st;
    return p && stat(p, &st) == 0;
}

Config *config_load(Arena *a, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (uint64_t)sz >= a->size - a->used) {
        fclose(f); return NULL;
    }
    char *raw = arena_alloc(a, (size_t)sz + 1);
    if (!raw) { fclose(f); return NULL; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return NULL; }
    raw[sz] = 0; fclose(f);

    char *js = strip_jsonc(a, raw);
    if (!js) { fprintf(stderr, "config: out of memory\n"); return NULL; }
    json_error_t err;
    json_t *root = json_loads(js, 0, &err);
    if (!root) { fprintf(stderr, "json: %s\n", err.text); return NULL; }

    Config *c = arena_alloc(a, sizeof(*c));
    memset(c, 0, sizeof(*c));
    c->httpd_user       = arena_strdup(a, j_str(root, "httpd_user") ? j_str(root, "httpd_user") : "nobody");
    c->cgi_user         = arena_strdup(a, j_str(root, "cgi_user")   ? j_str(root, "cgi_user")   : "nobody");
    c->cert_file        = arena_strdup(a, j_str(root, "cert_file"));
    c->key_file         = arena_strdup(a, j_str(root, "key_file"));
    c->letsencrypt_root = arena_strdup(a, j_str(root, "letsencrypt_root"));
    c->access_log       = arena_strdup(a, j_str(root, "access_log"));
    c->access_log_owner = arena_strdup(a, j_str(root, "access_log_owner"));
    c->access_log_mode  = j_mode(root, "access_log_mode", -1);
    c->arena_size       = j_int(root, "arena_size", 32u << 20);

    json_t *defs = json_object_get(root, "defaults");
    c->def_header_timeout = j_timeout(defs, "header_timeout", 10);
    c->def_body_timeout   = j_timeout(defs, "body_timeout",   30);
    c->def_keepalive      = j_timeout(defs, "keepalive_timeout", 60);

    /* sites */
    json_t *sites = json_object_get(root, "sites");
    if (json_is_array(sites)) {
        size_t n = json_array_size(sites);
        c->sites = arena_alloc(a, sizeof(SiteCfg *) * n);
        for (size_t i = 0; i < n; i++) {
            json_t *s = json_array_get(sites, i);
            SiteCfg *sc = arena_alloc(a, sizeof(*sc));
            memset(sc, 0, sizeof(*sc));
            sc->name = arena_strdup(a, j_str(s, "name"));
            sc->cert_file = arena_strdup(a, j_str(s, "cert_file"));
            sc->key_file  = arena_strdup(a, j_str(s, "key_file"));
            sc->root = parse_dir(a, s, NULL, c, NULL);
            if (!sc->root) {
                json_decref(root);
                return NULL;
            }
            c->sites[c->n_sites++] = sc;
        }
    }

    /* ---- TLS material ----
     * Loaded here, once, by the master.  The global cert/key pair is the
     * default certificate; sites may provide their own pair, selected via
     * SNI during the handshake.  Identical (cert,key) pairs are loaded
     * only once. */
    struct KeyEnt keys[128];
    size_t nkeys = 0;
    if (c->cert_file || c->key_file) {
        if (!c->cert_file || !c->key_file) {
            fprintf(stderr, "config: need both cert_file and key_file\n");
            json_decref(root);
            return NULL;
        }
        if (!file_exists(c->cert_file) || !file_exists(c->key_file)) {
            /* not there yet: start without a default certificate so the
             * HTTP-01 bootstrap (ACME challenges on port 80) works */
            log_warn("config: certificate files %s and %s do not exist "
                     "yet; starting without a default certificate",
                     c->cert_file, c->key_file);
        } else {
            c->tls_key = key_load_cached(a, c->cert_file, c->key_file,
                                         keys, &nkeys);
            if (!c->tls_key) {
                fprintf(stderr, "config: failed to load TLS key\n");
                json_decref(root);
                return NULL;
            }
        }
    }
    for (int i = 0; i < c->n_sites; i++) {
        SiteCfg *sc = c->sites[i];
        if (sc->cert_file || sc->key_file) {
            if (!sc->cert_file || !sc->key_file) {
                fprintf(stderr, "config: site %s: need both cert_file and key_file\n",
                        sc->name ? sc->name : "?");
                json_decref(root);
                return NULL;
            }
            if (!file_exists(sc->cert_file) || !file_exists(sc->key_file)) {
                /* the site starts with the default certificate; once the
                 * files appear (e.g. after corehttpd-acme fetches them),
                 * restart the server */
                log_warn("config: site %s: certificate files %s and %s do "
                         "not exist yet; using the default certificate",
                         sc->name ? sc->name : "?",
                         sc->cert_file, sc->key_file);
                continue;
            }
            sc->tls_key = key_load_cached(a, sc->cert_file, sc->key_file,
                                          keys, &nkeys);
            if (!sc->tls_key) {
                fprintf(stderr, "config: site %s: failed to load TLS key\n",
                        sc->name ? sc->name : "?");
                json_decref(root);
                return NULL;
            }
        }
    }
    json_decref(root);
    return c;
}

SiteCfg *config_find_site(Config *c, const char *host) {
    if (!host) return c->n_sites ? c->sites[0] : NULL;
    /* IPv4 only: a ':' means a trailing port ("name:443"), which is
     * ignored for the site match */
    size_t hlen = strlen(host);
    const char *colon = memchr(host, ':', hlen);
    if (colon) hlen = (size_t)(colon - host);
    for (int i = 0; i < c->n_sites; i++)
        if (strlen(c->sites[i]->name) == hlen &&
            !strncasecmp(c->sites[i]->name, host, hlen))
            return c->sites[i];
    return c->n_sites ? c->sites[0] : NULL;
}

/* simple glob: '*' matches any run (possibly empty), '?' one char */
static int glob_match(const char *pat, const char *s, size_t slen) {
    size_t si = 0;
    const char *star = NULL;
    size_t backi = 0;
    const char *p = pat;
    while (si < slen) {
        if (*p == '?' || *p == s[si]) {
            p++;
            si++;
        } else if (*p == '*') {
            star = p++;
            backi = si;
        } else if (star) {
            p = star + 1;
            backi++;
            si = backi;
        } else {
            return 0;
        }
    }
    while (*p == '*') p++;
    return *p == 0;
}

DirCfg *config_walk(DirCfg *root, char *path, char **rest,
                    char *fs_buf, size_t fs_cap) {
    DirCfg *cur = root;
    size_t flen = 0;
    if (root->path) {
        flen = strlen(root->path);
        if (flen + 1 > fs_cap) return NULL;
        memcpy(fs_buf, root->path, flen + 1);
    } else {
        if (fs_cap < 1) return NULL;
        fs_buf[0] = 0;
    }

    char *p = path;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char *slash = strchr(p, '/');
        size_t clen = slash ? (size_t)(slash - p) : strlen(p);

        DirCfg *m = NULL;
        /* exact literal names win over patterns */
        for (int i = 0; i < cur->n_subdirs; i++) {
            const char *n = cur->subdirs[i]->name;
            if (!n) continue;
            if (strlen(n) == clen && !memcmp(n, p, clen) &&
                !strchr(n, '*') && !strchr(n, '?')) {
                m = cur->subdirs[i];
                break;
            }
        }
        if (!m) {
            /* otherwise the longest matching glob pattern */
            size_t best = 0;
            for (int i = 0; i < cur->n_subdirs; i++) {
                const char *n = cur->subdirs[i]->name;
                if (!n) continue;
                if ((strchr(n, '*') || strchr(n, '?')) &&
                    glob_match(n, p, clen) && strlen(n) > best) {
                    m = cur->subdirs[i];
                    best = strlen(n);
                }
            }
        }
        if (!m) break;
        cur = m;
        if (cur->path) {
            /* static path (explicit documentroot or derived) */
            size_t pl = strlen(cur->path);
            if (pl + 1 > fs_cap) return NULL;
            memcpy(fs_buf, cur->path, pl + 1);
            flen = pl;
        } else {
            /* glob dir: the path grows by the matched component */
            if (flen + clen + 2 > fs_cap) return NULL;
            fs_buf[flen++] = '/';
            memcpy(fs_buf + flen, p, clen);
            flen += clen;
            fs_buf[flen] = 0;
        }
        p += clen;
    }
    *rest = p;
    return cur;
}

/* SNI -> certificate for the handshake: the named site's own cert, or
 * the default certificate when the name is unknown or absent */
static const TlsKey *pick_site_key(const char *sni, void *arg) {
    Config *cfg = arg;
    if (sni && *sni) {
        SiteCfg *s = config_find_site(cfg, sni);
        if (s && s->tls_key) return s->tls_key;
    }
    return cfg->tls_key;
}

/* =====================================================================
 * tiny helpers
 * ===================================================================== */
static int wait_readable(Conn *c, int secs) {
    if (c->tls && tls_pending(c->tls)) return 1;
    struct pollfd p = { c->fd, POLLIN, 0 };
    int r = poll(&p, 1, secs * 1000);
    return r > 0 && (p.revents & POLLIN);
}

static ssize_t conn_read(Conn *c, void *buf, size_t n) {
    return c->tls ? tls_read(c->tls, buf, n) : read(c->fd, buf, n);
}

static int send_all(Conn *c, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = c->tls ? tls_write(c->tls, p, n) : write(c->fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        c->nbytes += (uint64_t)w;
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* error logging (defined in the logging section below) */
static void log_err(const char *fmt, ...);
static void log_warn(const char *fmt, ...);
static void log_info(const char *fmt, ...);
static void log_debug(const char *fmt, ...);

/* raw-fd variant for the cgi socketpair */
static int send_fd_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, unsigned char *out, size_t outmax) {
    size_t o = 0; int quad = 0; uint32_t acc = 0;
    for (const char *p = in; *p; p++) {
        if (*p == '=' || *p == '\r' || *p == '\n') continue;
        int v = b64_val((unsigned char)*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v; quad++;
        if (quad == 4) {
            if (o + 3 > outmax) return -1;
            out[o++] = acc >> 16;
            out[o++] = (acc >> 8) & 0xff;
            out[o++] = acc & 0xff;
            acc = 0; quad = 0;
        }
    }
    if (quad == 2) { if (o + 1 > outmax) return -1; out[o++] = acc >> 4; }
    else if (quad == 3) { if (o + 2 > outmax) return -1; out[o++] = acc >> 10; out[o++] = (acc >> 2) & 0xff; }
    return (int)o;
}

/* =====================================================================
 * HTTP request parser
 * ===================================================================== */
static char *read_headers(Arena *a, Conn *c, int timeout,
                          size_t *out_len, size_t *out_extra) {
    size_t cap = 8192, len = 0, scanned = 0;
    char *buf = arena_alloc(a, cap);
    if (!buf) return NULL;
    while (len < cap) {
        if (!wait_readable(c, timeout)) return NULL;
        ssize_t n = conn_read(c, buf + len, cap - len);
        if (n <= 0) return NULL;
        len += (size_t)n;
        /* continue scanning where the previous scan stopped; -3 so a
         * terminator spanning the seam between reads is still caught */
        for (size_t i = scanned; i + 3 < len; i++) {
            if (buf[i] == '\r' && buf[i+1] == '\n' &&
                buf[i+2] == '\r' && buf[i+3] == '\n') {
                /* NUL-terminate at the blank line (i+2), NOT at i: the
                 * CRLF at i..i+1 also terminates the last header line
                 * and the header parser still needs it */
                buf[i + 2] = 0;
                *out_len = i;
                *out_extra = len - (i + 4);
                return buf;
            }
        }
        scanned = len >= 3 ? len - 3 : 0;
    }
    return NULL;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

int http_read_request(Arena *a, Conn *c, HttpRequest *r,
                      int hdr_timeout, int body_timeout) {
    memset(r, 0, sizeof(*r));
    size_t hlen, extra;
    char *raw = read_headers(a, c, hdr_timeout, &hlen, &extra);
    if (!raw) return -1;

    char *nl = strstr(raw, "\r\n");
    if (!nl) return -1;
    *nl = 0;
    char *save = NULL;
    r->method  = strtok_r(raw, " ", &save);
    r->path    = strtok_r(NULL, " ", &save);
    r->version = strtok_r(NULL, " ", &save);
    if (!r->method || !r->path || !r->version) return -1;
    if (strcmp(r->version, "HTTP/1.1") != 0) return -1;

    char *q = strchr(r->path, '?');
    if (q) { *q = 0; r->query = q + 1; }
    r->keep_alive = 1;

    /* headers */
    char *cur = nl + 2;
    while (*cur) {
        char *eol = strstr(cur, "\r\n");
        if (!eol) break;
        *eol = 0;
        char *colon = strchr(cur, ':');
        if (colon) {
            *colon = 0;
            char *v = trim(colon + 1);
            if      (!strcasecmp(cur, "Host"))           r->host = v;
            else if (!strcasecmp(cur, "Authorization"))  r->authorization = v;
            else if (!strcasecmp(cur, "Content-Length")) r->content_length = atol(v);
            else if (!strcasecmp(cur, "Connection")) {
                if (!strcasecmp(v, "close")) r->keep_alive = 0;
            }
        }
        cur = eol + 2;
    }

    /* body */
    if (r->content_length > 0) {
        if (r->content_length > (long)(a->size - a->used)) return -1;
        r->body = arena_alloc(a, (size_t)r->content_length + 1);
        if (!r->body) return -1;
        size_t got = 0;
        /* bytes read_headers() consumed beyond the header belong to the body */
        if (extra) {
            if (extra > (size_t)r->content_length) {
                /* excess = pipelined next request; give it back */
                if (!c->tls) return -1;
                tls_unread(c->tls, raw + hlen + 4 + r->content_length,
                           extra - (size_t)r->content_length);
                extra = (size_t)r->content_length;
            }
            memcpy(r->body, raw + hlen + 4, extra);
            got = extra;
        }
        while (got < (size_t)r->content_length) {
            if (!wait_readable(c, body_timeout)) return -1;
            ssize_t n = conn_read(c, r->body + got, (size_t)r->content_length - got);
            if (n <= 0) return -1;
            got += (size_t)n;
        }
        r->body[r->content_length] = 0;
        r->body_len = (size_t)r->content_length;
    } else if (extra) {
        /* stray bytes past the header on a body-less request: pipelined
         * request bytes; push them back (TLS only) or reject */
        if (!c->tls) return -1;
        tls_unread(c->tls, raw + hlen + 4, extra);
    }
    return 0;
}

int http_send_simple(Conn *c, int code, const char *reason,
                     const char *extra, const char *body,
                     size_t body_len, int head_only) {
    char hdr[2048];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Server: corehttpd\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "%s"
        "\r\n", code, reason, body_len, extra ? extra : "");
    if (n < 0 || (size_t)n >= sizeof(hdr)) return -1;
    if (send_all(c, hdr, (size_t)n) < 0) return -1;
    if (!head_only && body && body_len) {
        if (send_all(c, body, body_len) < 0) return -1;
    }
    return 0;
}

/* =====================================================================
 * CGI wire protocol (httpd <-> cgi)
 * ===================================================================== */
struct CgiHdr {
    uint32_t prog_len;
    uint32_t user_len;
    uint32_t nenv;
    uint32_t body_len;
};

static int cgi_dispatch(Arena *a, int cgi_fd,
                        const char *prog, const char *user,
                        char *const *env, int nenv,
                        const void *body, size_t body_len) {
    (void)a;
    struct CgiHdr h = {
        .prog_len = (uint32_t)strlen(prog),
        .user_len = (uint32_t)strlen(user),
        .nenv     = (uint32_t)nenv,
        .body_len = (uint32_t)body_len,
    };
    if (send_fd_all(cgi_fd, &h, sizeof(h)) < 0) return -1;
    if (send_fd_all(cgi_fd, prog, h.prog_len) < 0) return -1;
    if (send_fd_all(cgi_fd, user, h.user_len) < 0) return -1;
    for (int i = 0; i < nenv; i++) {
        const char *e = env[i];
        const char *eq = strchr(e, '=');
        uint32_t kl = eq ? (uint32_t)(eq - e) : (uint32_t)strlen(e);
        uint32_t vl = eq ? (uint32_t)strlen(eq + 1) : 0;
        send_fd_all(cgi_fd, &kl, 4); send_fd_all(cgi_fd, &vl, 4);
        send_fd_all(cgi_fd, e, kl);
        if (vl) send_fd_all(cgi_fd, eq + 1, vl);
    }
    if (body_len) send_fd_all(cgi_fd, body, body_len);
    return 0;
}

/* =====================================================================
 * HTTP request handling (runs in the httpd process)
 * ===================================================================== */
struct SrvCtx {
    Config  *cfg;
    Arena   *arena;
    int      srv80, srv443;
    int      cgi_fd;
    int      log_fd;             /* access-log lines go to the master */
    int      stop;
};

static int ip_allowed(DirCfg *d, struct sockaddr_in *peer) {
    if (d->n_allow == 0) return 1;
    uint32_t ip = ntohl(peer->sin_addr.s_addr);
    for (int i = 0; i < d->n_allow; i++)
        if ((ip & d->allow[i].mask) == d->allow[i].net) return 1;
    return 0;
}

/* constant-time string comparison (no early exit on mismatch) */
static int ct_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    size_t n = la > lb ? la : lb;
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = i < la ? (unsigned char)a[i] : 0;
        unsigned char cb = i < lb ? (unsigned char)b[i] : 0;
        d |= (unsigned char)(ca ^ cb);
    }
    return d == 0;
}

static int auth_check(DirCfg *d, const char *hdr) {
    if (!d->auth_required) return 1;
    if (!hdr || strncasecmp(hdr, "Basic ", 6) != 0) return 0;
    unsigned char dec[512];
    int n = b64_decode(hdr + 6, dec, sizeof(dec) - 1);
    if (n <= 0) return 0;
    dec[n] = 0;
    char *colon = strchr((char*)dec, ':');
    if (!colon) return 0;
    *colon = 0;
    return ct_eq((char*)dec, d->auth_user) && ct_eq(colon + 1, d->auth_pass);
}

/* true if path, after symlink resolution, stays inside root */
static int path_within_root(const char *root, const char *path) {
    char rr[PATH_MAX], rp[PATH_MAX];
    if (!realpath(root, rr)) return 0;
    if (!realpath(path, rp)) return 0;
    size_t n = strlen(rr);
    return strncmp(rp, rr, n) == 0 && (rp[n] == 0 || rp[n] == '/');
}

/* Serve a static file (index.html if dir). */
static int serve_file(Conn *c, const char *root, const char *fullpath,
                      int head_only) {
    struct stat st;
    if (stat(fullpath, &st) < 0) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    if (!path_within_root(root, fullpath)) {
        errno = EACCES;      /* resolved outside the root: forbidden */
        return -1;
    }
    int f = open(fullpath, O_RDONLY | O_NOFOLLOW);
    if (f < 0) return -1;

    const char *ext = strrchr(fullpath, '.');
    const char *ct = "application/octet-stream";
    if      (ext && !strcasecmp(ext, ".html")) ct = "text/html; charset=utf-8";
    else if (ext && !strcasecmp(ext, ".htm"))  ct = "text/html; charset=utf-8";
    else if (ext && !strcasecmp(ext, ".css"))  ct = "text/css";
    else if (ext && !strcasecmp(ext, ".js"))   ct = "application/javascript";
    else if (ext && !strcasecmp(ext, ".json")) ct = "application/json";
    else if (ext && !strcasecmp(ext, ".png"))  ct = "image/png";
    else if (ext && !strcasecmp(ext, ".jpg"))  ct = "image/jpeg";
    else if (ext && !strcasecmp(ext, ".gif"))  ct = "image/gif";
    else if (ext && !strcasecmp(ext, ".svg"))  ct = "image/svg+xml";

    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Server: corehttpd\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %lld\r\n"
        "Connection: keep-alive\r\n\r\n",
        ct, (long long)st.st_size);
    if (n < 0 || (size_t)n >= sizeof(hdr)) { close(f); return -1; }
    if (send_all(c, hdr, (size_t)n) < 0) { close(f); return -1; }
    if (!head_only) {
        char buf[65536]; ssize_t r;
        while ((r = read(f, buf, sizeof(buf))) > 0)
            if (send_all(c, buf, (size_t)r) < 0) break;
    }
    close(f);
    return 0;
}

/* forward raw CGI output from cgi_fd to client; returns the status code */
static int relay_cgi(Conn *c, int cgi_fd, int head_only) {
    char buf[65536];
    int in_body = 0;
    int status = 200;
    size_t hdr_len = 0;
    char hdrbuf[8192];
    while (1) {
        ssize_t r = read(cgi_fd, buf, sizeof(buf));
        if (r <= 0) break;
        if (!in_body) {
            size_t csz = (size_t)r;
            if (hdr_len + csz >= sizeof(hdrbuf)) csz = sizeof(hdrbuf) - hdr_len - 1;
            memcpy(hdrbuf + hdr_len, buf, csz);
            hdr_len += csz;
            hdrbuf[hdr_len] = 0;
            char *e = strstr(hdrbuf, "\r\n\r\n");
            if (e) {
                /* honour a "Status:" header from the CGI program */
                char *line = hdrbuf;
                while (line < e) {
                    char *nl = strstr(line, "\r\n");
                    if (!nl) break;
                    if (!strncasecmp(line, "Status:", 7)) {
                        char st[256] = "200 OK";
                        const char *v = line + 7;
                        while (*v == ' ' || *v == '\t') v++;
                        size_t l = (size_t)(nl - v);
                        if (l >= sizeof st) l = sizeof st - 1;
                        memcpy(st, v, l);
                        st[l] = 0;
                        char *s = trim(st);
                        status = atoi(s);
                        if (head_only) {
                            char h[1024];
                            int hn = snprintf(h, sizeof(h),
                                "HTTP/1.1 %s\r\nServer: corehttpd\r\n"
                                "Connection: keep-alive\r\n\r\n", s);
                            if (hn < 0 || (size_t)hn >= sizeof(h)) return 502;
                            send_all(c, h, (size_t)hn);
                        }
                        break;
                    }
                    line = nl + 2;
                }
                in_body = 1;
            }
        }
        if (!head_only) {
            if (send_all(c, buf, (size_t)r) < 0) break;
        }
    }
    return status;
}

/* Match the request's remaining relative path against the effective dir's
 * CGI list.  Longest name wins so "foo/bar" beats "foo".  On match,
 * *path_info is set to the URL suffix after the matched name (possibly
 * the empty string). */
static CgiProgram *cgi_lookup(DirCfg *d, const char *rest, const char **path_info) {
    CgiProgram *best = NULL;
    size_t best_len = 0;
    const char *best_tail = NULL;
    for (int i = 0; i < d->n_cgi; i++) {
        const char *n = d->cgi[i].name;
        if (!n) continue;
        size_t nl = strlen(n);
        if (strncmp(rest, n, nl) == 0 && (rest[nl] == 0 || rest[nl] == '/')) {
            if (nl > best_len) {
                best = &d->cgi[i];
                best_len = nl;
                best_tail = rest + nl;
            }
        }
    }
    if (path_info && best) *path_info = best_tail;
    return best;
}

/* format into the arena; NULL when exhausted.  Avoids the raw
 * arena_alloc + sprintf pattern, which dereferences NULL on OOM. */
static char *arena_sprintf(Arena *a, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return NULL;
    char *p = arena_alloc(a, (size_t)n + 1);
    if (!p) return NULL;
    va_start(ap, fmt);
    vsnprintf(p, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return p;
}

/* Build one Apache-style access-log line and ship it to the master
 * (which writes it to disk). */
static void access_log_request(struct SrvCtx *ctx,
                               const struct sockaddr_in *peer,
                               const HttpRequest *req,
                               const char *auth_user,
                               int status, uint64_t nbytes) {
    if (ctx->log_fd < 0) return;
    char ip[INET_ADDRSTRLEN] = "-";
    inet_ntop(AF_INET, &peer->sin_addr, ip, sizeof ip);
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[64];
    strftime(ts, sizeof ts, "%d/%b/%Y:%H:%M:%S %z", &tm);
    char line[2048];
    int n = snprintf(line, sizeof line,
        "%s - %s [%s] \"%s %s%s%s %s\" %d %llu\n",
        ip,
        auth_user ? auth_user : "-",
        ts,
        req->method ? req->method : "-",
        req->path ? req->path : "-",
        req->query && *req->query ? "?" : "",
        req->query ? req->query : "",
        req->version ? req->version : "-",
        status, (unsigned long long)nbytes);
    if (n < 0) return;
    if (n >= (int)sizeof line) {
        n = (int)sizeof line - 1;
        line[n - 1] = '\n';    /* keep lines intact when truncated */
    }
    send_fd_all(ctx->log_fd, line, (size_t)n);
}

/* wait for the next request on a keep-alive connection.  Returns 1 when
 * request data is pending, 0 when the wait expired, -1 when a new
 * connection is pending on a listening socket (single-threaded server:
 * the idle keep-alive connection is dropped in favour of new work). */
static int wait_keepalive(struct SrvCtx *ctx, Conn *c, int secs) {
    if (c->tls && tls_pending(c->tls)) return 1;
    struct pollfd p[3] = {
        { c->fd, POLLIN, 0 },
        { ctx->srv80, POLLIN, 0 },
        { ctx->srv443, POLLIN, 0 },
    };
    int r = poll(p, 3, secs * 1000);
    if (r <= 0) return r;                 /* 0 = timeout, -1 = error */
    if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) return 1;
    return -1;                            /* new connection pending */
}

/* Main per‑connection handler. */
static void handle_connection(struct SrvCtx *ctx, int fd, int is_tls) {
    struct sockaddr_in peer; socklen_t pl = sizeof(peer);
    getpeername(fd, (struct sockaddr *)&peer, &pl);
    char ip[INET_ADDRSTRLEN] = "-";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);

    Conn conn = { fd, NULL, 0 };
    if (is_tls) {
        conn.tls = tls_server_handshake(ctx->arena, fd, ctx->cfg->tls_key,
                                        pick_site_key, ctx->cfg,
                                        ctx->cfg->def_header_timeout);
        if (!conn.tls) {
            log_warn("TLS handshake failed (client %s)", ip);
            close(fd);
            return;
        }
    }

    int first = 1;
    for (;;) {
        arena_reset(ctx->arena);

        if (!first) {
            /* keep-alive: wait for the next request, but let new
             * connections preempt the idle one */
            if (wait_keepalive(ctx, &conn, ctx->cfg->def_header_timeout) <= 0)
                break;
        }
        first = 0;

        uint64_t bytes0 = conn.nbytes;
        int status = 500;
        const char *auth_user = NULL;

        HttpRequest req;
        int r = http_read_request(ctx->arena, &conn, &req,
                                  ctx->cfg->def_header_timeout,
                                  ctx->cfg->def_body_timeout);
        if (r < 0) {
            log_debug("client %s: request read failed or timed out", ip);
            break;
        }

        SiteCfg *site = config_find_site(ctx->cfg, req.host);
        if (!site) {
            status = 404;
            http_send_simple(&conn, 404, "Not Found", NULL, "no site", 7, 0);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            break;
        }

        /* mutate a scratch copy of the path for walking */
        char *path_scratch = arena_strdup(ctx->arena, req.path);
        int head_only = !strcmp(req.method, "HEAD");
        char *rest = NULL;
        char fs_path[2048];
        DirCfg *eff = config_walk(site->root, path_scratch, &rest,
                                  fs_path, sizeof fs_path);
        if (!eff) {
            status = 414;
            http_send_simple(&conn, 414, "URI Too Long", NULL,
                             "uri too long\n", 13, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
            continue;
        }

        /* ---- port 80: redirect / letsencrypt / GET-HEAD only ---- */
        if (!is_tls) {
            if (strcmp(req.method, "GET") && strcmp(req.method, "HEAD")) {
                status = 405;
                http_send_simple(&conn, 405, "Method Not Allowed",
                                 "Allow: GET, HEAD\r\n", "no\r\n", 4, head_only);
                access_log_request(ctx, &peer, &req, NULL, status,
                                   conn.nbytes - bytes0);
                if (!req.keep_alive) break;
		continue;
            }
            if (req.path && !strncmp(req.path, "/.well-known/acme-challenge/", 28)) {
                char full[1024];
                const char *le_root = ctx->cfg->letsencrypt_root
                                    ? ctx->cfg->letsencrypt_root
                                    : "/var/www/letsencrypt";
                snprintf(full, sizeof(full), "%s/%s", le_root, req.path + 28);
                if (serve_file(&conn, le_root, full, head_only) < 0) {
                    status = 404;
                    http_send_simple(&conn, 404, "Not Found", NULL, "not found\n", 10, head_only);
                } else {
                    status = 200;
                }
            } else {
                status = 301;
                char loc[1024];
                snprintf(loc, sizeof(loc), "Location: https://%s%s\r\n",
                         req.host ? req.host : site->name, req.path);
                http_send_simple(&conn, 301, "Moved Permanently", loc, "", 0, head_only);
            }
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
            continue;
        }

        /* ---- restrictions ---- */
        if (!ip_allowed(eff, &peer)) {
            status = 403;
            http_send_simple(&conn, 403, "Forbidden", NULL, "forbidden\n", 10, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
	    continue;
        }
        if (!auth_check(eff, req.authorization)) {
            status = 401;
            http_send_simple(&conn, 401, "Unauthorized",
                "WWW-Authenticate: Basic realm=\"corehttpd\"\r\n",
                "auth required\n", 14, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
	    continue;
        }
        if (eff->auth_required) auth_user = eff->auth_user;

        /* ---- CGI dispatch (per-dir) ---- */
        {
            const char *rest_n = rest;
            while (*rest_n == '/') rest_n++;

            const char *path_info = NULL;
            CgiProgram *cp = cgi_lookup(eff, rest_n, &path_info);
            if (cp) {
                /* Where to exec from: absolute path, relative-to-dir path,
                 * or the matched file under the effective dir. */
                char prog_path[2048];
                if (cp->path) {
                    const char *pp = cp->path;
                    size_t l = strlen(pp);
                    if (pp[0] == '/') {
                        if (l + 1 > sizeof(prog_path)) goto cgi_toolong;
                        memcpy(prog_path, pp, l + 1);
                    } else {
                        size_t fl2 = strlen(fs_path);
                        if (fl2 + 1 + l + 1 > sizeof(prog_path))
                            goto cgi_toolong;
                        memcpy(prog_path, fs_path, fl2);
                        prog_path[fl2] = '/';
                        memcpy(prog_path + fl2 + 1, pp, l + 1);
                    }
                } else {
                    size_t plen = (size_t)(path_info - rest_n);
                    size_t fl2 = strlen(fs_path);
                    if (fl2 + 1 + plen + 1 > sizeof(prog_path))
                        goto cgi_toolong;
                    memcpy(prog_path, fs_path, fl2);
                    prog_path[fl2] = '/';
                    memcpy(prog_path + fl2 + 1, rest_n, plen);
                    prog_path[fl2 + 1 + plen] = 0;
                }

                const char *user = cp->user ? cp->user : ctx->cfg->cgi_user;

                /* SCRIPT_NAME = original URL path up to end of the CGI
                 * name.  path_info points right after it in path_scratch. */
                size_t sn_len = (size_t)(path_info - path_scratch);
                char *script_name = arena_alloc(ctx->arena, sn_len + 1);
                if (!script_name) goto cgi_nomem;
                memcpy(script_name, path_scratch, sn_len);
                script_name[sn_len] = 0;

                char *req_uri = arena_sprintf(ctx->arena, "%s%s%s", req.path,
                        req.query ? "?" : "", req.query ? req.query : "");
                if (!req_uri) goto cgi_nomem;

                char *env[24]; int ne = 0;
                char *t;
                env[ne++] = "GATEWAY_INTERFACE=CGI/1.1";
                env[ne++] = "SERVER_PROTOCOL=HTTP/1.1";
                if (!(t = arena_sprintf(ctx->arena, "REQUEST_METHOD=%s", req.method))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "REQUEST_URI=%s", req_uri))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "QUERY_STRING=%s", req.query ? req.query : ""))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "CONTENT_TYPE=%s", "application/octet-stream"))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "CONTENT_LENGTH=%zu", req.body_len))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "SCRIPT_NAME=%s", script_name))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "SCRIPT_FILENAME=%s", prog_path))) goto cgi_nomem;
                env[ne++] = t;
                if (!(t = arena_sprintf(ctx->arena, "DOCUMENT_ROOT=%s", fs_path))) goto cgi_nomem;
                env[ne++] = t;
                if (path_info && *path_info) {
                    if (!(t = arena_sprintf(ctx->arena, "PATH_INFO=%s", path_info))) goto cgi_nomem;
                    env[ne++] = t;
                }
                env[ne] = NULL;

                if (cgi_dispatch(ctx->arena, ctx->cgi_fd, prog_path, user,
                                 env, ne, req.body, req.body_len) < 0) {
                    status = 502;
                    log_warn("client %s: cgi dispatch failed for %s",
                             ip, prog_path);
                    http_send_simple(&conn, 502, "Bad Gateway", NULL, "cgi\n", 4, head_only);
                } else {
                    status = relay_cgi(&conn, ctx->cgi_fd, head_only);
                }
                access_log_request(ctx, &peer, &req, auth_user, status,
                                   conn.nbytes - bytes0);
                if (!req.keep_alive) break;
                continue;
            }
        }

        /* ---- static file ---- */
        char full[2048];
        int fl = snprintf(full, sizeof(full), "%s/%s", fs_path, rest);
        if (fl < 0 || (size_t)fl >= sizeof(full)) {
            status = 414;
            http_send_simple(&conn, 414, "URI Too Long", NULL, "uri too long\n", 13, head_only);
            access_log_request(ctx, &peer, &req, auth_user, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
            continue;
        }
        if (rest[0] == 0 || rest[strlen(rest) - 1] == '/') {
            /* directory: append "index.html" in place, bounded */
            size_t flen = strlen(full);
            static const char suffix[] = "/index.html";   /* 11 + NUL */
            if (flen + sizeof(suffix) > sizeof(full)) {
                status = 414;
                http_send_simple(&conn, 414, "URI Too Long", NULL, "uri too long\n", 13, head_only);
                access_log_request(ctx, &peer, &req, auth_user, status,
                                   conn.nbytes - bytes0);
                if (!req.keep_alive) break;
                continue;
            }
            memcpy(full + flen, suffix, sizeof(suffix));
            if (serve_file(&conn, fs_path, full, head_only) < 0) {
                /* a missing index.html is "not found"; an unreadable
                 * file is "forbidden" (the httpd process reads files —
                 * authentication does not grant filesystem access) */
                int nf = (errno == ENOENT || errno == ENOTDIR);
                status = nf ? 404 : 403;
                log_debug("client %s: %s: %s", ip, full, strerror(errno));
                http_send_simple(&conn, status,
                                 nf ? "Not Found" : "Forbidden", NULL,
                                 nf ? "not found\n" : "forbidden\n", 10,
                                 head_only);
            } else {
                status = 200;
            }
        } else {
            if (serve_file(&conn, fs_path, full, head_only) < 0) {
                int nf = (errno == ENOENT || errno == ENOTDIR);
                status = nf ? 404 : 403;
                log_debug("client %s: %s: %s", ip, full, strerror(errno));
                http_send_simple(&conn, status,
                                 nf ? "Not Found" : "Forbidden", NULL,
                                 nf ? "not found\n" : "forbidden\n", 10,
                                 head_only);
            } else {
                status = 200;
            }
        }
        access_log_request(ctx, &peer, &req, auth_user, status,
                           conn.nbytes - bytes0);
        if (!req.keep_alive) break;
        continue;

cgi_nomem:
        status = 500;
        http_send_simple(&conn, 500, "Internal Server Error", NULL, "nomem\n", 6, head_only);
        access_log_request(ctx, &peer, &req, auth_user, status,
                           conn.nbytes - bytes0);
        if (!req.keep_alive) break;
        continue;

cgi_toolong:
        status = 502;
        http_send_simple(&conn, 502, "Bad Gateway", NULL, "cgi\n", 4, head_only);
        access_log_request(ctx, &peer, &req, auth_user, status,
                           conn.nbytes - bytes0);
        if (!req.keep_alive) break;
        continue;
    }

    if (conn.tls) tls_close(conn.tls);
    close(fd);
}

/* =====================================================================
 * httpd process
 * ===================================================================== */
static struct SrvCtx *g_ctx;
static void on_term(int sig) { (void)sig; if (g_ctx) g_ctx->stop = 1; }

static void run_httpd(struct SrvCtx *ctx) {
    g_ctx = ctx;
    signal(SIGTERM, on_term);
    signal(SIGINT,  on_term);

    struct pollfd pfds[2] = {
        { .fd = ctx->srv80,  .events = POLLIN },
        { .fd = ctx->srv443, .events = POLLIN },
    };

    while (!ctx->stop) {
        int r = poll(pfds, 2, 500);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) continue;
        for (int i = 0; i < 2; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;
            struct sockaddr_in peer; socklen_t pl = sizeof(peer);
            int fd = accept(pfds[i].fd, (struct sockaddr *)&peer, &pl);
            if (fd < 0) continue;
            handle_connection(ctx, fd, i == 1);
        }
    }
}

/* =====================================================================
 * cgi process
 * ===================================================================== */
/* read exactly n bytes; the wire is a stream socketpair, so a single
 * read() may return a partial chunk */
static int read_all(int fd, void *buf, size_t n) {
    char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static int cgi_run_one(int cgi_fd) {
    struct CgiHdr h;
    if (read_all(cgi_fd, &h, sizeof(h)) < 0) return -1;

    char prog[1024], user[256];
    if (h.prog_len >= sizeof(prog) || h.user_len >= sizeof(user)) return -1;
    if (read_all(cgi_fd, prog, h.prog_len) < 0) return -1;
    prog[h.prog_len] = 0;
    if (read_all(cgi_fd, user, h.user_len) < 0) return -1;
    user[h.user_len] = 0;

    /* peer is a trusted socketpair, but stay defensive about wire values */
    if (h.nenv > 128 || h.body_len > (16u << 20)) return -1;

    char **env = calloc((size_t)h.nenv + 1, sizeof(char *));
    if (!env) return -1;

    int ret = -1;
    uint32_t ne = 0;
    char *body = NULL;

    for (; ne < h.nenv; ne++) {
        uint32_t kl, vl;
        if (read_all(cgi_fd, &kl, 4) < 0 || read_all(cgi_fd, &vl, 4) < 0)
            goto fail;
        if (kl > 4096 || vl > (1u << 20)) goto fail;
        char *e = malloc((size_t)kl + vl + 2);
        if (!e) goto fail;
        if (read_all(cgi_fd, e, kl) < 0) { free(e); goto fail; }
        e[kl] = '=';
        if (vl && read_all(cgi_fd, e + kl + 1, vl) < 0) {
            free(e); goto fail;
        }
        e[kl + 1 + vl] = 0;
        env[ne] = e;
    }

    if (h.body_len) {
        body = malloc(h.body_len);
        if (!body) goto fail;
        if (read_all(cgi_fd, body, h.body_len) < 0) goto fail;
    }

    pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        struct passwd *pw = getpwnam(user);
        if (!pw) {
            log_err("cgi: unknown user '%s' for %s", user, prog);
            _exit(126);
        }
        setgroups(0, NULL);
        if (setgid(pw->pw_gid) < 0) {
            log_err("cgi: setgid(%s) for %s: %s", user, prog, strerror(errno));
            _exit(126);
        }
        if (setuid(pw->pw_uid) < 0) {
            log_err("cgi: setuid(%s) for %s: %s", user, prog, strerror(errno));
            _exit(126);
        }

        int inp[2], outp[2];
        if (pipe(inp) < 0 || pipe(outp) < 0) {
            log_err("cgi: pipe for %s: %s", prog, strerror(errno));
            _exit(126);
        }
        pid_t p2 = fork();
        if (p2 == 0) {
            dup2(inp[0], 0); dup2(outp[1], 1);
            close(inp[0]); close(inp[1]); close(outp[0]); close(outp[1]);
            /* the CGI program must not inherit the control channel back
             * to the httpd (cgi_fd) or any other server fds: a rogue or
             * compromised CGI could otherwise read the next request's
             * parameters or forge responses.  Keep only the error log. */
            for (int i = 3; i < 1024; i++)
                if (i != g_errfd) close(i);
            execve(prog, (char *const[]){ (char *)prog, NULL }, env);
            log_err("cgi: execve %s: %s", prog, strerror(errno));
            _exit(127);
        }
        close(inp[0]); close(outp[1]);
        if (body) {
            size_t w = 0;
            while (w < h.body_len) {
                ssize_t k = write(inp[1], body + w, h.body_len - w);
                if (k <= 0) break;
                w += (size_t)k;
            }
        }
        close(inp[1]);
        char buf[65536]; ssize_t r;
        while ((r = read(outp[0], buf, sizeof(buf))) > 0)
            send_fd_all(cgi_fd, buf, (size_t)r);
        close(outp[0]);
        waitpid(p2, NULL, 0);
        _exit(0);
    }
    waitpid(pid, NULL, 0);
    ret = 0;

fail:
    for (uint32_t i = 0; i < ne; i++) free(env[i]);
    free(env);
    free(body);
    return ret;
}

static void run_cgi(int cgi_fd) {
    signal(SIGTERM, SIG_DFL);
    while (cgi_run_one(cgi_fd) == 0) {}
}

/* =====================================================================
 * master
 * ===================================================================== */
static int open_port(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); exit(1); }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port),
                             .sin_addr.s_addr = INADDR_ANY };
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); exit(1); }
    if (listen(fd, 128) < 0) { perror("listen"); exit(1); }
    return fd;
}

static void drop_to(const char *user) {
    struct passwd *pw = getpwnam(user);
    if (!pw) { log_err("unknown user %s", user); fprintf(stderr, "unknown user %s\n", user); exit(1); }
    if (setgroups(0, NULL) < 0) { log_err("setgroups: %s", strerror(errno)); perror("setgroups"); exit(1); }
    if (setgid(pw->pw_gid) < 0) { log_err("setgid: %s", strerror(errno)); perror("setgid"); exit(1); }
    if (setuid(pw->pw_uid) < 0) { log_err("setuid: %s", strerror(errno)); perror("setuid"); exit(1); }
}

/* =====================================================================
 * logging
 * ===================================================================== */
/* Error log: the master opens the file and the fd is inherited by the
 * httpd and cgi children, so every process can log.  When no file is
 * configured, messages go to stdout (which is what systemd collects);
 * with a file configured they are additionally mirrored to stdout in
 * the foreground. */
static int g_errfd = -1;
static int g_errlevel = 1;     /* 0 debug, 1 info, 2 warning, 3 error */
static int g_mirror = 1;       /* also write to stdout; off after daemonize */

static const char *err_level_name(int severity) {
    switch (severity) {
    case 0: return "debug";
    case 1: return "info";
    case 2: return "warning";
    default: return "error";
    }
}

static void log_msg(int severity, const char *msg) {
    if (severity < g_errlevel) return;
    char line[2048];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char ts[64];
    strftime(ts, sizeof ts, "%a %b %d %H:%M:%S %Y", &tm);
    int n = snprintf(line, sizeof line, "[%s] [%s] %s\n",
                     ts, err_level_name(severity), msg);
    if (n < 0) return;
    if (n >= (int)sizeof line) n = (int)sizeof line - 1;
    if (g_errfd >= 0) {
        ssize_t w = write(g_errfd, line, (size_t)n);
        (void)w;
        if (g_mirror) {
            w = write(1, line, (size_t)n);
            (void)w;
        }
    } else {
        ssize_t w = write(1, line, (size_t)n);
        (void)w;
    }
}

static void log_err(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log_msg(3, buf);
}

static void log_warn(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log_msg(2, buf);
}

static void log_info(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log_msg(1, buf);
}

static void log_debug(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log_msg(0, buf);
}

/* parse "user", "user:group", "uid", "uid:gid"; -1 entries mean "leave" */
static int owner_ids(const char *spec, uid_t *uid, gid_t *gid) {
    char buf[128];
    if (!spec || !*spec) { *uid = (uid_t)-1; *gid = (gid_t)-1; return 0; }
    snprintf(buf, sizeof buf, "%s", spec);
    char *colon = strchr(buf, ':');
    char *uname = buf, *gname = NULL;
    if (colon) { *colon = 0; gname = colon + 1; }
    if (uname[0] >= '0' && uname[0] <= '9') {
        *uid = (uid_t)strtoul(uname, NULL, 10);
    } else {
        struct passwd *pw = getpwnam(uname);
        if (!pw) return -1;
        *uid = pw->pw_uid;
    }
    if (gname) {
        if (gname[0] >= '0' && gname[0] <= '9') {
            *gid = (gid_t)strtoul(gname, NULL, 10);
        } else {
            struct group *gr = getgrnam(gname);
            if (!gr) return -1;
            *gid = gr->gr_gid;
        }
    } else {
        *gid = (gid_t)-1;
    }
    return 0;
}

/* Load the separate error-log config file (jsonc):
 *   { "file": "...", "owner": "user[:group]", "mode": "0640",
 *     "level": "debug"|"info"|"warning"|"error" }
 * Missing or broken config falls back to stdout-only logging (silently
 * so for the default path; with a note when explicitly requested). */
static void errorlog_init(Arena *a, const char *path, int explicit_flag) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (explicit_flag || errno != ENOENT)
            fprintf(stderr, "corehttpd: error-log config %s: %s (logging to stdout)\n",
                    path, strerror(errno));
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return; }
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 65536) {
        fclose(f);
        fprintf(stderr, "corehttpd: error-log config %s too large\n", path);
        return;
    }
    char *raw = arena_alloc(a, (size_t)sz + 1);
    if (!raw) { fclose(f); return; }
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return; }
    raw[sz] = 0;
    fclose(f);

    char *js = strip_jsonc(a, raw);
    if (!js) {
        fprintf(stderr, "corehttpd: error-log config %s: out of memory\n", path);
        return;
    }
    json_error_t err;
    json_t *root = json_loads(js, 0, &err);
    if (!root) {
        fprintf(stderr, "corehttpd: error-log config %s: %s\n", path, err.text);
        return;
    }

    const char *level = j_str(root, "level");
    if (level) {
        if (!strcmp(level, "debug")) g_errlevel = 0;
        else if (!strcmp(level, "info")) g_errlevel = 1;
        else if (!strcmp(level, "warning")) g_errlevel = 2;
        else if (!strcmp(level, "error")) g_errlevel = 3;
    }

    const char *file = j_str(root, "file");
    if (file) {
        int mode = j_mode(root, "mode", 0640);
        int fd = open(file, O_WRONLY | O_CREAT | O_APPEND, mode);
        if (fd < 0) {
            fprintf(stderr, "corehttpd: error log %s: %s\n", file, strerror(errno));
        } else {
            (void)fchmod(fd, (mode_t)mode);
            const char *owner = j_str(root, "owner");
            if (owner) {
                uid_t uid; gid_t gid;
                if (owner_ids(owner, &uid, &gid) == 0) {
                    if (fchown(fd, uid, gid) < 0)
                        fprintf(stderr, "corehttpd: fchown error log: %s\n",
                                strerror(errno));
                } else {
                    fprintf(stderr, "corehttpd: error log owner '%s': unknown user/group\n",
                            owner);
                }
            }
            g_errfd = fd;
        }
    }
    json_decref(root);
}

/* Open the access log with the configured ownership/mode.  Written only
 * by the master; O_APPEND keeps lines from several instances intact. */
static int accesslog_open(const Config *cfg) {
    if (!cfg->access_log || !*cfg->access_log) return -1;
    int mode = cfg->access_log_mode >= 0 ? cfg->access_log_mode : 0640;
    int fd = open(cfg->access_log, O_WRONLY | O_CREAT | O_APPEND, mode);
    if (fd < 0) {
        log_err("access log %s: %s", cfg->access_log, strerror(errno));
        return -1;
    }
    if (cfg->access_log_mode >= 0) (void)fchmod(fd, (mode_t)mode);
    if (cfg->access_log_owner && *cfg->access_log_owner) {
        uid_t uid; gid_t gid;
        if (owner_ids(cfg->access_log_owner, &uid, &gid) == 0) {
            if (fchown(fd, uid, gid) < 0)
                log_warn("access log fchown: %s", strerror(errno));
        } else {
            log_err("access log owner '%s': unknown user/group",
                    cfg->access_log_owner);
        }
    }
    return fd;
}

/* classic double-fork daemonization */
static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) { log_err("fork: %s", strerror(errno)); exit(1); }
    if (pid > 0) _exit(0);
    if (setsid() < 0) { log_err("setsid: %s", strerror(errno)); exit(1); }
    pid = fork();
    if (pid < 0) { log_err("fork: %s", strerror(errno)); exit(1); }
    if (pid > 0) _exit(0);
    if (chdir("/") < 0) log_warn("chdir(/): %s", strerror(errno));
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        int out = g_errfd >= 0 ? g_errfd : devnull;
        (void)dup2(devnull, 0);
        (void)dup2(out, 1);
        (void)dup2(out, 2);
        if (devnull > 2) close(devnull);
    }
    g_mirror = 0;              /* stderr now points at the error log */
}

/* Read access-log lines from the socket and write them to outfd.
 * Lines arrive whole (one send per line); O_APPEND keeps them intact. */
static void drain_log_lines(int sockfd, int outfd) {
    static char acc[8192];
    static size_t acclen = 0;
    char buf[4096];
    for (;;) {
        ssize_t r = read(sockfd, buf, sizeof buf);
        if (r <= 0) return;
        for (ssize_t i = 0; i < r; i++) {
            if (acclen < sizeof acc - 1) acc[acclen++] = buf[i];
            if (buf[i] == '\n' || acclen == sizeof acc - 1) {
                ssize_t w = write(outfd, acc, acclen);
                (void)w;
                acclen = 0;
            }
        }
    }
}

static int g_sigpipe_w = -1;
static void on_sig(int sig) {
    int e = errno;
    if (g_sigpipe_w >= 0) {
        ssize_t r = write(g_sigpipe_w, &sig, sizeof sig);
        (void)r;
    }
    errno = e;
}

static void usage(FILE *out) {
    fprintf(out,
        "Usage: corehttpd [OPTIONS] [CONFIG]\n"
        "\n"
        "Minimal HTTP/1.1 + TLS 1.3 web server.\n"
        "\n"
        "Arguments:\n"
        "  CONFIG              path to the JSONC configuration file\n"
        "                      (default: /etc/corehttpd/config.jsonc)\n"
        "\n"
        "Options:\n"
        "  -h, --help          show this help and exit\n"
        "  -d, --daemonize     run in the background (for systems without\n"
        "                      a service manager such as systemd)\n"
        "  -e, --error-log-config PATH\n"
        "                      separate JSONC file configuring the error\n"
        "                      log (default: /etc/corehttpd/errorlog.jsonc)\n"
        "\n"
        "corehttpd must be started as root: it binds ports 80 and 443 and\n"
        "then drops privileges to the user configured as httpd_user.  The\n"
        "TLS certificate and private key are read once by the master\n"
        "process at startup, so the private key does not need to be\n"
        "readable by the httpd user.\n"
        "\n"
        "Signals:\n"
        "  SIGTERM, SIGINT     graceful shutdown: let the current request\n"
        "                      finish, stop the CGI broker, exit\n"
        "\n"
        "Examples:\n"
        "  corehttpd\n"
        "  corehttpd --daemonize /etc/corehttpd/config.jsonc\n"
        "\n"
        "See the README for the configuration file formats.\n");
}

int main(int argc, char **argv) {
    const char *cfgpath = "/etc/corehttpd/config.jsonc";
    const char *errcfg = "/etc/corehttpd/errorlog.jsonc";
    int daemon = 0;
    int errcfg_explicit = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--daemonize")) {
            daemon = 1;
        } else if (!strcmp(argv[i], "-e") ||
                   !strcmp(argv[i], "--error-log-config")) {
            if (i + 1 >= argc) {
                fprintf(stderr, "corehttpd: option %s needs an argument\n", argv[i]);
                usage(stderr);
                return 1;
            }
            errcfg = argv[++i];
            errcfg_explicit = 1;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "corehttpd: unknown option: %s\n", argv[i]);
            usage(stderr);
            return 1;
        } else {
            cfgpath = argv[i];
        }
    }

    /* EPIPE instead of SIGPIPE death when a client goes away mid-write */
    signal(SIGPIPE, SIG_IGN);

    Arena master_arena;
    arena_init(&master_arena, 10u << 20);

    errorlog_init(&master_arena, errcfg, errcfg_explicit);
    log_info("corehttpd starting, config %s", cfgpath);

    Config *cfg = config_load(&master_arena, cfgpath);
    if (!cfg) { log_err("config load failed"); return 1; }

    /* default certificate for connections without (or with unknown) SNI:
     * the global cert, or failing that the first site's certificate */
    if (!cfg->tls_key) {
        for (int i = 0; i < cfg->n_sites; i++)
            if (cfg->sites[i]->tls_key) {
                cfg->tls_key = cfg->sites[i]->tls_key;
                break;
            }
    }
    if (!cfg->tls_key)
        log_warn("no TLS certificate configured; port 443 will reject connections");

    int access_fd = accesslog_open(cfg);
    if (access_fd < 0 && !daemon) {
        /* no access-log file (or it could not be opened): in the
         * foreground, write access-log lines to stdout so systemd (or a
         * terminal) collects them; daemonized stdout is /dev/null */
        access_fd = 1;
    }

    if (daemon) daemonize();

    int srv80  = open_port(80);
    int srv443 = open_port(443);
    log_info("listening on ports 80 and 443");

    /* httpd -> master channel carrying access-log lines */
    int log_pair[2] = { -1, -1 };
    if (access_fd >= 0 &&
        socketpair(AF_UNIX, SOCK_STREAM, 0, log_pair) < 0) {
        log_err("socketpair (access log): %s", strerror(errno));
        return 1;
    }

    int cgi_pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cgi_pair) < 0) {
        log_err("socketpair (cgi): %s", strerror(errno));
        return 1;
    }

    /* self-pipe so signals wake the master out of poll() */
    int sigpipe[2];
    if (pipe(sigpipe) < 0) { log_err("pipe: %s", strerror(errno)); return 1; }
    g_sigpipe_w = sigpipe[1];
    {
        int fl = fcntl(sigpipe[0], F_GETFL, 0);
        if (fl >= 0) fcntl(sigpipe[0], F_SETFL, fl | O_NONBLOCK);
    }
    if (log_pair[0] >= 0) {
        int fl = fcntl(log_pair[0], F_GETFL, 0);
        if (fl >= 0) fcntl(log_pair[0], F_SETFL, fl | O_NONBLOCK);
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_sig;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* cgi child */
    pid_t cgi_pid = fork();
    if (cgi_pid == 0) {
        close(srv80); close(srv443);
        close(cgi_pair[0]);
        if (log_pair[0] >= 0) close(log_pair[0]);
        if (log_pair[1] >= 0) close(log_pair[1]);
        close(sigpipe[0]); close(sigpipe[1]);
        if (access_fd > 2) close(access_fd);
        /* cgi broker runs privileged so it can setuid per program */
        run_cgi(cgi_pair[1]);
        _exit(0);
    }
    close(cgi_pair[1]);

    /* httpd child */
    pid_t httpd_pid = fork();
    if (httpd_pid == 0) {
        drop_to(cfg->httpd_user);
        if (log_pair[0] >= 0) close(log_pair[0]);
        close(sigpipe[0]); close(sigpipe[1]);
        if (access_fd > 2) close(access_fd);
        Arena *ar = mmap(NULL, sizeof(Arena), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        arena_init(ar, cfg->arena_size);
        struct SrvCtx ctx = {
            .cfg = cfg, .arena = ar,
            .srv80 = srv80, .srv443 = srv443,
            .cgi_fd = cgi_pair[0], .log_fd = log_pair[1], .stop = 0,
        };
        run_httpd(&ctx);
        _exit(0);
    }
    close(cgi_pair[0]);
    if (log_pair[1] >= 0) close(log_pair[1]);
    /* the master no longer needs the listening sockets: the httpd child
     * has its own copies, and the master never accepts from them.  Close
     * them so only the unprivileged httpd process holds ports 80/443. */
    close(srv80);
    close(srv443);
    /* note: sigpipe[1] stays open in the master — the signal handler
     * writes to it to wake the poll loop */
    log_info("master running (httpd pid %d, cgi pid %d)",
             (int)httpd_pid, (int)cgi_pid);

    /* master: write access-log lines to disk, react to signals */
    int stopping = 0;
    for (;;) {
        struct pollfd pfd[2];
        nfds_t nfds = 0;
        pfd[nfds].fd = sigpipe[0]; pfd[nfds].events = POLLIN; nfds++;
        if (log_pair[0] >= 0) {
            pfd[nfds].fd = log_pair[0];
            pfd[nfds].events = POLLIN;
            nfds++;
        }

        int pr = poll(pfd, nfds, 1000);
        if (pr < 0) {
            if (errno == EINTR) continue;
            log_err("poll: %s", strerror(errno));
            break;
        }

        if (pfd[0].revents & POLLIN) {
            int sig = 0;
            while (read(sigpipe[0], &sig, sizeof sig) == (ssize_t)sizeof sig) {}
            if (!stopping) {
                stopping = 1;
                log_info("received signal %d, shutting down", sig);
                kill(httpd_pid, SIGTERM);
            }
        }

        if (nfds > 1 && (pfd[1].revents & POLLIN))
            drain_log_lines(log_pair[0], access_fd);
        if (nfds > 1 && (pfd[1].revents & (POLLHUP | POLLERR))) {
            if (!stopping) {
                stopping = 1;
                log_warn("httpd exited unexpectedly");
                kill(httpd_pid, SIGTERM);
            }
        }

        if (stopping) {
            int st;
            if (waitpid(httpd_pid, &st, WNOHANG) == httpd_pid) {
                if (log_pair[0] >= 0)
                    drain_log_lines(log_pair[0], access_fd);
                break;
            }
        }
    }

    kill(cgi_pid, SIGTERM);
    waitpid(cgi_pid, NULL, 0);
    if (access_fd > 2) close(access_fd);
    log_info("shutdown complete");
    return 0;
}
