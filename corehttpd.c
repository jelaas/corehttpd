#define _GNU_SOURCE
#include "corehttpd.h"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
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
/* zero everything handed out since the last reset (memory above "used"
 * is still zero from the previous reset or the initial mmap), so no
 * request data — credentials, bodies, TLS handshake buffers — survives
 * into the next request */
void arena_reset(Arena *a) {
    memset(a->base, 0, a->used);
    a->used = 0;
}

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

/* "a.b.c.d" or "a.b.c.d/n" (n = 0..32).  Strict: a typo must never turn
 * into an allow-all rule. */
static int parse_acl_entry(const char *s, Acl *out) {
    char buf[32];
    size_t l = strlen(s);
    if (l == 0 || l >= sizeof buf) return -1;
    memcpy(buf, s, l + 1);
    int bits = 32;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        const char *b = slash + 1;
        size_t bl = strlen(b);
        if (bl < 1 || bl > 2 || strspn(b, "0123456789") != bl) return -1;
        bits = atoi(b);
        if (bits > 32) return -1;
    }
    struct in_addr ia;
    if (inet_pton(AF_INET, buf, &ia) != 1) return -1;
    uint32_t mask = bits == 0 ? 0u : (0xffffffffu << (32 - bits));
    out->net  = ntohl(ia.s_addr) & mask;
    out->mask = mask;
    return 0;
}

/* parse an "ip_allow" array; any bad entry is a config error */
static int parse_acl(Arena *a, json_t *arr, Acl **out, int *n_out) {
    *out = NULL;
    *n_out = 0;
    if (!json_is_array(arr)) {
        fprintf(stderr, "config: ip_allow must be an array of addresses\n");
        return -1;
    }
    size_t len = json_array_size(arr);
    if (len == 0) {
        fprintf(stderr, "config: ip_allow is empty (omit it to allow "
                "everyone)\n");
        return -1;
    }
    if (len > 4096) {
        fprintf(stderr, "config: ip_allow has too many entries\n");
        return -1;
    }
    Acl *o = arena_alloc(a, sizeof(Acl) * len);
    if (!o) {
        fprintf(stderr, "config: out of memory (ip_allow)\n");
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        const char *s = json_string_value(json_array_get(arr, i));
        if (!s || parse_acl_entry(s, &o[i]) < 0) {
            fprintf(stderr, "config: bad ip_allow entry %s%s%s\n",
                    s ? "\"" : "", s ? s : "(not a string)", s ? "\"" : "");
            return -1;
        }
    }
    *out = o;
    *n_out = (int)len;
    return 0;
}

/* Intersect two allow-lists: an address is allowed only if both lists
 * allow it.  Two prefixes overlap only if they agree on the bits of the
 * shorter one; the overlap is then the longer prefix.  An empty result
 * is valid and means "deny all". */
static int acl_intersect(Arena *a, const Acl *x, int nx, const Acl *y,
                         int ny, Acl **out, int *n_out) {
    *out = NULL;
    *n_out = 0;
    size_t cnt = (size_t)nx * (size_t)ny;
    if (cnt > a->size / sizeof(Acl)) return -1;
    Acl *o = arena_alloc(a, sizeof(Acl) * (cnt ? cnt : 1));
    if (!o) return -1;
    int k = 0;
    for (int i = 0; i < nx; i++)
        for (int j = 0; j < ny; j++) {
            uint32_t common = x[i].mask & y[j].mask;
            if ((x[i].net ^ y[j].net) & common) continue;      /* disjoint */
            uint32_t mask = x[i].mask | y[j].mask;             /* longer prefix */
            o[k].net  = (x[i].net | y[j].net) & mask;
            o[k].mask = mask;
            k++;
        }
    *out = o;
    *n_out = k;
    return 0;
}

/* CGI programs must run as an existing, non-root user */
static int cgi_user_ok(const char *user) {
    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "config: CGI user '%s' does not exist\n", user);
        return 0;
    }
    if (pw->pw_uid == 0) {
        fprintf(stderr, "config: CGI user '%s' is root; CGI programs must "
                "not run as root\n", user);
        return 0;
    }
    return 1;
}

static DirCfg *parse_dir(Arena *a, json_t *j, DirCfg *parent,
                         const Config *cfg, const char *forced_name) {
    if (!json_is_object(j)) return NULL;
    DirCfg *d = arena_alloc(a, sizeof(*d));
    if (!d) { fprintf(stderr, "config: out of memory\n"); return NULL; }
    memset(d, 0, sizeof(*d));

    const char *nm = forced_name ? forced_name : j_str(j, "name");
    if (parent && (!nm || !*nm || strchr(nm, '/') ||
                   !strcmp(nm, ".") || !strcmp(nm, ".."))) {
        fprintf(stderr, "config: every subdir needs a \"name\" that is a "
                "single path component\n");
        return NULL;
    }
    if (nm && !(d->name = arena_strdup(a, nm))) {
        fprintf(stderr, "config: out of memory\n");
        return NULL;
    }

    /* deny: this directory (and everything below it) is not served.
     * Inherited, so a denied parent also covers configured children.
     * Anything but a JSON boolean is a config error (fail closed). */
    json_t *jdeny = json_object_get(j, "deny");
    if (jdeny && !json_is_boolean(jdeny)) {
        fprintf(stderr, "config: \"deny\" must be true or false\n");
        return NULL;
    }
    d->deny = json_is_true(jdeny) || (parent && parent->deny);

    /* ---- filesystem path ---- */
    const char *dr = j_str(j, "documentroot");
    if (!parent && !dr) {
        /* no silent default: a forgotten documentroot used to serve "/" */
        fprintf(stderr, "config: site %s needs a \"documentroot\"\n",
                nm ? nm : "?");
        return NULL;
    }
    if (dr && dr[0] != '/') {
        fprintf(stderr, "config: documentroot \"%s\" must be an absolute "
                "path\n", dr);
        return NULL;
    }
    if (dr) {
        if (!(d->path = arena_strdup(a, dr))) return NULL;
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
    } else {
        /* glob name (or a child of one): the real filesystem path is
         * derived per request from the matched URL component */
        d->path = NULL;
    }

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
        if (!d->auth_user || !d->auth_pass) return NULL;
    } else if (parent) {
        d->auth_required = parent->auth_required;
        d->auth_user     = parent->auth_user;
        d->auth_pass     = parent->auth_pass;
    }

    /* ---- ip ACL: inherited, intersected with the parent's ---- */
    json_t *jacl = json_object_get(j, "ip_allow");
    Acl *own = NULL;
    int n_own = 0;
    if (jacl && parse_acl(a, jacl, &own, &n_own) < 0) return NULL;
    if (parent && parent->acl_set) {
        d->acl_set = 1;
        if (!jacl) {
            d->allow = parent->allow;
            d->n_allow = parent->n_allow;
        } else if (acl_intersect(a, parent->allow, parent->n_allow,
                                 own, n_own, &d->allow, &d->n_allow) < 0) {
            fprintf(stderr, "config: out of memory (ip_allow)\n");
            return NULL;
        } else if (d->n_allow == 0) {
            log_warn("config: ip_allow of \"%s\" does not overlap its "
                     "parent's: nobody can access it", nm ? nm : "?");
        }
    } else if (jacl) {
        d->acl_set = 1;
        d->allow = own;
        d->n_allow = n_own;
    }

    /* ---- timeouts: free ---- */
    d->header_timeout    = j_timeout(j, "header_timeout",
                                 parent ? parent->header_timeout    : cfg->def_header_timeout);
    d->body_timeout      = j_timeout(j, "body_timeout",
                                 parent ? parent->body_timeout      : cfg->def_body_timeout);
    d->keepalive_timeout = j_timeout(j, "keepalive_timeout",
                                 parent ? parent->keepalive_timeout : cfg->def_keepalive);
    d->cgi_timeout       = j_timeout(j, "cgi_timeout",
                                 parent ? parent->cgi_timeout       : cfg->def_cgi_timeout);

    /* ---- cgi: per-directory only, not inherited from the parent ---- */
    json_t *jcgi = json_object_get(j, "cgi");
    if (json_is_array(jcgi)) {
        size_t nadd = json_array_size(jcgi);
        d->cgi = arena_alloc(a, sizeof(CgiProgram) * (nadd ? nadd : 1));
        if (!d->cgi) return NULL;
        for (size_t i = 0; i < nadd; i++) {
            json_t *e = json_array_get(jcgi, i);
            const char *name = j_str(e, "name");
            if (!name || !*name || name[0] == '/') {
                fprintf(stderr, "config: every cgi entry needs a relative "
                        "\"name\"\n");
                return NULL;
            }
            CgiProgram *slot = &d->cgi[d->n_cgi++];
            memset(slot, 0, sizeof(*slot));
            const char *pp = j_str(e, "path");
            const char *uu = j_str(e, "user");
            if (!cgi_user_ok(uu ? uu : cfg->cgi_user)) return NULL;
            slot->name = arena_strdup(a, name);
            slot->path = pp ? arena_strdup(a, pp) : NULL;
            slot->user = uu ? arena_strdup(a, uu) : NULL;
            if (!slot->name || (pp && !slot->path) || (uu && !slot->user))
                return NULL;
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
    if (!c) { fprintf(stderr, "config: out of memory\n"); json_decref(root); return NULL; }
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
    if (!c->httpd_user || !c->cgi_user ||
        (j_str(root, "cert_file") && !c->cert_file) ||
        (j_str(root, "key_file") && !c->key_file) ||
        (j_str(root, "letsencrypt_root") && !c->letsencrypt_root) ||
        (j_str(root, "access_log") && !c->access_log) ||
        (j_str(root, "access_log_owner") && !c->access_log_owner)) {
        fprintf(stderr, "config: out of memory\n");
        json_decref(root);
        return NULL;
    }

    json_t *defs = json_object_get(root, "defaults");
    c->def_header_timeout = j_timeout(defs, "header_timeout", 10);
    c->def_body_timeout   = j_timeout(defs, "body_timeout",   30);
    c->def_keepalive      = j_timeout(defs, "keepalive_timeout", 60);
    c->def_cgi_timeout    = j_timeout(defs, "cgi_timeout", 30);

    /* sites */
    json_t *sites = json_object_get(root, "sites");
    if (json_is_array(sites)) {
        size_t n = json_array_size(sites);
        c->sites = arena_alloc(a, sizeof(SiteCfg *) * (n ? n : 1));
        if (!c->sites) {
            fprintf(stderr, "config: out of memory\n");
            json_decref(root);
            return NULL;
        }
        for (size_t i = 0; i < n; i++) {
            json_t *s = json_array_get(sites, i);
            const char *sn = j_str(s, "name");
            if (!sn || !*sn) {
                fprintf(stderr, "config: every site needs a \"name\"\n");
                json_decref(root);
                return NULL;
            }
            SiteCfg *sc = arena_alloc(a, sizeof(*sc));
            if (!sc) {
                fprintf(stderr, "config: out of memory\n");
                json_decref(root);
                return NULL;
            }
            memset(sc, 0, sizeof(*sc));
            sc->name = arena_strdup(a, sn);
            sc->cert_file = arena_strdup(a, j_str(s, "cert_file"));
            sc->key_file  = arena_strdup(a, j_str(s, "key_file"));
            if (!sc->name || (j_str(s, "cert_file") && !sc->cert_file) ||
                (j_str(s, "key_file") && !sc->key_file)) {
                fprintf(stderr, "config: out of memory\n");
                json_decref(root);
                return NULL;
            }
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
            /* otherwise the matching glob pattern: any deny pattern
             * wins, then the longest, ties go to the first entry */
            size_t best = 0;
            for (int i = 0; i < cur->n_subdirs; i++) {
                DirCfg *c = cur->subdirs[i];
                const char *n = c->name;
                if (!n) continue;
                if (!(strchr(n, '*') || strchr(n, '?')) ||
                    !glob_match(n, p, clen)) continue;
                size_t nl = strlen(n);
                if (!m || (c->deny && !m->deny) ||
                    (c->deny == m->deny && nl > best)) {
                    m = c;
                    best = nl;
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
        if (cur->deny) {
            while (*p == '/') p++;   /* keep *rest consistent */
            break;                   /* deny covers the whole subtree */
        }
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
/* Wait for request data.  The read must finish by the absolute deadline,
 * each wait is limited to idle_s, and a connection that has been silent
 * for IDLE_PREEMPT_MS is given up as soon as another client waits. */
static int conn_wait(Conn *c, int64_t deadline, int idle_s) {
    if (c->tls && tls_pending(c->tls)) return 1;
    int64_t last = c->last_rx;
    if (c->tls && tls_last_rx(c->tls) > last) last = tls_last_rx(c->tls);
    return io_wait(c->fd, deadline, idle_s * 1000, c->pre_fd, &last) > 0;
}

static ssize_t conn_read(Conn *c, void *buf, size_t n) {
    ssize_t r;
    if (c->tls) r = tls_read(c->tls, buf, n);
    else do r = read(c->fd, buf, n); while (r < 0 && errno == EINTR);
    if (r > 0) c->last_rx = mono_ms();
    return r;
}

/* the socket has SO_SNDTIMEO set, so a client that stops reading makes
 * write() fail instead of blocking the server forever */
static int send_all(Conn *c, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = c->tls ? tls_write(c->tls, p, n) : write(c->fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
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

/* true if the URL path is absolute and has no "." or ".." segments */
static int path_is_clean(const char *path) {
    if (!path || path[0] != '/') return 0;
    for (const char *p = path; *p; ) {
        while (*p == '/') p++;
        const char *e = p;
        while (*e && *e != '/') e++;
        size_t l = (size_t)(e - p);
        if ((l == 1 && p[0] == '.') ||
            (l == 2 && p[0] == '.' && p[1] == '.')) return 0;
        p = e;
    }
    return 1;
}

/* =====================================================================
 * HTTP request parser
 * ===================================================================== */
#define MAX_HEADER_BYTES 8192

/* Request bodies and responses must move at no less than this average
 * rate (bytes/s) on top of the configured timeout.  A deadline per
 * transfer keeps a trickling client from holding the (single-connection)
 * server indefinitely while still allowing large transfers. */
#define MIN_TRANSFER_RATE 32768

/* read up to the blank line ending the header block.  NULL with
 * *err = -1 on I/O error/timeout, 431 when the block is too large. */
static char *read_headers(Arena *a, Conn *c, int64_t deadline, int idle_s,
                          size_t *out_len, size_t *out_extra, int *err) {
    size_t cap = MAX_HEADER_BYTES, len = 0, scanned = 0;
    *err = -1;
    char *buf = arena_alloc(a, cap);
    if (!buf) return NULL;
    while (len < cap) {
        if (!conn_wait(c, deadline, idle_s)) return NULL;
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
    *err = 431;
    return NULL;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

/* Bytes of the request line and header block: CR and LF only as CRLF
 * pairs, no NUL or other control characters (TAB is allowed).  Bare
 * LFs would otherwise be copied into log lines or response headers. */
static int header_bytes_ok(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)p[i];
        if (ch == '\r') {
            if (i + 1 >= n || p[i + 1] != '\n') return 0;
            i++;
            continue;
        }
        if (ch == '\t') continue;
        if (ch < 0x20 || ch == 0x7f) return 0;
    }
    return 1;
}

static const char TCHARS[] =
    "!#$%&'*+-.^_`|~0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* host name or IPv4 address, optionally ":port" */
static int host_ok(const char *h) {
    size_t n = strlen(h);
    if (n == 0 || n > 255) return 0;
    const char *colon = strchr(h, ':');
    size_t nl = colon ? (size_t)(colon - h) : n;
    if (nl == 0 || strspn(h, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "abcdefghijklmnopqrstuvwxyz0123456789.-") != nl)
        return 0;
    if (colon) {
        size_t pl = strlen(colon + 1);
        if (pl < 1 || pl > 5 || strspn(colon + 1, "0123456789") != pl)
            return 0;
    }
    return 1;
}

/* true if a comma-separated header value contains token tok */
static int has_token(const char *v, const char *tok) {
    size_t tl = strlen(tok);
    while (*v) {
        while (*v == ' ' || *v == '\t' || *v == ',') v++;
        const char *e = v;
        while (*e && *e != ',') e++;
        const char *t = e;
        while (t > v && (t[-1] == ' ' || t[-1] == '\t')) t--;
        if ((size_t)(t - v) == tl && !strncasecmp(v, tok, tl)) return 1;
        v = e;
    }
    return 0;
}

int http_read_request(Arena *a, Conn *c, HttpRequest *r,
                      int hdr_timeout, int body_timeout) {
    memset(r, 0, sizeof(*r));
    /* the whole header block must arrive within hdr_timeout */
    int64_t deadline = mono_ms() + (int64_t)hdr_timeout * 1000;
    if (c->tls) tls_set_deadline(c->tls, deadline);
    size_t hlen, extra;
    int err;
    char *raw = read_headers(a, c, deadline, hdr_timeout, &hlen, &extra, &err);
    if (!raw) return err;
    if (!header_bytes_ok(raw, hlen + 2)) return 400;

    /* request line: METHOD SP target SP HTTP/1.1 */
    char *nl = strstr(raw, "\r\n");
    if (!nl) return 400;
    *nl = 0;
    char *sp1 = strchr(raw, ' ');
    if (!sp1) return 400;
    *sp1 = 0;
    char *target = sp1 + 1;
    char *sp2 = strchr(target, ' ');
    if (!sp2) return 400;
    *sp2 = 0;
    r->method  = raw;
    r->path    = target;
    r->version = sp2 + 1;
    size_t ml = strlen(raw);
    if (ml < 1 || ml > 16 || strspn(raw, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != ml)
        return 400;
    if (!*target) return 400;
    for (const char *p = target; *p; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f) return 400;
    if (strcmp(r->version, "HTTP/1.1") != 0) return 505;

    char *q = strchr(r->path, '?');
    if (q) { *q = 0; r->query = q + 1; }
    r->keep_alive = 1;

    /* headers */
    int have_cl = 0;
    char *cur = nl + 2;
    while (*cur) {
        char *eol = strstr(cur, "\r\n");
        if (!eol) return 400;
        *eol = 0;
        if (*cur == ' ' || *cur == '\t') return 400;      /* obsolete folding */
        char *colon = strchr(cur, ':');
        if (!colon || colon == cur) return 400;
        *colon = 0;
        if (strspn(cur, TCHARS) != strlen(cur)) return 400;
        char *v = trim(colon + 1);
        if (!strcasecmp(cur, "Host")) {
            if (r->host || !host_ok(v)) return 400;
            r->host = v;
        } else if (!strcasecmp(cur, "Authorization")) {
            if (r->authorization) return 400;
            r->authorization = v;
        } else if (!strcasecmp(cur, "Content-Length")) {
            size_t vl = strlen(v);
            if (have_cl || vl < 1 || vl > 18 ||
                strspn(v, "0123456789") != vl) return 400;
            r->content_length = strtol(v, NULL, 10);
            have_cl = 1;
        } else if (!strcasecmp(cur, "Transfer-Encoding")) {
            return 501;                    /* chunked bodies: not supported */
        } else if (!strcasecmp(cur, "Connection")) {
            if (has_token(v, "close")) r->keep_alive = 0;
        }
        cur = eol + 2;
    }
    if (!r->host) return 400;              /* mandatory in HTTP/1.1 */

    /* body */
    if (r->content_length > 0) {
        if (r->content_length > (long)(a->size - a->used)) return 413;
        r->body = arena_alloc(a, (size_t)r->content_length + 1);
        if (!r->body) return 413;
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
        int64_t bdeadline = mono_ms() +
            ((int64_t)body_timeout + r->content_length / MIN_TRANSFER_RATE) * 1000;
        if (c->tls) tls_set_deadline(c->tls, bdeadline);
        while (got < (size_t)r->content_length) {
            if (!conn_wait(c, bdeadline, body_timeout)) return -1;
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
    if (c->tls) tls_set_deadline(c->tls, 0);
    return 0;
}

static int send_simple(Conn *c, int code, const char *reason,
                       const char *extra, const char *body,
                       size_t body_len, int head_only, int close_conn) {
    char hdr[MAX_HEADER_BYTES + 1024];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Server: corehttpd\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n", code, reason, body_len, close_conn ? "close" : "keep-alive",
        extra ? extra : "");
    if (n < 0 || (size_t)n >= sizeof(hdr)) return -1;
    if (send_all(c, hdr, (size_t)n) < 0) return -1;
    if (!head_only && body && body_len) {
        if (send_all(c, body, body_len) < 0) return -1;
    }
    return 0;
}

int http_send_simple(Conn *c, int code, const char *reason,
                     const char *extra, const char *body,
                     size_t body_len, int head_only) {
    return send_simple(c, code, reason, extra, body, body_len, head_only, 0);
}

static const char *status_reason(int code) {
    switch (code) {
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 413: return "Payload Too Large";
    case 414: return "URI Too Long";
    case 429: return "Too Many Requests";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 505: return "HTTP Version Not Supported";
    default:  return "Error";
    }
}

/* error response after which the connection is closed */
static void send_error_close(Conn *c, int code, int head_only) {
    char body[64];
    int bl = snprintf(body, sizeof body, "%d %s\n", code, status_reason(code));
    send_simple(c, code, status_reason(code), NULL, body, (size_t)bl,
                head_only, 1);
}

/* =====================================================================
 * CGI wire protocol (httpd <-> cgi broker)
 *
 * The httpd sends only the request (method, site, URL, query, body);
 * the broker resolves the program and user from its own copy of the
 * configuration.  The response comes back as frames: uint32 length +
 * data, a zero length ends it.
 * ===================================================================== */
#define CGI_MAX_BODY  (16u << 20)
#define CGI_MAX_FIELD MAX_HEADER_BYTES

struct CgiReq {
    uint32_t method_len, host_len, path_len, query_len, body_len;
};

static int cgi_send_request(int fd, const char *method, const char *host,
                            const char *path, const char *query,
                            const void *body, size_t body_len) {
    struct CgiReq h = {
        .method_len = (uint32_t)strlen(method),
        .host_len   = (uint32_t)strlen(host),
        .path_len   = (uint32_t)strlen(path),
        .query_len  = query ? (uint32_t)strlen(query) : 0,
        .body_len   = (uint32_t)body_len,
    };
    if (send_fd_all(fd, &h, sizeof h) < 0 ||
        send_fd_all(fd, method, h.method_len) < 0 ||
        send_fd_all(fd, host, h.host_len) < 0 ||
        send_fd_all(fd, path, h.path_len) < 0 ||
        (h.query_len && send_fd_all(fd, query, h.query_len) < 0) ||
        (body_len && send_fd_all(fd, body, body_len) < 0))
        return -1;
    return 0;
}

/* read exactly n bytes before the deadline */
static int read_full_deadline(int fd, void *buf, size_t n, int64_t deadline) {
    char *p = buf;
    while (n) {
        int64_t rem = deadline - mono_ms();
        if (rem <= 0) return -1;
        struct pollfd pf = { fd, POLLIN, 0 };
        int r = poll(&pf, 1, (int)rem);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        ssize_t k = read(fd, p, n);
        if (k < 0) { if (errno == EINTR || errno == EAGAIN) continue; return -1; }
        if (k == 0) return -1;
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

/* =====================================================================
 * HTTP request handling (runs in the httpd process)
 * ===================================================================== */
struct SrvCtx {
    Config  *cfg;
    Arena   *arena;
    int      srv80, srv443;
    int      cgi_fd;             /* -1 once the broker channel broke */
    int      log_fd;             /* access-log lines go to the master */
    int      stop;
};

static int ip_allowed(DirCfg *d, struct sockaddr_in *peer) {
    if (!d->acl_set) return 1;
    uint32_t ip = ntohl(peer->sin_addr.s_addr);
    for (int i = 0; i < d->n_allow; i++)
        if ((ip & d->allow[i].mask) == d->allow[i].net) return 1;
    return 0;                  /* includes an empty (no-overlap) list */
}

/* Constant-time comparison of a client-supplied string with a configured
 * secret.  The loop always runs over the whole secret, so the time
 * depends neither on where the strings differ nor on the secret's
 * length relative to the input. */
static int ct_eq(const char *given, const char *secret) {
    size_t lg = strlen(given), ls = strlen(secret);
    unsigned char d = 0;
    for (size_t i = 0; i < ls; i++) {
        unsigned char g = i < lg ? (unsigned char)given[i] : 0;
        d |= (unsigned char)(g ^ (unsigned char)secret[i]);
    }
    return (d == 0) & (lg == ls);
}

static int auth_check(DirCfg *d, const char *hdr) {
    if (!d->auth_required) return 1;
    if (!hdr || strncasecmp(hdr, "Basic ", 6) != 0) return 0;
    unsigned char dec[512];
    int ok = 0;
    int n = b64_decode(hdr + 6, dec, sizeof(dec) - 1);
    if (n > 0) {
        dec[n] = 0;
        char *colon = strchr((char*)dec, ':');
        if (colon) {
            *colon = 0;
            /* always compare both, so the time does not reveal whether
             * the user name was right */
            ok = ct_eq((char*)dec, d->auth_user) & ct_eq(colon + 1, d->auth_pass);
        }
    }
    explicit_bzero(dec, sizeof dec);
    return ok;
}

/* Failed Basic-auth attempts per client IP: after AUTHFAIL_MAX failures
 * within AUTHFAIL_WINDOW_MS the client gets 429 for protected paths
 * until the window ends.  A small fixed table; a colliding IP evicts
 * an older entry. */
#define AUTHFAIL_SLOTS     256
#define AUTHFAIL_MAX       10
#define AUTHFAIL_WINDOW_MS (60 * 1000)
static struct { uint32_t ip; int fails; int64_t start; } g_authfail[AUTHFAIL_SLOTS];

static unsigned authfail_slot(uint32_t ip) {
    return (ip * 2654435761u) >> 24;                /* 0..255 */
}

static int authfail_blocked(uint32_t ip) {
    unsigned s = authfail_slot(ip);
    return g_authfail[s].ip == ip && g_authfail[s].fails >= AUTHFAIL_MAX &&
           mono_ms() - g_authfail[s].start < AUTHFAIL_WINDOW_MS;
}

static void authfail_note(uint32_t ip, int failed) {
    unsigned s = authfail_slot(ip);
    int64_t now = mono_ms();
    if (!failed) {
        if (g_authfail[s].ip == ip) g_authfail[s].fails = 0;
        return;
    }
    if (g_authfail[s].ip != ip || now - g_authfail[s].start >= AUTHFAIL_WINDOW_MS) {
        g_authfail[s].ip = ip;
        g_authfail[s].fails = 0;
        g_authfail[s].start = now;
    }
    g_authfail[s].fails++;
}

static int path_prefix(const char *root, const char *p) {
    size_t n = strlen(root);
    if (n == 1 && root[0] == '/') return 1;
    return strncmp(p, root, n) == 0 && (p[n] == 0 || p[n] == '/');
}

/* Serve a regular file under root.  The file is opened first and the
 * check is made on the opened file (its resolved path must be inside
 * root and name the same inode), so swapping a symlink between check
 * and open does not help.  Returns 0 when served, -1 before anything
 * was sent (errno set), -2 when the response was cut short (the
 * connection must be closed). */
static int serve_file(Conn *c, const char *root, const char *fullpath,
                      int head_only, int send_timeout) {
    int f = open(fullpath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (f < 0) return -1;
    struct stat st, st2;
    char rr[PATH_MAX], rp[PATH_MAX];
    if (fstat(f, &st) < 0) { int e = errno; close(f); errno = e; return -1; }
    if (!S_ISREG(st.st_mode)) { close(f); errno = ENOENT; return -1; }
    if (!realpath(root, rr) || !realpath(fullpath, rp) || !path_prefix(rr, rp) ||
        stat(rp, &st2) < 0 || st2.st_dev != st.st_dev || st2.st_ino != st.st_ino) {
        close(f);
        errno = EACCES;      /* resolves outside the root (or raced): forbidden */
        return -1;
    }

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
    if (send_all(c, hdr, (size_t)n) < 0) { close(f); return -2; }
    if (!head_only) {
        /* send exactly st_size bytes (the announced length), at no less
         * than MIN_TRANSFER_RATE on average */
        int64_t deadline = mono_ms() +
            ((int64_t)send_timeout + st.st_size / MIN_TRANSFER_RATE) * 1000;
        char buf[65536];
        off_t left = st.st_size;
        while (left > 0) {
            if (mono_ms() > deadline) { close(f); return -2; }
            size_t want = left < (off_t)sizeof buf ? (size_t)left : sizeof buf;
            ssize_t r = read(f, buf, want);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { close(f); return -2; }      /* file shrank */
            if (send_all(c, buf, (size_t)r) < 0) { close(f); return -2; }
            left -= r;
        }
    }
    close(f);
    return 0;
}

/* Convert a CGI header block (lines ended by LF or CRLF) into an HTTP/1.1
 * response head.  "Status:" sets the status line (a "Location:" without
 * it means 302); "Connection:" is replaced, since the response is not
 * length-delimited and the connection is closed after it.  Returns the
 * length written to out, or -1 for malformed output. */
static int cgi_build_head(const char *h, size_t hl, char *out, size_t cap,
                          int *status) {
    char st[128] = "200 OK";
    int has_status = 0, has_location = 0;
    size_t lines_len = 0;
    char lines[8192];
    *status = 200;
    for (size_t i = 0; i < hl; ) {
        size_t e = i;
        while (e < hl && h[e] != '\n') e++;
        size_t le = e;
        if (le > i && h[le - 1] == '\r') le--;
        size_t ll = le - i;
        const char *line = h + i;
        i = e + 1;
        if (ll == 0) continue;
        for (size_t k = 0; k < ll; k++) {
            unsigned char ch = (unsigned char)line[k];
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) return -1;
        }
        const char *colon = memchr(line, ':', ll);
        if (!colon || colon == line) return -1;
        size_t nlen = (size_t)(colon - line);
        if (nlen == 6 && !strncasecmp(line, "Status", 6)) {
            const char *v = colon + 1;
            while (v < line + ll && (*v == ' ' || *v == '\t')) v++;
            size_t vl = (size_t)(line + ll - v);
            if (vl < 3 || vl >= sizeof st || v[0] < '1' || v[0] > '5' ||
                v[1] < '0' || v[1] > '9' || v[2] < '0' || v[2] > '9' ||
                (vl > 3 && v[3] != ' '))
                return -1;
            memcpy(st, v, vl);
            st[vl] = 0;
            *status = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
            has_status = 1;
            continue;
        }
        if (nlen == 10 && !strncasecmp(line, "Connection", 10)) continue;
        if (nlen == 8 && !strncasecmp(line, "Location", 8)) has_location = 1;
        if (lines_len + ll + 2 > sizeof lines) return -1;
        memcpy(lines + lines_len, line, ll);
        lines_len += ll;
        lines[lines_len++] = '\r';
        lines[lines_len++] = '\n';
    }
    if (!has_status && has_location) {
        snprintf(st, sizeof st, "302 Found");
        *status = 302;
    }
    int n = snprintf(out, cap, "HTTP/1.1 %s\r\nServer: corehttpd\r\n"
                     "Connection: close\r\n%.*s\r\n",
                     st, (int)lines_len, lines);
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

/* find the end of a CGI header block: "\n\n" or "\n\r\n"; *body = offset
 * of the first body byte */
static int cgi_header_end(const char *h, size_t hl, size_t *hdr_len,
                          size_t *body) {
    for (size_t i = 0; i + 1 < hl; i++) {
        if (h[i] != '\n') continue;
        if (h[i + 1] == '\n') { *hdr_len = i + 1; *body = i + 2; return 1; }
        if (h[i + 1] == '\r' && i + 2 < hl && h[i + 2] == '\n') {
            *hdr_len = i + 1; *body = i + 3; return 1;
        }
    }
    return 0;
}

/* Relay one CGI response from the broker.  Frames are always drained up
 * to the end marker, even after the client went away, so the channel
 * stays in sync.  *sent: something reached the client; *chan_ok = 0
 * when the broker channel broke (timeout, protocol error).  Returns the
 * HTTP status. */
static int relay_cgi(Conn *c, int cgi_fd, int head_only, int cgi_timeout,
                     int send_timeout, int *sent, int *chan_ok) {
    static char buf[65536];
    char hdr[8192];
    size_t hl = 0;
    int state = 0;             /* 0 = CGI headers, 1 = body, 2 = NPH */
    int status = 502, client_ok = 1;
    int64_t start = mono_ms();
    int64_t client_deadline = start + (int64_t)(cgi_timeout + 5) * 1000;
    int64_t hard_deadline = start +
        (int64_t)(cgi_timeout + send_timeout + 15) * 1000;
    *sent = 0;
    *chan_ok = 1;
    for (;;) {
        uint32_t len;
        if (read_full_deadline(cgi_fd, &len, 4, hard_deadline) < 0 ||
            len > sizeof buf ||
            (len && read_full_deadline(cgi_fd, buf, len, hard_deadline) < 0)) {
            *chan_ok = 0;
            break;
        }
        if (len == 0) break;                           /* end of response */
        if (!client_ok) continue;                      /* keep draining */
        if (mono_ms() > client_deadline) { client_ok = 0; continue; }

        if (state == 0) {
            size_t room = sizeof hdr - 1 - hl;
            size_t take = len < room ? len : room;
            memcpy(hdr + hl, buf, take);
            hl += take;
            hdr[hl] = 0;
            if (hl >= 5 && !memcmp(hdr, "HTTP/", 5)) {
                /* non-parsed-header CGI: pass the output through */
                state = 2;
                status = hl >= 12 ? atoi(hdr + 9) : 200;
                client_ok = send_all(c, hdr, hl) == 0 &&
                            (take == len || send_all(c, buf + take, len - take) == 0);
                *sent = 1;
                continue;
            }
            size_t hlen, body;
            if (!cgi_header_end(hdr, hl, &hlen, &body)) {
                if (hl == sizeof hdr - 1) client_ok = 0;   /* header too large */
                continue;
            }
            char head[sizeof hdr + 256];
            int n = cgi_build_head(hdr, hlen, head, sizeof head, &status);
            if (n < 0) { status = 502; client_ok = 0; continue; }
            state = 1;
            *sent = 1;
            client_ok = send_all(c, head, (size_t)n) == 0;
            if (client_ok && !head_only) {
                if (hl > body) client_ok = send_all(c, hdr + body, hl - body) == 0;
                if (client_ok && take < len)
                    client_ok = send_all(c, buf + take, len - take) == 0;
            }
            continue;
        }
        if (state == 1 && head_only) continue;
        client_ok = send_all(c, buf, len) == 0;
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

/* append s to the log line, escaping control characters, '"', '\' and
 * non-ASCII bytes as \xHH so a request cannot forge or break log lines */
static void log_append(char *line, size_t cap, size_t *n, const char *s) {
    for (; *s && *n + 5 < cap; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch < 0x20 || ch >= 0x7f || ch == '"' || ch == '\\') {
            snprintf(line + *n, cap - *n, "\\x%02x", ch);
            *n += 4;
        } else {
            line[(*n)++] = (char)ch;
        }
    }
    line[*n] = 0;
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
    const size_t cap = sizeof line - 48;   /* room for status, bytes, \n */
    size_t n = 0;
    log_append(line, cap, &n, ip);
    log_append(line, cap, &n, " - ");
    log_append(line, cap, &n, auth_user ? auth_user : "-");
    log_append(line, cap, &n, " [");
    log_append(line, cap, &n, ts);
    log_append(line, cap, &n, "] ");
    if (n + 1 < cap) line[n++] = '"';
    log_append(line, cap, &n, req->method ? req->method : "-");
    log_append(line, cap, &n, " ");
    log_append(line, cap, &n, req->path ? req->path : "-");
    if (req->query && *req->query) {
        log_append(line, cap, &n, "?");
        log_append(line, cap, &n, req->query);
    }
    log_append(line, cap, &n, " ");
    log_append(line, cap, &n, req->version ? req->version : "-");
    int k = snprintf(line + n, sizeof line - n, "\" %d %llu\n",
                     status, (unsigned long long)nbytes);
    if (k < 0) return;
    send_fd_all(ctx->log_fd, line, n + (size_t)k);
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

/* Main per-connection handler. */
static void handle_connection(struct SrvCtx *ctx, int fd, int is_tls) {
    struct sockaddr_in peer; socklen_t pl = sizeof(peer);
    memset(&peer, 0, sizeof peer);
    getpeername(fd, (struct sockaddr *)&peer, &pl);
    char ip[INET_ADDRSTRLEN] = "-";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
    uint32_t ip_u32 = ntohl(peer.sin_addr.s_addr);
    const Config *cfg = ctx->cfg;

    /* a client that stops reading cannot stall a write for longer than
     * the body timeout */
    struct timeval tv = { .tv_sec = cfg->def_body_timeout, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    Conn conn = { .fd = fd, .tls = NULL, .nbytes = 0,
                  .pre_fd = { ctx->srv80, ctx->srv443 },
                  .last_rx = mono_ms() };
    if (is_tls) {
        conn.tls = tls_server_handshake(ctx->arena, fd, cfg->tls_key,
                                        pick_site_key, ctx->cfg,
                                        cfg->def_header_timeout, conn.pre_fd);
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
            if (wait_keepalive(ctx, &conn, cfg->def_header_timeout) <= 0)
                break;
        }
        first = 0;

        uint64_t bytes0 = conn.nbytes;
        int status = 500;
        const char *auth_user = NULL;

        HttpRequest req;
        int r = http_read_request(ctx->arena, &conn, &req,
                                  cfg->def_header_timeout,
                                  cfg->def_body_timeout);
        if (r < 0) {
            log_debug("client %s: request read failed or timed out", ip);
            break;
        }
        int head_only = req.method && !strcmp(req.method, "HEAD");
        if (r > 0) {
            /* malformed request: answer and close */
            status = r;
            send_error_close(&conn, status, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            break;
        }

        /* The path is matched against the config as-is, so "." and ".."
         * segments would slip past deny/auth/ip_allow entries (e.g.
         * "/./.git/config").  Refuse them, and anything not absolute. */
        if (!path_is_clean(req.path)) {
            status = 400;
            send_error_close(&conn, status, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            break;
        }

        SiteCfg *site = config_find_site(ctx->cfg, req.host);
        if (!site) {
            status = 404;
            send_error_close(&conn, status, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            break;
        }

        /* mutate a scratch copy of the path for walking */
        char *path_scratch = arena_strdup(ctx->arena, req.path);
        char *rest = NULL;
        char fs_path[2048];
        DirCfg *eff = path_scratch
                    ? config_walk(site->root, path_scratch, &rest,
                                  fs_path, sizeof fs_path)
                    : NULL;
        if (!eff) {
            status = path_scratch ? 414 : 500;
            send_error_close(&conn, status, head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            break;
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
            static const char acme[] = "/.well-known/acme-challenge/";
            int close_after = 0;
            if (!strncmp(req.path, acme, sizeof acme - 1)) {
                const char *tok = req.path + sizeof acme - 1;
                const char *le_root = cfg->letsencrypt_root
                                    ? cfg->letsencrypt_root
                                    : "/var/www/letsencrypt";
                char full[1024];
                int fl = snprintf(full, sizeof(full), "%s/%s", le_root, tok);
                int rc = -1;
                if (*tok && fl > 0 && (size_t)fl < sizeof full)
                    rc = serve_file(&conn, le_root, full, head_only,
                                    cfg->def_body_timeout);
                if (rc == 0) {
                    status = 200;
                } else if (rc == -2) {
                    status = 200;
                    close_after = 1;
                } else {
                    status = 404;
                    http_send_simple(&conn, 404, "Not Found", NULL,
                                     "not found\n", 10, head_only);
                }
            } else {
                char *loc = arena_sprintf(ctx->arena,
                                          "Location: https://%s%s\r\n",
                                          req.host, req.path);
                if (!loc) {
                    status = 500;
                    send_error_close(&conn, status, head_only);
                    close_after = 1;
                } else {
                    status = 301;
                    http_send_simple(&conn, 301, "Moved Permanently", loc,
                                     "", 0, head_only);
                }
            }
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (close_after || !req.keep_alive) break;
            continue;
        }

        /* ---- denied subtrees (config "deny": true) ---- */
        if (eff->deny) {
            status = 404;
            log_debug("client %s: denied subdir", ip);
            http_send_simple(&conn, 404, "Not Found", NULL, "not found\n", 10,
                             head_only);
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
        if (eff->auth_required && authfail_blocked(ip_u32)) {
            status = 429;
            http_send_simple(&conn, 429, "Too Many Requests",
                             "Retry-After: 60\r\n", "too many attempts\n", 18,
                             head_only);
            access_log_request(ctx, &peer, &req, NULL, status,
                               conn.nbytes - bytes0);
            if (!req.keep_alive) break;
            continue;
        }
        int auth_ok = auth_check(eff, req.authorization);
        if (eff->auth_required && req.authorization)
            authfail_note(ip_u32, !auth_ok);
        if (!auth_ok) {
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
            if (cgi_lookup(eff, rest_n, &path_info)) {
                int responded = 0;
                if (req.body_len > CGI_MAX_BODY) {
                    status = 413;
                } else if (ctx->cgi_fd < 0) {
                    status = 502;
                } else if (cgi_send_request(ctx->cgi_fd, req.method,
                                            site->name, req.path, req.query,
                                            req.body, req.body_len) < 0) {
                    log_err("cgi: cannot reach the CGI broker; CGI disabled");
                    close(ctx->cgi_fd);
                    ctx->cgi_fd = -1;
                    status = 502;
                } else {
                    int chan_ok;
                    status = relay_cgi(&conn, ctx->cgi_fd, head_only,
                                       eff->cgi_timeout, cfg->def_body_timeout,
                                       &responded, &chan_ok);
                    if (!chan_ok) {
                        log_err("cgi: broker channel broken; CGI disabled");
                        close(ctx->cgi_fd);
                        ctx->cgi_fd = -1;
                    }
                    if (!responded) {
                        status = 502;
                        log_warn("client %s: CGI %s produced no valid response",
                                 ip, req.path);
                    }
                }
                if (!responded) send_error_close(&conn, status, head_only);
                access_log_request(ctx, &peer, &req, auth_user, status,
                                   conn.nbytes - bytes0);
                break;      /* CGI output has no length: close the connection */
            }
        }

        /* ---- static file ---- */
        char full[2048];
        int fl = snprintf(full, sizeof(full), "%s/%s", fs_path, rest);
        if (fl < 0 || (size_t)fl >= sizeof(full)) {
            status = 414;
            send_error_close(&conn, status, head_only);
            access_log_request(ctx, &peer, &req, auth_user, status,
                               conn.nbytes - bytes0);
            break;
        }
        if (rest[0] == 0 || rest[strlen(rest) - 1] == '/') {
            /* directory: append "index.html" in place, bounded */
            size_t flen = strlen(full);
            static const char suffix[] = "/index.html";   /* 11 + NUL */
            if (flen + sizeof(suffix) > sizeof(full)) {
                status = 414;
                send_error_close(&conn, status, head_only);
                access_log_request(ctx, &peer, &req, auth_user, status,
                                   conn.nbytes - bytes0);
                break;
            }
            memcpy(full + flen, suffix, sizeof(suffix));
        }
        int rc = serve_file(&conn, fs_path, full, head_only,
                            cfg->def_body_timeout);
        if (rc == -1) {
            /* a missing file is "not found"; an unreadable one is
             * "forbidden" (the httpd process reads files — authentication
             * does not grant filesystem access) */
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
        access_log_request(ctx, &peer, &req, auth_user, status,
                           conn.nbytes - bytes0);
        if (rc == -2 || !req.keep_alive) break;
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

    /* a stuck CGI broker must not block the httpd forever on a send */
    struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
    setsockopt(ctx->cgi_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

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
 * cgi process (broker, runs as root)
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

/* one response frame to the httpd; len 0 ends the response */
static int cgi_frame(int fd, const void *data, uint32_t len) {
    if (send_fd_all(fd, &len, 4) < 0) return -1;
    if (len && send_fd_all(fd, data, len) < 0) return -1;
    return 0;
}

/* malloc'd "KEY=value"; exits on allocation failure */
static char *env_str(const char *key, const char *val) {
    size_t kl = strlen(key), vl = strlen(val);
    char *e = malloc(kl + vl + 2);
    if (!e) { log_err("cgi: out of memory"); exit(1); }
    memcpy(e, key, kl);
    e[kl] = '=';
    memcpy(e + kl + 1, val, vl + 1);
    return e;
}

/* What the broker runs for a request, resolved from its own copy of the
 * configuration.  The httpd only says which URL was requested, so even a
 * compromised httpd can start nothing but the configured CGI programs,
 * as their configured (non-root) users. */
typedef struct {
    char prog[2048];
    char fs[2048];             /* the effective directory */
    const char *user;
    int timeout;
    const char *path_info;     /* points into the path scratch copy */
    size_t script_name_len;
} CgiJob;

static int cgi_resolve(Config *cfg, const char *host, char *path, CgiJob *j) {
    if (!path_is_clean(path)) return -1;
    SiteCfg *site = config_find_site(cfg, host);
    if (!site) return -1;
    char *rest;
    DirCfg *eff = config_walk(site->root, path, &rest, j->fs, sizeof j->fs);
    if (!eff || eff->deny) return -1;
    const char *rest_n = rest;
    while (*rest_n == '/') rest_n++;
    const char *path_info = NULL;
    CgiProgram *cp = cgi_lookup(eff, rest_n, &path_info);
    if (!cp) return -1;

    /* where to exec from: absolute path, relative-to-dir path, or the
     * matched file under the effective dir */
    size_t fl = strlen(j->fs);
    if (cp->path && cp->path[0] == '/') {
        size_t l = strlen(cp->path);
        if (l + 1 > sizeof j->prog) return -1;
        memcpy(j->prog, cp->path, l + 1);
    } else {
        const char *tail = cp->path ? cp->path : rest_n;
        size_t l = cp->path ? strlen(cp->path) : (size_t)(path_info - rest_n);
        if (fl + 1 + l + 1 > sizeof j->prog) return -1;
        memcpy(j->prog, j->fs, fl);
        j->prog[fl] = '/';
        memcpy(j->prog + fl + 1, tail, l);
        j->prog[fl + 1 + l] = 0;
    }
    j->user = cp->user ? cp->user : cfg->cgi_user;
    j->timeout = eff->cgi_timeout;
    j->path_info = path_info;
    j->script_name_len = (size_t)(path_info - path);
    return 0;
}

static void kill_cgi(pid_t pid) {
    if (pid <= 0) return;      /* never kill(-0) / kill(-1) */
    kill(-pid, SIGKILL);       /* the program's process group */
    kill(pid, SIGKILL);
}

/* Handle one request from the httpd.  Returns -1 only when the channel
 * itself is unusable (EOF, protocol violation); a request that cannot
 * be served gets an empty response, which the httpd answers with 502. */
static int cgi_run_one(Config *cfg, int cgi_fd) {
    /* collect programs that outlived an earlier request */
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    struct CgiReq h;
    if (read_all(cgi_fd, &h, sizeof(h)) < 0) return -1;
    if (h.method_len < 1 || h.method_len > 16 || h.host_len > 255 ||
        h.path_len < 1 || h.path_len > CGI_MAX_FIELD ||
        h.query_len > CGI_MAX_FIELD || h.body_len > CGI_MAX_BODY)
        return -1;

    static char method[17], host[256], path[CGI_MAX_FIELD + 1],
                scratch[CGI_MAX_FIELD + 1], query[CGI_MAX_FIELD + 1];
    if (read_all(cgi_fd, method, h.method_len) < 0 ||
        read_all(cgi_fd, host, h.host_len) < 0 ||
        read_all(cgi_fd, path, h.path_len) < 0 ||
        (h.query_len && read_all(cgi_fd, query, h.query_len) < 0))
        return -1;
    method[h.method_len] = 0;
    host[h.host_len] = 0;
    path[h.path_len] = 0;
    query[h.query_len] = 0;
    char *body = NULL;
    if (h.body_len) {
        body = malloc(h.body_len);
        if (!body) { log_err("cgi: out of memory"); exit(1); }
        if (read_all(cgi_fd, body, h.body_len) < 0) { free(body); return -1; }
    }

    /* the request is fully read: the stream stays in sync from here on */
    CgiJob j;
    memcpy(scratch, path, h.path_len + 1);
    int ok = strlen(method) == h.method_len && strlen(host) == h.host_len &&
             strlen(path) == h.path_len && strlen(query) == h.query_len &&
             cgi_resolve(cfg, h.host_len ? host : NULL, scratch, &j) == 0;
    struct passwd *pw = ok ? getpwnam(j.user) : NULL;
    if (ok && (!pw || pw->pw_uid == 0)) {
        log_err("cgi: refusing to run %s as user '%s'", j.prog, j.user);
        ok = 0;
    }
    if (!ok) {
        free(body);
        return cgi_frame(cgi_fd, NULL, 0);
    }
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;

    /* environment (built here, not by the httpd) */
    char script_name[CGI_MAX_FIELD + 1], clen[32];
    memcpy(script_name, scratch, j.script_name_len);
    script_name[j.script_name_len] = 0;
    snprintf(clen, sizeof clen, "%u", h.body_len);
    char *req_uri = malloc(h.path_len + 1 + h.query_len + 1);
    if (!req_uri) { log_err("cgi: out of memory"); exit(1); }
    snprintf(req_uri, h.path_len + 1 + h.query_len + 1, "%s%s%s",
             path, h.query_len ? "?" : "", query);
    char *env[16];
    int ne = 0;
    env[ne++] = env_str("GATEWAY_INTERFACE", "CGI/1.1");
    env[ne++] = env_str("SERVER_PROTOCOL", "HTTP/1.1");
    env[ne++] = env_str("REQUEST_METHOD", method);
    env[ne++] = env_str("REQUEST_URI", req_uri);
    env[ne++] = env_str("QUERY_STRING", query);
    env[ne++] = env_str("CONTENT_TYPE", "application/octet-stream");
    env[ne++] = env_str("CONTENT_LENGTH", clen);
    env[ne++] = env_str("SCRIPT_NAME", script_name);
    env[ne++] = env_str("SCRIPT_FILENAME", j.prog);
    env[ne++] = env_str("DOCUMENT_ROOT", j.fs);
    if (*j.path_info) env[ne++] = env_str("PATH_INFO", j.path_info);
    env[ne] = NULL;
    free(req_uri);

    int ret = 0, ended = 0;
    int inp[2] = { -1, -1 }, outp[2] = { -1, -1 };
    if (pipe2(inp, O_CLOEXEC) < 0 || pipe2(outp, O_CLOEXEC) < 0) {
        log_err("cgi: pipe for %s: %s", j.prog, strerror(errno));
        goto done;
    }
    pid_t pid = fork();
    if (pid < 0) {
        log_err("cgi: fork for %s: %s", j.prog, strerror(errno));
        goto done;
    }
    if (pid == 0) {
        setpgid(0, 0);
        if (setgroups(0, NULL) < 0 || setgid(gid) < 0 || setuid(uid) < 0 ||
            getuid() != uid || geteuid() != uid || getgid() != gid) {
            log_err("cgi: cannot switch to user '%s' for %s: %s",
                    j.user, j.prog, strerror(errno));
            _exit(126);
        }
        dup2(inp[0], 0);
        dup2(outp[1], 1);
        /* the CGI program must not inherit the control channel back to
         * the httpd (cgi_fd) or any other server fds.  Keep only the
         * error log. */
        for (int i = 3; i < 1024; i++)
            if (i != g_errfd) close(i);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        execve(j.prog, (char *const[]){ j.prog, NULL }, env);
        log_err("cgi: execve %s: %s", j.prog, strerror(errno));
        _exit(127);
    }
    setpgid(pid, pid);
    close(inp[0]); inp[0] = -1;
    close(outp[1]); outp[1] = -1;
    fcntl(inp[1], F_SETFL, O_NONBLOCK);
    fcntl(outp[0], F_SETFL, O_NONBLOCK);

    /* feed the body and collect the output at the same time (a program
     * writing a lot before reading stdin must not deadlock), all within
     * the CGI timeout */
    int64_t deadline = mono_ms() + (int64_t)j.timeout * 1000;
    size_t w = 0;
    if (!h.body_len) { close(inp[1]); inp[1] = -1; }
    static char buf[65536];
    int timed_out = 0;
    for (;;) {
        int64_t rem = deadline - mono_ms();
        if (rem <= 0) { timed_out = 1; break; }
        struct pollfd p[2] = {
            { outp[0], POLLIN, 0 },
            { inp[1], POLLOUT, 0 },          /* ignored once closed (-1) */
        };
        int r = poll(p, 2, (int)rem);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) continue;
        if (inp[1] >= 0 && (p[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t k = write(inp[1], body + w, h.body_len - w);
            if (k > 0) w += (size_t)k;
            if ((k < 0 && errno != EAGAIN && errno != EINTR) || w == h.body_len) {
                close(inp[1]);
                inp[1] = -1;
            }
        }
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t k = read(outp[0], buf, sizeof buf);
            if (k > 0) {
                if (cgi_frame(cgi_fd, buf, (uint32_t)k) < 0) { ret = -1; break; }
            } else if (k == 0 || (errno != EAGAIN && errno != EINTR)) {
                break;                       /* output closed */
            }
        }
    }
    if (timed_out) log_warn("cgi: %s timed out after %d s", j.prog, j.timeout);
    if (timed_out || ret < 0) kill_cgi(pid);
    /* the response is complete once stdout is closed: release the
     * client before reaping the process */
    if (ret == 0) {
        ended = 1;
        if (cgi_frame(cgi_fd, NULL, 0) < 0) ret = -1;
    }

    /* Reap.  A program still running at the deadline is killed, and
     * the wait after a kill is bounded: a process that does not die
     * (stuck in the kernel, or the kill was refused) must not stall the
     * broker.  It is collected later by the sweep in cgi_run_one(). */
    int killed = timed_out || ret < 0;
    int64_t reap_deadline = killed ? mono_ms() + 1000 : deadline;
    for (;;) {
        int st;
        pid_t wp = waitpid(pid, &st, WNOHANG);
        if (wp == pid || (wp < 0 && errno != EINTR)) break;
        int64_t now = mono_ms();
        if (now >= reap_deadline) {
            if (!killed) {
                log_warn("cgi: %s still running after %d s, killed",
                         j.prog, j.timeout);
                kill_cgi(pid);
                killed = 1;
                reap_deadline = now + 1000;
                continue;
            }
            log_err("cgi: %s (pid %d) does not exit after SIGKILL; not "
                    "waiting for it", j.prog, (int)pid);
            break;
        }
        poll(NULL, 0, 10);
    }

done:
    if (inp[0] >= 0) close(inp[0]);
    if (inp[1] >= 0) close(inp[1]);
    if (outp[0] >= 0) close(outp[0]);
    if (outp[1] >= 0) close(outp[1]);
    for (int i = 0; i < ne; i++) free(env[i]);
    free(body);
    if (ret == 0 && !ended && cgi_frame(cgi_fd, NULL, 0) < 0) ret = -1;
    return ret;
}

static void run_cgi(Config *cfg, int cgi_fd) {
    signal(SIGTERM, SIG_DFL);
    while (cgi_run_one(cfg, cgi_fd) == 0) {}
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

/* Open a log file for appending as root without following symlinks.  It
 * must be a regular file with a single link: otherwise someone who can
 * write to the log directory could point the master's writes, chown and
 * chmod at another file (e.g. a symlink or hard link to /etc/shadow). */
static int open_log_file(const char *path, int mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NOCTTY,
                  mode);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
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
        int fd = open_log_file(file, mode);
        if (fd < 0) {
            fprintf(stderr, "corehttpd: error log %s: %s%s\n", file, strerror(errno),
                    errno == EPERM || errno == ELOOP
                        ? " (must be a regular file, not a link)" : "");
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
    int fd = open_log_file(cfg->access_log, mode);
    if (fd < 0) {
        log_err("access log %s: %s%s", cfg->access_log, strerror(errno),
                errno == EPERM || errno == ELOOP
                    ? " (must be a regular file, not a link)" : "");
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
        run_cgi(cfg, cgi_pair[1]);
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
        if (ar == MAP_FAILED) { log_err("mmap: %s", strerror(errno)); _exit(1); }
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
