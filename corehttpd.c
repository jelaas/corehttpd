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

/* =====================================================================
 * jsonc – strip comments but preserve strings
 * ===================================================================== */
static char *strip_jsonc(Arena *a, const char *s) {
    size_t n = strlen(s);
    char *out = arena_alloc(a, n + 1);
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
static const char *j_str(json_t *o, const char *k) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    return json_is_string(v) ? json_string_value(v) : NULL;
}
static int j_true(json_t *o, const char *k) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    return json_is_true(v);
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
    if (dr) d->path = arena_strdup(a, dr);
    else if (parent) {
        size_t pl = strlen(parent->path), nl = d->name ? strlen(d->name) : 0;
        char *p = arena_alloc(a, pl + nl + 2);
        memcpy(p, parent->path, pl);
        p[pl] = '/';
        if (nl) memcpy(p + pl + 1, d->name, nl);
        p[pl + nl + 1] = 0;
        d->path = p;
    } else d->path = arena_strdup(a, "/");

    /* ---- auth: monotonic ---- */
    json_t *jauth = json_object_get(j, "auth");
    if (jauth) {
        d->auth_required = 1;
        d->auth_user = arena_strdup(a, j_str(jauth, "user") ? j_str(jauth, "user") : "");
        d->auth_pass = arena_strdup(a, j_str(jauth, "pass") ? j_str(jauth, "pass") : "");
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
    d->header_timeout    = j_int(j, "header_timeout",
                                 parent ? parent->header_timeout    : cfg->def_header_timeout);
    d->body_timeout      = j_int(j, "body_timeout",
                                 parent ? parent->body_timeout      : cfg->def_body_timeout);
    d->keepalive_timeout = j_int(j, "keepalive_timeout",
                                 parent ? parent->keepalive_timeout : cfg->def_keepalive);

    /* ---- cgi: inherit from parent, then merge this dir ----
     *
     * Rules mirror auth:
     *   - child starts with a copy of parent's effective list
     *   - "cgi_clear": true wipes it first
     *   - each entry in "cgi": [] overrides an existing name (found in the
     *     inherited list) in place, or appends a new one
     *   - an entry with "disabled": true removes it from the child's list
     */
    if (parent && parent->n_cgi) {
        d->cgi = arena_alloc(a, sizeof(CgiProgram) * parent->n_cgi);
        memcpy(d->cgi, parent->cgi, sizeof(CgiProgram) * parent->n_cgi);
        d->n_cgi = parent->n_cgi;
    }

    if (j_true(j, "cgi_clear")) {
        d->cgi = NULL;
        d->n_cgi = 0;
    }

    json_t *jcgi = json_object_get(j, "cgi");
    if (json_is_array(jcgi)) {
        size_t nadd = json_array_size(jcgi);
        for (size_t i = 0; i < nadd; i++) {
            json_t *e = json_array_get(jcgi, i);
            const char *name = j_str(e, "name");
            if (!name) continue;

            int found = -1;
            for (int k = 0; k < d->n_cgi; k++)
                if (d->cgi[k].name && !strcmp(d->cgi[k].name, name)) {
                    found = k; break;
                }

            if (j_true(e, "disabled")) {
                if (found >= 0) {
                    memmove(&d->cgi[found], &d->cgi[found + 1],
                            sizeof(CgiProgram) * (d->n_cgi - found - 1));
                    d->n_cgi--;
                }
                continue;
            }

            CgiProgram *slot;
            if (found >= 0) {
                slot = &d->cgi[found];
            } else {
                CgiProgram *nc = arena_alloc(a, sizeof(CgiProgram) * (d->n_cgi + 1));
                if (d->n_cgi) memcpy(nc, d->cgi, sizeof(CgiProgram) * d->n_cgi);
                d->cgi = nc;
                slot = &d->cgi[d->n_cgi++];
            }
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
        for (size_t i = 0; i < n; i++) {
            DirCfg *cd = parse_dir(a, json_array_get(subs, i), d, cfg, NULL);
            if (cd) d->subdirs[d->n_subdirs++] = cd;
        }
    }
    return d;
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
    c->arena_size       = j_int(root, "arena_size", 32u << 20);

    json_t *defs = json_object_get(root, "defaults");
    c->def_header_timeout = j_int(defs, "header_timeout", 10);
    c->def_body_timeout   = j_int(defs, "body_timeout",   30);
    c->def_keepalive      = j_int(defs, "keepalive_timeout", 60);

    /* sites */
    json_t *sites = json_object_get(root, "sites");
    if (json_is_array(sites)) {
        size_t n = json_array_size(sites);
        c->sites = arena_alloc(a, sizeof(SiteCfg *) * n);
        for (size_t i = 0; i < n; i++) {
            json_t *s = json_array_get(sites, i);
            SiteCfg *sc = arena_alloc(a, sizeof(*sc));
            sc->name = arena_strdup(a, j_str(s, "name"));
            sc->root = parse_dir(a, s, NULL, c, NULL);
            c->sites[c->n_sites++] = sc;
        }
    }
    json_decref(root);
    return c;
}

SiteCfg *config_find_site(Config *c, const char *host) {
    if (!host) return c->n_sites ? c->sites[0] : NULL;
    for (int i = 0; i < c->n_sites; i++)
        if (!strcasecmp(c->sites[i]->name, host)) return c->sites[i];
    return c->n_sites ? c->sites[0] : NULL;
}

DirCfg *config_walk(DirCfg *root, char *path, char **rest) {
    char *p = path; DirCfg *cur = root;
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        char *slash = strchr(p, '/');
        size_t clen = slash ? (size_t)(slash - p) : strlen(p);
        DirCfg *m = NULL;
        for (int i = 0; i < cur->n_subdirs; i++) {
            size_t nl = strlen(cur->subdirs[i]->name);
            if (nl == clen && !memcmp(cur->subdirs[i]->name, p, clen)) {
                m = cur->subdirs[i]; break;
            }
        }
        if (!m) break;
        cur = m; p += clen;
    }
    *rest = p;
    return cur;
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
        p += w; n -= (size_t)w;
    }
    return 0;
}

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
    if (!path_within_root(root, fullpath)) return -1;
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

/* forward raw CGI output from cgi_fd to client */
static int relay_cgi(Conn *c, int cgi_fd, int head_only) {
    char buf[65536];
    int in_body = 0;
    size_t hdr_len = 0;
    char hdrbuf[8192];
    while (1) {
        ssize_t r = read(cgi_fd, buf, sizeof(buf));
        if (r <= 0) break;
        if (head_only) {
            if (!in_body) {
                size_t csz = (size_t)r;
                if (hdr_len + csz >= sizeof(hdrbuf)) csz = sizeof(hdrbuf) - hdr_len - 1;
                memcpy(hdrbuf + hdr_len, buf, csz);
                hdr_len += csz;
                hdrbuf[hdr_len] = 0;
                char *e = strstr(hdrbuf, "\r\n\r\n");
                if (e) {
                    size_t hlen = (size_t)(e - hdrbuf) + 4;
                    (void)hlen;
                    char status[256] = "200 OK";
                    char *line = hdrbuf;
                    while (line < e) {
                        char *nl = strstr(line, "\r\n");
                        if (!nl) break;
                        if (!strncasecmp(line, "Status:", 7)) {
                            size_t l = (size_t)(nl - line - 7);
                            if (l > sizeof(status) - 1) l = sizeof(status) - 1;
                            memcpy(status, line + 8 < nl ? line + 8 : line + 7, l);
                            status[l] = 0;
                            char *s = trim(status); memmove(status, s, strlen(s) + 1);
                        }
                        line = nl + 2;
                    }
                    char h[1024];
                    int hn = snprintf(h, sizeof(h),
                        "HTTP/1.1 %s\r\nServer: corehttpd\r\n"
                        "Connection: keep-alive\r\n\r\n", status);
                    if (hn < 0 || (size_t)hn >= sizeof(h)) return -1;
                    send_all(c, h, (size_t)hn);
                    in_body = 1;
                }
            }
        } else {
            if (send_all(c, buf, (size_t)r) < 0) break;
        }
    }
    return 0;
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

/* Main per‑connection handler. */
static void handle_connection(struct SrvCtx *ctx, int fd, int is_tls) {
    struct sockaddr_in peer; socklen_t pl = sizeof(peer);
    getpeername(fd, (struct sockaddr *)&peer, &pl);

    Conn conn = { fd, NULL };
    if (is_tls) {
        conn.tls = tls_server_handshake(ctx->arena, fd, ctx->cfg->tls_key,
                                        ctx->cfg->def_header_timeout);
        if (!conn.tls) { close(fd); return; }
    }

    for (;;) {
        arena_reset(ctx->arena);

        HttpRequest req;
        int r = http_read_request(ctx->arena, &conn, &req,
                                  ctx->cfg->def_header_timeout,
                                  ctx->cfg->def_body_timeout);
        if (r < 0) break;

        SiteCfg *site = config_find_site(ctx->cfg, req.host);
        if (!site) { http_send_simple(&conn, 404, "Not Found", NULL, "no site", 7, 0); break; }

        /* mutate a scratch copy of the path for walking */
        char *path_scratch = arena_strdup(ctx->arena, req.path);
        char *rest = NULL;
        DirCfg *eff = config_walk(site->root, path_scratch, &rest);

        int head_only = !strcmp(req.method, "HEAD");

        /* ---- port 80: redirect / letsencrypt / GET-HEAD only ---- */
        if (!is_tls) {
            if (strcmp(req.method, "GET") && strcmp(req.method, "HEAD")) {
                http_send_simple(&conn, 405, "Method Not Allowed",
                                 "Allow: GET, HEAD\r\n", "no\r\n", 4, head_only);
                if (!req.keep_alive) break;
		continue;
            }
            if (req.path && !strncmp(req.path, "/.well-known/acme-challenge/", 28)) {
                char full[1024];
                const char *le_root = ctx->cfg->letsencrypt_root
                                    ? ctx->cfg->letsencrypt_root
                                    : "/var/www/letsencrypt";
                snprintf(full, sizeof(full), "%s/%s", le_root, req.path + 28);
                if (serve_file(&conn, le_root, full, head_only) < 0)
                    http_send_simple(&conn, 404, "Not Found", NULL, "not found\n", 10, head_only);
            } else {
                char loc[1024];
                snprintf(loc, sizeof(loc), "Location: https://%s%s\r\n",
                         req.host ? req.host : site->name, req.path);
                http_send_simple(&conn, 301, "Moved Permanently", loc, "", 0, head_only);
            }
            if (!req.keep_alive) break;
            continue;
        }

        /* ---- restrictions ---- */
        if (!ip_allowed(eff, &peer)) {
            http_send_simple(&conn, 403, "Forbidden", NULL, "forbidden\n", 10, head_only);
            if (!req.keep_alive) break;
	    continue;
        }
        if (!auth_check(eff, req.authorization)) {
            http_send_simple(&conn, 401, "Unauthorized",
                "WWW-Authenticate: Basic realm=\"corehttpd\"\r\n",
                "auth required\n", 14, head_only);
            if (!req.keep_alive) break;
	    continue;
        }

        /* ---- CGI dispatch (per-dir, inherited) ---- */
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
                    if (cp->path[0] == '/')
                        snprintf(prog_path, sizeof(prog_path), "%s", cp->path);
                    else
                        snprintf(prog_path, sizeof(prog_path), "%s/%s",
                                 eff->path, cp->path);
                } else {
                    size_t plen = (size_t)(path_info - rest_n);
                    snprintf(prog_path, sizeof(prog_path), "%s/%.*s",
                             eff->path, (int)plen, rest_n);
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
                if (!(t = arena_sprintf(ctx->arena, "DOCUMENT_ROOT=%s", eff->path))) goto cgi_nomem;
                env[ne++] = t;
                if (path_info && *path_info) {
                    if (!(t = arena_sprintf(ctx->arena, "PATH_INFO=%s", path_info))) goto cgi_nomem;
                    env[ne++] = t;
                }
                env[ne] = NULL;

                if (cgi_dispatch(ctx->arena, ctx->cgi_fd, prog_path, user,
                                 env, ne, req.body, req.body_len) < 0)
                    http_send_simple(&conn, 502, "Bad Gateway", NULL, "cgi\n", 4, head_only);
                else
                    relay_cgi(&conn, ctx->cgi_fd, head_only);

                if (!req.keep_alive) break;
                continue;
            }
        }

        /* ---- static file ---- */
        char full[2048];
        int fl = snprintf(full, sizeof(full), "%s/%s", eff->path, rest);
        if (fl < 0 || (size_t)fl >= sizeof(full)) {
            http_send_simple(&conn, 414, "URI Too Long", NULL, "uri too long\n", 13, head_only);
            if (!req.keep_alive) break;
            continue;
        }
        if (rest[0] == 0 || rest[strlen(rest) - 1] == '/') {
            /* directory: append "index.html" in place, bounded */
            size_t flen = strlen(full);
            static const char suffix[] = "/index.html";   /* 11 + NUL */
            if (flen + sizeof(suffix) > sizeof(full)) {
                http_send_simple(&conn, 414, "URI Too Long", NULL, "uri too long\n", 13, head_only);
                if (!req.keep_alive) break;
                continue;
            }
            memcpy(full + flen, suffix, sizeof(suffix));
            if (serve_file(&conn, eff->path, full, head_only) < 0)
                http_send_simple(&conn, 403, "Forbidden", NULL, "forbidden\n", 10, head_only);
        } else {
            if (serve_file(&conn, eff->path, full, head_only) < 0)
                http_send_simple(&conn, 404, "Not Found", NULL, "not found\n", 10, head_only);
        }
        if (!req.keep_alive) break;
        continue;

cgi_nomem:
        http_send_simple(&conn, 500, "Internal Server Error", NULL, "nomem\n", 6, head_only);
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
static int cgi_run_one(int cgi_fd) {
    struct CgiHdr h;
    ssize_t n = read(cgi_fd, &h, sizeof(h));
    if (n != (ssize_t)sizeof(h)) return -1;

    char prog[1024], user[256];
    if (h.prog_len >= sizeof(prog) || h.user_len >= sizeof(user)) return -1;
    if (read(cgi_fd, prog, h.prog_len) != (ssize_t)h.prog_len) return -1;
    prog[h.prog_len] = 0;
    if (read(cgi_fd, user, h.user_len) != (ssize_t)h.user_len) return -1;
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
        if (read(cgi_fd, &kl, 4) != 4 || read(cgi_fd, &vl, 4) != 4) goto fail;
        if (kl > 4096 || vl > (1u << 20)) goto fail;
        char *e = malloc((size_t)kl + vl + 2);
        if (!e) goto fail;
        if (read(cgi_fd, e, kl) != (ssize_t)kl) { free(e); goto fail; }
        e[kl] = '=';
        if (vl && read(cgi_fd, e + kl + 1, vl) != (ssize_t)vl) {
            free(e); goto fail;
        }
        e[kl + 1 + vl] = 0;
        env[ne] = e;
    }

    if (h.body_len) {
        body = malloc(h.body_len);
        if (!body) goto fail;
        if (read(cgi_fd, body, h.body_len) != (ssize_t)h.body_len) goto fail;
    }

    pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        struct passwd *pw = getpwnam(user);
        if (!pw) _exit(126);
        setgroups(0, NULL);
        if (setgid(pw->pw_gid) < 0) _exit(126);
        if (setuid(pw->pw_uid) < 0) _exit(126);

        int inp[2], outp[2];
        if (pipe(inp) < 0 || pipe(outp) < 0) _exit(126);
        pid_t p2 = fork();
        if (p2 == 0) {
            dup2(inp[0], 0); dup2(outp[1], 1);
            close(inp[0]); close(inp[1]); close(outp[0]); close(outp[1]);
            execve(prog, (char *const[]){ (char *)prog, NULL }, env);
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
    if (!pw) { fprintf(stderr, "unknown user %s\n", user); exit(1); }
    if (setgroups(0, NULL) < 0) { perror("setgroups"); exit(1); }
    if (setgid(pw->pw_gid) < 0) { perror("setgid"); exit(1); }
    if (setuid(pw->pw_uid) < 0) { perror("setuid"); exit(1); }
}

int main(int argc, char **argv) {
    const char *cfgpath = argc > 1 ? argv[1] : "/etc/corehttpd/config.jsonc";

    /* EPIPE instead of SIGPIPE death when a client goes away mid-write */
    signal(SIGPIPE, SIG_IGN);

    Arena master_arena;
    arena_init(&master_arena, 4u << 20);
    Config *cfg = config_load(&master_arena, cfgpath);
    if (!cfg) { fprintf(stderr, "config load failed\n"); return 1; }

    /* the master reads the TLS material once and passes it to the
     * httpd child; the unprivileged child never touches the files */
    if (cfg->cert_file || cfg->key_file) {
        if (!cfg->cert_file || !cfg->key_file) {
            fprintf(stderr, "config: need both cert_file and key_file\n");
            return 1;
        }
        cfg->tls_key = tls_load_key(&master_arena,
                                    cfg->cert_file, cfg->key_file);
        if (!cfg->tls_key) {
            fprintf(stderr, "config: failed to load TLS key\n");
            return 1;
        }
    }

    int srv80  = open_port(80);
    int srv443 = open_port(443);

    int cgi_pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cgi_pair) < 0) { perror("socketpair"); return 1; }

    /* cgi child */
    pid_t cgi_pid = fork();
    if (cgi_pid == 0) {
        close(srv80); close(srv443);
        close(cgi_pair[0]);
        /* cgi broker runs privileged so it can setuid per program */
        run_cgi(cgi_pair[1]);
        _exit(0);
    }
    close(cgi_pair[1]);

    /* httpd child */
    pid_t httpd_pid = fork();
    if (httpd_pid == 0) {
        drop_to(cfg->httpd_user);
        Arena *ar = mmap(NULL, sizeof(Arena), PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        arena_init(ar, cfg->arena_size);
        struct SrvCtx ctx = {
            .cfg = cfg, .arena = ar,
            .srv80 = srv80, .srv443 = srv443,
            .cgi_fd = cgi_pair[0], .stop = 0,
        };
        run_httpd(&ctx);
        _exit(0);
    }
    close(cgi_pair[0]);

    /* master waits; on SIGTERM forwards to httpd, then kills cgi */
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);

    int stop = 0;
    while (!stop) {
        int sig;
        sigwait(&set, &sig);
        if (sig == SIGTERM || sig == SIGINT) stop = 1;
    }
    kill(httpd_pid, SIGTERM);
    int status;
    waitpid(httpd_pid, &status, 0);
    kill(cgi_pid, SIGTERM);
    waitpid(cgi_pid, &status, 0);
    close(srv80); close(srv443);
    return 0;
}
