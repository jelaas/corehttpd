#ifndef COREHTTPD_H
#define COREHTTPD_H

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/* ---------- arena ---------- */
typedef struct { unsigned char *base; size_t size, used; } Arena;
void  arena_init(Arena *, size_t);
void *arena_alloc(Arena *, size_t);
char *arena_strdup(Arena *, const char *);
void  arena_reset(Arena *);

/* ---------- config ---------- */
typedef struct Acl { uint32_t net, mask; } Acl;   /* host byte order */

/* Per-directory CGI program entry.  Lives inside DirCfg and applies only
 * to its own directory: it is not inherited by subdirectories. */
typedef struct CgiProgram {
    const char *name;   /* relative name inside the dir, e.g. "gen.cgi" or
                           "sub/gen.cgi".  Longest match wins, so
                           "gen.cgi/x/y" runs gen.cgi with PATH_INFO=/x/y. */
    const char *path;   /* optional exec path.  absolute, or relative to
                           the effective dir, or NULL to exec the matched
                           file itself. */
    const char *user;   /* optional; NULL => cfg->cgi_user */
} CgiProgram;

typedef struct DirCfg {
    const char *name;
    const char *path;                    /* absolute fs path (NULL for glob) */
    int         deny;                    /* this subtree is not served */
    int         auth_required;
    const char *auth_user;
    const char *auth_pass;
    /* IP allow-list.  acl_set == 0: no restriction.  acl_set == 1: only
     * the listed networks are allowed; n_allow == 0 then denies all. */
    int         acl_set;
    Acl        *allow; int n_allow;      /* effective (intersected) */
    int         header_timeout;
    int         body_timeout;
    int         keepalive_timeout;
    int         cgi_timeout;
    CgiProgram *cgi; int n_cgi;          /* this directory's own CGI programs */
    struct DirCfg **subdirs; int n_subdirs;
} DirCfg;

typedef struct SiteCfg {
    const char *name;
    DirCfg *root;
    /* optional per-site TLS material (SNI-selected); NULL => global */
    const char *cert_file;
    const char *key_file;
    struct TlsKey *tls_key;
} SiteCfg;

struct TlsKey;   /* from tls.c */

typedef struct Config {
    const char *httpd_user;
    const char *cgi_user;                /* fallback user for CGI entries */
    const char *cert_file;
    const char *key_file;
    struct TlsKey *tls_key;              /* loaded once by the master */
    const char *letsencrypt_root;
    const char *access_log;              /* NULL = no access log */
    const char *access_log_owner;        /* "user[:group]" */
    int         access_log_mode;         /* -1 = default 0640 */
    size_t      arena_size;
    int         def_header_timeout, def_body_timeout, def_keepalive;
    int         def_cgi_timeout;
    SiteCfg   **sites; int n_sites;
} Config;

Config *config_load(Arena *, const char *path);
SiteCfg *config_find_site(Config *, const char *host);
/* walk URL path against hierarchy; fills *rest with remaining file part
 * and fs_buf with the effective filesystem path (for glob subdirs the
 * path is derived from the actual matched component); NULL on overflow */
DirCfg *config_walk(DirCfg *root, char *path_scratch, char **rest,
                    char *fs_buf, size_t fs_cap);

/* ---------- I/O deadlines ----------
 * Every blocking read has an absolute deadline.  In addition a connection
 * that has been idle (no bytes received) for IDLE_PREEMPT_MS is dropped
 * as soon as another connection is waiting on a listening socket: the
 * server handles one connection at a time, so a silent client must not
 * hold up the others. */
#define IDLE_PREEMPT_MS 2000

static inline int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait until fd is readable.  deadline_ms: absolute (mono_ms) or 0 for
 * none; idle_ms: per-wait limit; pre_fd: listening sockets to watch
 * (entries < 0 are ignored); *last_rx: time of the last received byte.
 * Returns 1 when readable, 0 on timeout/preemption, -1 on error. */
static inline int io_wait(int fd, int64_t deadline_ms, int idle_ms,
                          const int pre_fd[2], const int64_t *last_rx) {
    int pending = 0;
    for (;;) {
        int64_t now = mono_ms();
        int64_t wait = idle_ms;
        if (deadline_ms) {
            if (now >= deadline_ms) return 0;
            if (deadline_ms - now < wait) wait = deadline_ms - now;
        }
        struct pollfd p[3] = {
            { fd, POLLIN, 0 },
            { pending || !pre_fd ? -1 : pre_fd[0], POLLIN, 0 },
            { pending || !pre_fd ? -1 : pre_fd[1], POLLIN, 0 },
        };
        if (pending) {
            int64_t idle = now - *last_rx;
            if (idle >= IDLE_PREEMPT_MS) return 0;
            if (IDLE_PREEMPT_MS - idle < wait) wait = IDLE_PREEMPT_MS - idle;
        }
        if (wait < 0) wait = 0;
        int r = poll(p, 3, (int)wait);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) {
            if (pending) continue;     /* re-check the idle allowance */
            return 0;
        }
        if (p[0].revents & (POLLIN | POLLHUP | POLLERR)) return 1;
        if ((p[1].revents | p[2].revents) & POLLIN) pending = 1;
    }
}

/* ---------- http ---------- */
typedef struct TlsConn TlsConn;   /* from tls.c */

typedef struct {
    char        *method;
    char        *path;
    char        *query;
    char        *version;
    char        *host;
    char        *authorization;
    long         content_length;
    int          keep_alive;
    char        *body; size_t body_len;
} HttpRequest;

/* unified I/O endpoint: plain fd or a TLS connection */
typedef struct Conn {
    int fd; TlsConn *tls; uint64_t nbytes;
    int pre_fd[2];          /* listening sockets (idle preemption) */
    int64_t last_rx;        /* mono_ms of the last received bytes */
} Conn;

/* returns 0 on success, -1 on I/O error/timeout (close silently), or an
 * HTTP status code (400, 413, 431, 501) for a malformed request */
int  http_read_request(Arena *, Conn *, HttpRequest *, int hdr_timeout,
                       int body_timeout);
int  http_send_simple(Conn *, int code, const char *reason,
                      const char *extra_hdrs, const char *body,
                      size_t body_len, int head_only);

/* ---------- tls ---------- */
typedef struct TlsConn TlsConn;

#define TLS_MAX_CERTS 16

/* TLS material loaded once by the master process and shared (via fork)
 * with the httpd child; the child never reads the cert/key files. */
typedef struct TlsKey {
    unsigned char priv[32];              /* ECDSA P-256 private scalar */
    int n_certs;
    const unsigned char *der[TLS_MAX_CERTS];   /* certificate chain, DER */
    size_t len[TLS_MAX_CERTS];
} TlsKey;

TlsKey *tls_load_key(Arena *, const char *cert_file, const char *key_file);

/* callback for SNI-based certificate selection: return the key for the
 * given server name (case-insensitive), or NULL to use the default */
typedef const TlsKey *(*tls_pick_key_fn)(const char *sni, void *arg);

/* timeout: seconds for the whole handshake; pre_fd: listening sockets
 * for idle preemption (may be NULL) */
TlsConn *tls_server_handshake(Arena *, int fd, const TlsKey *defkey,
                              tls_pick_key_fn pick, void *arg, int timeout,
                              const int pre_fd[2]);
ssize_t  tls_read (TlsConn *, void *, size_t);
ssize_t  tls_write(TlsConn *, const void *, size_t);
int      tls_pending(TlsConn *);
void     tls_unread(TlsConn *, const void *, size_t);
void     tls_close(TlsConn *);
/* absolute deadline (mono_ms, 0 = none) for reads that need more data */
void     tls_set_deadline(TlsConn *, int64_t deadline_ms);
int64_t  tls_last_rx(TlsConn *);

#endif
