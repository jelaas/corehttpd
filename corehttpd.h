#ifndef COREHTTPD_H
#define COREHTTPD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ---------- arena ---------- */
typedef struct { unsigned char *base; size_t size, used; } Arena;
void  arena_init(Arena *, size_t);
void *arena_alloc(Arena *, size_t);
char *arena_strdup(Arena *, const char *);
void  arena_reset(Arena *);

/* ---------- config ---------- */
typedef struct Acl { uint32_t net, mask; } Acl;   /* host byte order */

/* Per-directory CGI program entry.  Lives inside DirCfg; inherited by
 * children like auth is, and can be overridden or disabled per subtree. */
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
    const char *path;                    /* absolute fs path */
    int         auth_required;
    const char *auth_user;
    const char *auth_pass;
    Acl        *allow; int n_allow;      /* effective (intersected) */
    int         header_timeout;
    int         body_timeout;
    int         keepalive_timeout;
    CgiProgram *cgi; int n_cgi;          /* effective (inherited+merged) */
    struct DirCfg **subdirs; int n_subdirs;
} DirCfg;

typedef struct SiteCfg { const char *name; DirCfg *root; } SiteCfg;

struct TlsKey;   /* from tls.c */

typedef struct Config {
    const char *httpd_user;
    const char *cgi_user;                /* fallback user for CGI entries */
    const char *cert_file;
    const char *key_file;
    struct TlsKey *tls_key;              /* loaded once by the master */
    const char *letsencrypt_root;
    size_t      arena_size;
    int         def_header_timeout, def_body_timeout, def_keepalive;
    SiteCfg   **sites; int n_sites;
} Config;

Config *config_load(Arena *, const char *path);
SiteCfg *config_find_site(Config *, const char *host);
/* walk URL path against hierarchy; fills *rest with remaining file part */
DirCfg *config_walk(DirCfg *root, char *path_scratch, char **rest);

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
typedef struct Conn { int fd; TlsConn *tls; } Conn;

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

TlsConn *tls_server_handshake(Arena *, int fd, const TlsKey *key, int timeout);
ssize_t  tls_read (TlsConn *, void *, size_t);
ssize_t  tls_write(TlsConn *, const void *, size_t);
int      tls_pending(TlsConn *);
void     tls_unread(TlsConn *, const void *, size_t);
void     tls_close(TlsConn *);

#endif