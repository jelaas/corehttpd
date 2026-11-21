/* tls.c — minimal TLS 1.3 server.
 *
 * The interface below is what the rest of corehttpd expects. The full
 * implementation consists of:
 *   - SHA-256 / HMAC-SHA256 / HKDF (RFC 5869)
 *   - X25519 (RFC 7748)
 *   - AES-128-GCM
 *   - ECDSA P-256 sign (for CertificateVerify)
 *   - TLS 1.3 server state machine (RFC 8446), only
 *     TLS_AES_128_GCM_SHA256 + x25519 + ecdsa_secp256r1_sha256.
 *   - cert/key loaded via `openssl x509 -outform DER` /
 *     `openssl ec -outform DER` and parsed in-process.
 *
 * Until that module is dropped in, every HTTPS request is refused with
 * a plain 503 so the HTTP side can be exercised independently.
 */
#include "corehttpd.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>

struct TlsConn { int fd; };

TlsConn *tls_server_handshake(Arena *a, int fd, const char *cert, const char *key) {
    (void)a; (void)cert; (void)key;
    static const char *body =
        "HTTP/1.1 503 TLS not enabled\r\n"
        "Server: corehttpd\r\n"
        "Content-Length: 17\r\n"
        "Connection: close\r\n\r\n"
        "tls not enabled\n";
    ssize_t ignored = write(fd, body, strlen(body));
    (void)ignored;
    return NULL;
}
ssize_t tls_read (TlsConn *c, void *b, size_t n) { (void)c; (void)b; (void)n; return -1; }
ssize_t tls_write(TlsConn *c, const void *b, size_t n) { (void)c; (void)b; (void)n; return -1; }
void    tls_close(TlsConn *c) { (void)c; }