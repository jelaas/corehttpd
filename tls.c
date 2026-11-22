/* tls.c — minimal TLS 1.3 server (RFC 8446).
 *
 * Implements just enough for a modern Firefox (NSS) to connect:
 *   - TLS 1.3 only, cipher suite TLS_AES_128_GCM_SHA256
 *   - key exchange X25519 (RFC 7748)
 *   - signature scheme ecdsa_secp256r1_sha256, signed in-process with
 *     deterministic RFC 6979 nonces (no external programs).  The
 *     certificate must be ECDSA P-256 (e.g. Let's Encrypt ECDSA cert).
 *     The cert chain and private key are loaded ONCE by the master
 *     process (tls_load_key) and shared with the httpd child via the
 *     config; the httpd process never reads the key files itself.
 *   - no PSK / session resumption / early data / ALPN
 *
 * In-process primitives: SHA-256, HMAC-SHA256, HKDF (RFC 5869),
 * X25519, AES-128, GCM, ECDSA P-256.  Verified against OpenSSL and
 * GnuTLS clients.
 */
#include "corehttpd.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

/* =====================================================================
 * connection state
 * ===================================================================== */
struct TlsConn {
    int  fd;
    int  timeout;                 /* seconds, for record reads */
    int  handshake_done;

    unsigned char client_hs_key[16], client_hs_iv[12];
    unsigned char server_hs_key[16], server_hs_iv[12];
    unsigned char client_ap_key[16], client_ap_iv[12];
    unsigned char server_ap_key[16], server_ap_iv[12];
    uint64_t seq_in, seq_out;     /* record sequence numbers (ap keys) */

    unsigned char *rbbuf;         /* raw bytes read from the socket */
    size_t rblen, rbpos, rbcap;

    unsigned char *pb;            /* pushback: decrypted bytes to serve first */
    size_t pb_len, pb_off, pb_cap;

    unsigned char *ptbuf;         /* decrypted plaintext for tls_read */
    size_t ptlen, ptoff, ptcap;

    unsigned char *scratch;       /* record encrypt/decrypt work area */
    size_t scratchcap;
};

#define TLS_MAX_PLAINTEXT 16384

static void die_oom(void) {
    fputs("corehttpd: out of memory (tls)\n", stderr);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) die_oom();
    return p;
}

/* =====================================================================
 * misc helpers
 * ===================================================================== */
static void put_u16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v;
}
static void put_u24(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 16); p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)v;
}
static unsigned get_u16(const unsigned char *p) {
    return ((unsigned)p[0] << 8) | p[1];
}
static unsigned get_u24(const unsigned char *p) {
    return ((unsigned)p[0] << 16) | ((unsigned)p[1] << 8) | p[2];
}

static int random_bytes(void *buf, size_t n) {
#if defined(__linux__)
    ssize_t r = getrandom(buf, n, 0);
    if (r == (ssize_t)n) return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (unsigned char *)buf + got, n - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    return got == n ? 0 : -1;
}

static int ct_eq32(const unsigned char *a, const unsigned char *b) {
    unsigned char d = 0;
    for (int i = 0; i < 32; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

static int send_raw_all(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* =====================================================================
 * SHA-256
 * ===================================================================== */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char blk[64];
    size_t blen;
} Sha256;

static const uint32_t sha_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(Sha256 *s) {
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    };
    memcpy(s->h, iv, sizeof(iv));
    s->len = 0; s->blen = 0;
}

static void sha256_block(Sha256 *s, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    uint32_t e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + sha_k[i] + w[i];
        uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_update(Sha256 *s, const void *data, size_t n) {
    const unsigned char *p = data;
    s->len += n;
    if (s->blen) {
        size_t take = 64 - s->blen;
        if (take > n) take = n;
        memcpy(s->blk + s->blen, p, take);
        s->blen += take; p += take; n -= take;
        if (s->blen == 64) { sha256_block(s, s->blk); s->blen = 0; }
    }
    while (n >= 64) { sha256_block(s, p); p += 64; n -= 64; }
    if (n) { memcpy(s->blk, p, n); s->blen = n; }
}

static void sha256_final(Sha256 *s, unsigned char out[32]) {
    uint64_t bits = s->len * 8;
    unsigned char pad = 0x80;
    sha256_update(s, &pad, 1);
    unsigned char zero = 0;
    while (s->blen != 56) sha256_update(s, &zero, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(s, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(s->h[i] >> 24);
        out[4*i+1] = (unsigned char)(s->h[i] >> 16);
        out[4*i+2] = (unsigned char)(s->h[i] >> 8);
        out[4*i+3] = (unsigned char)s->h[i];
    }
}

static void sha256_one(unsigned char out[32], const void *data, size_t n) {
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, data, n);
    sha256_final(&s, out);
}

/* =====================================================================
 * HMAC-SHA256
 * ===================================================================== */
static void hmac_sha256(unsigned char out[32], const unsigned char *key,
                        size_t klen, const unsigned char *data, size_t dlen) {
    unsigned char k[64] = {0};
    if (klen > 64) { sha256_one(k, key, klen); klen = 32; }
    else if (klen) memcpy(k, key, klen);

    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    Sha256 s;
    sha256_init(&s);
    sha256_update(&s, ipad, 64);
    sha256_update(&s, data, dlen);
    unsigned char h[32];
    sha256_final(&s, h);
    sha256_init(&s);
    sha256_update(&s, opad, 64);
    sha256_update(&s, h, 32);
    sha256_final(&s, out);
}

/* =====================================================================
 * HKDF (RFC 5869) + TLS 1.3 labels (RFC 8446 §7.1)
 * ===================================================================== */
static void hkdf_extract(unsigned char prk[32], const unsigned char *salt,
                         size_t slen, const unsigned char *ikm, size_t ilen) {
    hmac_sha256(prk, salt, slen, ikm, ilen);
}

static void hkdf_expand(unsigned char *out, size_t olen,
                        const unsigned char prk[32],
                        const unsigned char *info, size_t ilen) {
    unsigned char t[32];
    size_t tlen = 0, done = 0;
    unsigned char counter = 1;
    unsigned char msg[32 + 255 + 1];
    while (done < olen) {
        size_t mlen = 0;
        if (tlen) { memcpy(msg, t, tlen); mlen += tlen; }
        memcpy(msg + mlen, info, ilen); mlen += ilen;
        msg[mlen++] = counter;
        hmac_sha256(t, prk, 32, msg, mlen);
        tlen = 32; counter++;
        size_t take = olen - done;
        if (take > 32) take = 32;
        memcpy(out + done, t, take);
        done += take;
    }
}

/* HKDF-Expand-Label(secret, label, context, length) */
static void expand_label(unsigned char *out, size_t olen,
                         const unsigned char secret[32], const char *label,
                         const unsigned char *ctx, size_t ctxlen) {
    size_t llen = strlen(label);
    unsigned char info[2 + 1 + 6 + 32 + 1 + 255];
    put_u16(info, (unsigned)olen);
    info[2] = (unsigned char)(6 + llen);
    memcpy(info + 3, "tls13 ", 6);
    memcpy(info + 9, label, llen);
    info[9 + llen] = (unsigned char)ctxlen;
    if (ctxlen) memcpy(info + 10 + llen, ctx, ctxlen);
    hkdf_expand(out, olen, secret, info, 2 + 1 + 6 + llen + 1 + ctxlen);
}

/* Derive-Secret(secret, label, transcript) */
static void derive_secret(unsigned char out[32], const unsigned char secret[32],
                          const char *label, const Sha256 *tr) {
    Sha256 c = *tr;
    unsigned char hash[32];
    sha256_final(&c, hash);
    expand_label(out, 32, secret, label, hash, 32);
}

/* =====================================================================
 * X25519 (RFC 7748) — 16 x 16-bit limbs
 * ===================================================================== */
typedef int64_t gf[16];

static void gf_set(gf o, int64_t v) {
    for (int i = 0; i < 16; i++) o[i] = 0;
    o[0] = v;
}

static void gf_add(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

/* reduce limbs to 16 bits, folding carries at 2^256 back down (2^256 ≡ 38) */
static void gf_norm(gf o) {
    for (int pass = 0; pass < 3; pass++) {
        for (int i = 0; i < 15; i++) {
            int64_t c = o[i] >> 16;
            o[i] -= c * 65536;
            o[i + 1] += c;
        }
        int64_t c = o[15] >> 16;
        o[15] -= c * 65536;
        o[0] += 38 * c;
    }
}

static void gf_mul(gf o, const gf a, const gf b) {
    gf t;
    for (int i = 0; i < 16; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) {
            int k = i + j;
            if (k < 16) t[k] += a[i] * b[j];
            else t[k - 16] += 38 * a[i] * b[j];
        }
    gf_norm(t);
    memcpy(o, t, sizeof(gf));
}

static void gf_sq(gf o, const gf a) { gf_mul(o, a, a); }

static void gf_cswap(uint64_t sw, gf a, gf b) {
    int64_t m = (int64_t)(0 - sw);
    for (int i = 0; i < 16; i++) {
        int64_t t = (a[i] ^ b[i]) & m;
        a[i] ^= t; b[i] ^= t;
    }
}

/* a^(p-2) = a^(2^255 - 21), for inversion */
static void gf_inv(gf o, const gf a) {
    static const unsigned char e[32] = {
        0xeb,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
    };
    gf r;
    gf_set(r, 1);
    for (int b = 254; b >= 0; b--) {
        gf_sq(r, r);
        if (e[b / 8] & (1 << (b % 8))) gf_mul(r, r, a);
    }
    memcpy(o, r, sizeof(gf));
}

static void modp_sub(unsigned char r[32]) {
    static const unsigned char P[32] = {
        0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
    };
    unsigned char t[32];
    int64_t borrow = 0;
    for (int i = 0; i < 32; i++) {
        int64_t v = (int64_t)r[i] - P[i] - borrow;
        t[i] = (unsigned char)(v & 0xff);
        borrow = (v >> 8) & 1;
    }
    if (!borrow) memcpy(r, t, 32);   /* r >= p: keep the reduced value */
}

static void pack32(unsigned char out[32], const gf g) {
    int64_t t[16];
    memcpy(t, g, sizeof t);
    for (int iter = 0; iter < 10; iter++) {
        int64_t carry = 0;
        for (int i = 0; i < 16; i++) {
            int64_t v = t[i] + carry;
            carry = v >> 16;
            t[i] = v - carry * 65536;
        }
        if (!carry) break;
        t[0] += 38 * carry;
    }
    for (int i = 0; i < 16; i++) {
        out[2 * i]     = (unsigned char)(t[i] & 0xff);
        out[2 * i + 1] = (unsigned char)((t[i] >> 8) & 0xff);
    }
    modp_sub(out);
    modp_sub(out);
}

static void unpack16(gf o, const unsigned char in[32]) {
    for (int i = 0; i < 16; i++)
        o[i] = in[2 * i] | ((int64_t)in[2 * i + 1] << 8);
    o[15] &= 0x7fff;                 /* clear bit 255 */
}

/* X25519(scalar, u-coordinate) -> shared secret (little-endian).
 * The scalar is clamped per RFC 7748. */
static void x25519(unsigned char out[32], const unsigned char scalar[32],
                   const unsigned char point[32]) {
    gf x1, x2, z2, x3, z3, A, AA, B, BB, E, C, D, DA, CB, t0;
    static const gf c121665 = {
        121665,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    };

    unsigned char k[32];
    memcpy(k, scalar, 32);
    k[0] &= 248; k[31] &= 127; k[31] |= 64;

    unpack16(x1, point);
    gf_set(x2, 1); gf_set(z2, 0);
    memcpy(x3, x1, sizeof(gf)); gf_set(z3, 1);

    uint64_t swap = 0;
    for (int t = 254; t >= 0; t--) {
        uint64_t kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        gf_cswap(swap, x2, x3);
        gf_cswap(swap, z2, z3);
        swap = kt;

        gf_add(A, x2, z2);  gf_sq(AA, A);
        gf_sub(B, x2, z2);  gf_sq(BB, B);
        gf_sub(E, AA, BB);
        gf_add(C, x3, z3);
        gf_sub(D, x3, z3);
        gf_mul(DA, D, A);
        gf_mul(CB, C, B);
        gf_add(t0, DA, CB); gf_sq(x3, t0);
        gf_sub(t0, DA, CB); gf_sq(z3, t0); gf_mul(z3, z3, x1);
        gf_mul(x2, AA, BB);
        gf_mul(t0, E, c121665);
        gf_add(t0, AA, t0);
        gf_mul(z2, E, t0);
    }
    gf_cswap(swap, x2, x3);
    gf_cswap(swap, z2, z3);

    gf_inv(z2, z2);
    gf_mul(t0, x2, z2);
    pack32(out, t0);
}

/* =====================================================================
 * 256-bit modular arithmetic (4 x 64-bit limbs, little-endian)
 * ===================================================================== */
typedef struct { uint64_t l[4]; } M256;

static const M256 P256_MOD = { .l = {
    0xffffffffffffffffULL, 0x00000000ffffffffULL,
    0x0000000000000000ULL, 0xffffffff00000001ULL } };

static const M256 N256_MOD = { .l = {
    0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL,
    0xffffffffffffffffULL, 0xffffffff00000000ULL } };

static const M256 P256_GX = { .l = {
    0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
    0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL } };

static const M256 P256_GY = { .l = {
    0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
    0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL } };

static int m256_cmp(const M256 *a, const M256 *b) {
    for (int i = 3; i >= 0; i--) {
        if (a->l[i] != b->l[i]) return a->l[i] > b->l[i] ? 1 : -1;
    }
    return 0;
}

static int m256_is_zero(const M256 *a) {
    return (a->l[0] | a->l[1] | a->l[2] | a->l[3]) == 0;
}

static void m256_addmod(M256 *r, const M256 *a, const M256 *b,
                        const M256 *m) {
    uint64_t s[5];
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 v = (unsigned __int128)a->l[i] + b->l[i] + carry;
        s[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    s[4] = carry;                      /* a+b < 2^257 */
    for (int t = 0; t < 2; t++) {      /* subtract m up to twice */
        int lt = s[4] == 0 && m256_cmp((const M256 *)s, m) < 0;
        if (lt) break;
        uint64_t borrow = 0;
        for (int i = 0; i < 5; i++) {
            uint64_t mi = i < 4 ? m->l[i] : 0;
            uint64_t a2 = s[i];
            unsigned __int128 sub = (unsigned __int128)mi + borrow;
            borrow = ((unsigned __int128)a2 < sub) ? 1 : 0;
            s[i] = a2 - (uint64_t)sub;
        }
    }
    memcpy(r->l, s, 32);
}

static void m256_submod(M256 *r, const M256 *a, const M256 *b,
                        const M256 *m) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t a2 = a->l[i];
        unsigned __int128 sub = (unsigned __int128)b->l[i] + borrow;
        borrow = ((unsigned __int128)a2 < sub) ? 1 : 0;
        r->l[i] = a2 - (uint64_t)sub;
    }
    if (borrow) {                                  /* r += m */
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            unsigned __int128 s = (unsigned __int128)r->l[i] + m->l[i] + carry;
            r->l[i] = (uint64_t)s;
            carry = (uint64_t)(s >> 64);
        }
    }
}

/* reduce the 512-bit product t modulo m (m >= 2^255, so bit 255 of m is
 * set and the quotient has at most 257 bits) */
static void mod_reduce(uint64_t t[8], const M256 *m) {
    uint64_t s[8];
    for (int i = 511; i >= 255; i--) {
        int sh = i - 255;
        int woff = sh >> 6, sbit = sh & 63;
        memset(s, 0, sizeof(s));
        for (int k = 0; k < 4; k++) {
            s[woff + k] |= m->l[k] << sbit;
            if (sbit && woff + k + 1 < 8)
                s[woff + k + 1] |= m->l[k] >> (64 - sbit);
        }
        /* subtract m << sh if t >= that value */
        int skip = 0;
        for (int k = 7; k >= 0; k--) {
            if (t[k] != s[k]) { skip = t[k] < s[k]; break; }
        }
        if (skip) continue;
        uint64_t borrow = 0;
        for (int k = 0; k < 8; k++) {
            uint64_t a2 = t[k];
            unsigned __int128 sub = (unsigned __int128)s[k] + borrow;
            borrow = ((unsigned __int128)a2 < sub) ? 1 : 0;
            t[k] = a2 - (uint64_t)sub;
        }
    }
}

static void m256_mulmod(M256 *r, const M256 *a, const M256 *b,
                        const M256 *m) {
    uint64_t t[8] = {0};
    /* schoolbook with per-row carry propagation: the running sums can
     * exceed 2^128, so plain 128-bit accumulators would overflow */
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 p = (unsigned __int128)a->l[i] * b->l[j];
            unsigned __int128 sum = (unsigned __int128)t[i + j] +
                                    (uint64_t)p + carry;
            t[i + j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64) + (uint64_t)(p >> 64);
        }
        for (int k = i + 4; carry && k < 8; k++) {
            unsigned __int128 sum = (unsigned __int128)t[k] + carry;
            t[k] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
    }
    mod_reduce(t, m);
    memcpy(r->l, t, 32);
}

static void m256_sqrmod(M256 *r, const M256 *a, const M256 *m) {
    m256_mulmod(r, a, a, m);
}

/* a^(m-2) mod m (m prime) */
static void m256_invmod(M256 *r, const M256 *a, const M256 *m) {
    M256 e, x, res;
    uint64_t borrow = 2;
    for (int i = 0; i < 4; i++) {                  /* e = m - 2 */
        uint64_t v = m->l[i] - borrow;
        e.l[i] = v;
        borrow = (m->l[i] < borrow) ? 1 : 0;
    }
    x = *a;
    res.l[0] = 1; res.l[1] = res.l[2] = res.l[3] = 0;
    for (int i = 3; i >= 0; i--)
        for (int b = 63; b >= 0; b--) {
            m256_sqrmod(&res, &res, m);
            if ((e.l[i] >> b) & 1) m256_mulmod(&res, &res, &x, m);
        }
    *r = res;
}

/* =====================================================================
 * P-256 (secp256r1) — Jacobian coordinates
 * ===================================================================== */
typedef struct { M256 x, y, z; } PPoint;

static const M256 M256_ONE = { .l = {1, 0, 0, 0} };

/* Jacobian doubling (general formula, a = -3) */
static void ppoint_double(PPoint *r, const PPoint *p) {
    M256 XX, YY, YYYY, ZZ, S, M, T, t, t2;

    m256_sqrmod(&XX, &p->x, &P256_MOD);            /* XX = X1^2 */
    m256_sqrmod(&YY, &p->y, &P256_MOD);            /* YY = Y1^2 */
    m256_sqrmod(&YYYY, &YY, &P256_MOD);            /* YYYY = Y1^4 */
    m256_sqrmod(&ZZ, &p->z, &P256_MOD);            /* ZZ = Z1^2 */

    /* Z3 = 2*Y1*Z1 — computed first: r may alias p */
    m256_mulmod(&r->z, &p->y, &p->z, &P256_MOD);
    m256_addmod(&r->z, &r->z, &r->z, &P256_MOD);

    /* S = 4*X1*YY */
    m256_mulmod(&S, &p->x, &YY, &P256_MOD);
    m256_addmod(&S, &S, &S, &P256_MOD);
    m256_addmod(&S, &S, &S, &P256_MOD);

    /* M = 3*XX + a*ZZ^2 with a = -3  =>  3*(XX - ZZ^2) */
    m256_addmod(&t, &XX, &XX, &P256_MOD);
    m256_addmod(&M, &t, &XX, &P256_MOD);           /* 3*XX */
    m256_sqrmod(&t, &ZZ, &P256_MOD);               /* ZZ^2 */
    m256_addmod(&t2, &t, &t, &P256_MOD);
    m256_addmod(&t2, &t2, &t, &P256_MOD);          /* 3*ZZ^2 */
    m256_submod(&M, &M, &t2, &P256_MOD);

    /* T = M^2 - 2*S  =>  X3 */
    m256_sqrmod(&T, &M, &P256_MOD);
    m256_addmod(&t, &S, &S, &P256_MOD);
    m256_submod(&r->x, &T, &t, &P256_MOD);

    /* Y3 = M*(S - X3) - 8*YYYY */
    m256_submod(&t2, &S, &r->x, &P256_MOD);
    m256_mulmod(&t2, &M, &t2, &P256_MOD);
    m256_addmod(&t, &YYYY, &YYYY, &P256_MOD);
    m256_addmod(&t, &t, &t, &P256_MOD);
    m256_addmod(&t, &t, &t, &P256_MOD);            /* 8*YYYY */
    m256_submod(&r->y, &t2, &t, &P256_MOD);
}

/* general Jacobian addition */
static void ppoint_add(PPoint *r, const PPoint *p, const PPoint *q) {
    M256 Z1Z1, Z2Z2, U1, U2, S1, S2, H, R, HH, HHH, V, t, t2;
    M256 x, y, z;

    m256_sqrmod(&Z1Z1, &p->z, &P256_MOD);
    m256_sqrmod(&Z2Z2, &q->z, &P256_MOD);
    m256_mulmod(&U1, &p->x, &Z2Z2, &P256_MOD);
    m256_mulmod(&U2, &q->x, &Z1Z1, &P256_MOD);
    m256_mulmod(&t, &q->z, &Z2Z2, &P256_MOD);
    m256_mulmod(&S1, &p->y, &t, &P256_MOD);
    m256_mulmod(&t, &p->z, &Z1Z1, &P256_MOD);
    m256_mulmod(&S2, &q->y, &t, &P256_MOD);
    m256_submod(&H, &U2, &U1, &P256_MOD);
    m256_submod(&R, &S2, &S1, &P256_MOD);
    if (m256_is_zero(&H)) {
        if (m256_is_zero(&R)) { ppoint_double(r, p); return; }
        memset(r, 0, sizeof(*r));                  /* point at infinity */
        return;
    }
    m256_sqrmod(&HH, &H, &P256_MOD);
    m256_mulmod(&HHH, &HH, &H, &P256_MOD);
    m256_mulmod(&V, &U1, &HH, &P256_MOD);
    m256_sqrmod(&t, &R, &P256_MOD);                /* R^2 */
    m256_addmod(&t2, &V, &V, &P256_MOD);           /* 2V */
    m256_submod(&t, &t, &HHH, &P256_MOD);
    m256_submod(&x, &t, &t2, &P256_MOD);           /* X3 = R^2-HHH-2V */
    m256_submod(&t, &V, &x, &P256_MOD);            /* V - X3 */
    m256_mulmod(&t, &R, &t, &P256_MOD);
    m256_mulmod(&t2, &S1, &HHH, &P256_MOD);
    m256_submod(&y, &t, &t2, &P256_MOD);           /* Y3 */
    m256_mulmod(&z, &p->z, &q->z, &P256_MOD);
    m256_mulmod(&z, &z, &H, &P256_MOD);            /* Z3 */

    r->x = x; r->y = y; r->z = z;
}

/* k * P, double-and-add over the 256-bit scalar */
static void ppoint_mul(PPoint *r, const M256 *k, const PPoint *p) {
    PPoint res;
    memset(&res, 0, sizeof(res));                  /* infinity */
    int started = 0;
    for (int i = 3; i >= 0; i--)
        for (int b = 63; b >= 0; b--) {
            if (started) ppoint_double(&res, &res);
            if ((k->l[i] >> b) & 1) {
                if (!started) { res = *p; started = 1; }
                else ppoint_add(&res, &res, p);
            }
        }
    *r = res;
}

/* convert to affine; fails on the point at infinity */
static int ppoint_affine(M256 *ax, M256 *ay, const PPoint *p) {
    if (m256_is_zero(&p->z)) return -1;
    M256 zi, zi2, zi3;
    m256_invmod(&zi, &p->z, &P256_MOD);
    m256_sqrmod(&zi2, &zi, &P256_MOD);
    m256_mulmod(&zi3, &zi2, &zi, &P256_MOD);
    m256_mulmod(ax, &p->x, &zi2, &P256_MOD);
    m256_mulmod(ay, &p->y, &zi3, &P256_MOD);
    return 0;
}

static const PPoint *ppoint_base(void) {
    static PPoint g;
    static int init = 0;
    if (!init) {
        g.x = P256_GX;
        g.y = P256_GY;
        g.z = M256_ONE;
        init = 1;
    }
    return &g;
}

/* =====================================================================
 * ECDSA P-256 signature, deterministic nonce (RFC 6979)
 * ===================================================================== */
static void m256_from_be(M256 *r, const unsigned char be[32]) {
    for (int i = 0; i < 4; i++)
        r->l[i] = ((uint64_t)be[24 - 8*i]     << 56) |
                  ((uint64_t)be[25 - 8*i] << 48) |
                  ((uint64_t)be[26 - 8*i] << 40) |
                  ((uint64_t)be[27 - 8*i] << 32) |
                  ((uint64_t)be[28 - 8*i] << 24) |
                  ((uint64_t)be[29 - 8*i] << 16) |
                  ((uint64_t)be[30 - 8*i] << 8)  |
                  (uint64_t)be[31 - 8*i];
}

static void m256_to_be(unsigned char be[32], const M256 *r) {
    for (int i = 0; i < 4; i++)
        for (int b = 0; b < 8; b++)
            be[31 - 8*i - b] = (unsigned char)(r->l[i] >> (8 * b));
}

typedef struct { unsigned char v[32], K[32]; } Rfc6979;

/* RFC 6979 §3.2 init (ECDSA + SHA-256); digest already computed */
static void rfc6979_init(Rfc6979 *st, const unsigned char x[32],
                         const unsigned char digest[32]) {
    /* bits2octets(digest) */
    M256 h1m;
    m256_from_be(&h1m, digest);
    if (m256_cmp(&h1m, &N256_MOD) >= 0)
        m256_submod(&h1m, &h1m, &N256_MOD, &N256_MOD);
    unsigned char b2o[32];
    m256_to_be(b2o, &h1m);

    unsigned char msg[97];
    memset(st->v, 0x01, 32);
    memset(st->K, 0x00, 32);

    /* K = HMAC_K(V || 0x00 || x || bits2octets(h1)) */
    memcpy(msg, st->v, 32);
    msg[32] = 0;
    memcpy(msg + 33, x, 32);
    memcpy(msg + 65, b2o, 32);
    hmac_sha256(st->K, st->K, 32, msg, 97);
    /* V = HMAC_K(V) */
    hmac_sha256(st->v, st->K, 32, st->v, 32);
    /* K = HMAC_K(V || 0x01 || x || bits2octets(h1)) — with the NEW V */
    memcpy(msg, st->v, 32);
    msg[32] = 1;
    hmac_sha256(st->K, st->K, 32, msg, 97);
    /* V = HMAC_K(V) */
    hmac_sha256(st->v, st->K, 32, st->v, 32);
}

/* next deterministic nonce candidate; returns 1 <= k < n */
static void rfc6979_next(Rfc6979 *st, M256 *k) {
    unsigned char msg[33];
    for (;;) {
        /* V = HMAC_K(V); candidate = bits2int(V) */
        hmac_sha256(st->v, st->K, 32, st->v, 32);
        M256 cand;
        m256_from_be(&cand, st->v);
        if (!m256_is_zero(&cand) && m256_cmp(&cand, &N256_MOD) < 0) {
            *k = cand;
            return;
        }
        /* K = HMAC_K(V || 0x00); V = HMAC_K(V) */
        memcpy(msg, st->v, 32);
        msg[32] = 0;
        hmac_sha256(st->K, st->K, 32, msg, 33);
        hmac_sha256(st->v, st->K, 32, st->v, 32);
    }
}

static size_t der_encode_int(unsigned char *out, const M256 *v) {
    unsigned char b[32];
    m256_to_be(b, v);
    size_t i = 0;
    while (i < 31 && b[i] == 0) i++;
    size_t n = 32 - i;
    size_t off = 0;
    if (b[i] & 0x80) out[off++] = 0;               /* keep INTEGER positive */
    memcpy(out + off, b + i, n);
    return n + off;
}

/* ECDSA-P256-SHA256 sign; digest = the 32-byte message digest.
 * Returns DER SEQUENCE { INTEGER r, INTEGER s } in out (<= 72 bytes). */
static int ecdsa_sign(unsigned char *out, size_t *outlen,
                      const unsigned char d[32],
                      const unsigned char digest[32]) {
    M256 z, dm;
    m256_from_be(&z, digest);
    if (m256_cmp(&z, &N256_MOD) >= 0)
        m256_submod(&z, &z, &N256_MOD, &N256_MOD);
    m256_from_be(&dm, d);

    Rfc6979 st;
    rfc6979_init(&st, d, digest);

    for (int attempt = 0; attempt < 4; attempt++) {
        M256 k, kinv, r, s, t;
        rfc6979_next(&st, &k);

        /* r = x(k*G) mod n */
        PPoint kg;
        ppoint_mul(&kg, &k, ppoint_base());
        M256 ax, ay;
        if (ppoint_affine(&ax, &ay, &kg) < 0) continue;
        r = ax;
        if (m256_cmp(&r, &N256_MOD) >= 0)
            m256_submod(&r, &r, &N256_MOD, &N256_MOD);
        if (m256_is_zero(&r)) continue;

        /* s = k^-1 * (z + r*d) mod n */
        m256_invmod(&kinv, &k, &N256_MOD);
        m256_mulmod(&t, &r, &dm, &N256_MOD);
        m256_addmod(&t, &t, &z, &N256_MOD);
        m256_mulmod(&s, &kinv, &t, &N256_MOD);
        if (m256_is_zero(&s)) continue;

        unsigned char rbuf[64], sbuf[64];
        size_t rl = der_encode_int(rbuf, &r);
        size_t sl = der_encode_int(sbuf, &s);
        size_t total = 2 + rl + 2 + sl;
        out[0] = 0x30;
        out[1] = (unsigned char)total;
        out[2] = 0x02;
        out[3] = (unsigned char)rl;
        memcpy(out + 4, rbuf, rl);
        out[4 + rl] = 0x02;
        out[5 + rl] = (unsigned char)sl;
        memcpy(out + 6 + rl, sbuf, sl);
        *outlen = 6 + rl + sl;
        return 0;
    }
    return -1;
}

/* =====================================================================
 * AES-128
 * ===================================================================== */
static const unsigned char aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const unsigned char aes_rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

typedef struct { uint32_t rk[44]; } AesKey;

static uint32_t aes_subword(uint32_t w) {
    return ((uint32_t)aes_sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xff] << 8) |
           ((uint32_t)aes_sbox[w & 0xff]);
}

static void aes_expand(AesKey *k, const unsigned char key[16]) {
    for (int i = 0; i < 4; i++)
        k->rk[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                   ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
    for (int i = 4; i < 44; i++) {
        uint32_t t = k->rk[i-1];
        if (i % 4 == 0) {
            t = (t << 8) | (t >> 24);
            t = aes_subword(t) ^ ((uint32_t)aes_rcon[i / 4 - 1] << 24);
        }
        k->rk[i] = k->rk[i-4] ^ t;
    }
}

static uint32_t ld32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void st32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static void aes_enc_block(const AesKey *k, const unsigned char in[16],
                          unsigned char out[16]) {
    uint32_t s[4];
    s[0] = ld32(in)     ^ k->rk[0];
    s[1] = ld32(in + 4) ^ k->rk[1];
    s[2] = ld32(in + 8) ^ k->rk[2];
    s[3] = ld32(in + 12) ^ k->rk[3];

    for (int r = 1; r <= 10; r++) {
        uint32_t t[4];
        for (int i = 0; i < 4; i++)
            t[i] = ((uint32_t)aes_sbox[(s[i] >> 24) & 0xff] << 24) |
                   ((uint32_t)aes_sbox[(s[i] >> 16) & 0xff] << 16) |
                   ((uint32_t)aes_sbox[(s[i] >> 8) & 0xff] << 8) |
                   ((uint32_t)aes_sbox[s[i] & 0xff]);

        uint32_t u[4];
        u[0] = (t[0] & 0xff000000) | (t[1] & 0x00ff0000) |
               (t[2] & 0x0000ff00) | (t[3] & 0x000000ff);
        u[1] = (t[1] & 0xff000000) | (t[2] & 0x00ff0000) |
               (t[3] & 0x0000ff00) | (t[0] & 0x000000ff);
        u[2] = (t[2] & 0xff000000) | (t[3] & 0x00ff0000) |
               (t[0] & 0x0000ff00) | (t[1] & 0x000000ff);
        u[3] = (t[3] & 0xff000000) | (t[0] & 0x00ff0000) |
               (t[1] & 0x0000ff00) | (t[2] & 0x000000ff);

        if (r < 10) {
            for (int i = 0; i < 4; i++) {
                uint32_t a = u[i];
                uint32_t a0 = (a >> 24) & 0xff, a1 = (a >> 16) & 0xff,
                         a2 = (a >> 8) & 0xff,  a3 = a & 0xff;
                uint32_t xt0 = ((a0 << 1) ^ (0x1b & (uint32_t)-(a0 >> 7))) & 0xff;
                uint32_t xt1 = ((a1 << 1) ^ (0x1b & (uint32_t)-(a1 >> 7))) & 0xff;
                uint32_t xt2 = ((a2 << 1) ^ (0x1b & (uint32_t)-(a2 >> 7))) & 0xff;
                uint32_t xt3 = ((a3 << 1) ^ (0x1b & (uint32_t)-(a3 >> 7))) & 0xff;
                uint32_t b0 = xt0 ^ xt1 ^ a1 ^ a2 ^ a3;
                uint32_t b1 = a0 ^ xt1 ^ xt2 ^ a2 ^ a3;
                uint32_t b2 = a0 ^ a1 ^ xt2 ^ xt3 ^ a3;
                uint32_t b3 = xt0 ^ a0 ^ a1 ^ a2 ^ xt3;
                s[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
                s[i] ^= k->rk[4 * r + i];
            }
        } else {
            for (int i = 0; i < 4; i++)
                s[i] = u[i] ^ k->rk[40 + i];
        }
    }
    st32(out, s[0]); st32(out + 4, s[1]);
    st32(out + 8, s[2]); st32(out + 12, s[3]);
}

/* =====================================================================
 * AES-128-GCM
 * ===================================================================== */
/* GHASH multiplication per GCM spec (McGrew-Viega §2.3 / NIST SP 800-38D):
 * bits X_i counted from the left; V is right-shifted each step and
 * R = 11100001 || 0^120 (0xE1 in the first byte) is XORed in when the
 * shifted-out (rightmost) bit was 1. */
static void ghash_mul(unsigned char z[16], const unsigned char x[16],
                      const unsigned char y[16]) {
    unsigned char xx[16], v[16];   /* copies: z may alias x */
    memcpy(xx, x, 16);
    memcpy(v, y, 16);
    memset(z, 0, 16);
    for (int i = 0; i < 16; i++) {
        for (int b = 0x80; b; b >>= 1) {          /* X_i, left to right */
            if (xx[i] & b) {
                for (int k = 0; k < 16; k++) z[k] ^= v[k];
            }
            int lsb = v[15] & 1;                  /* LSB1(V): rightmost bit */
            for (int k = 15; k > 0; k--)
                v[k] = (unsigned char)((v[k] >> 1) | (v[k-1] << 7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1;                /* V = Rshift(V) XOR R */
        }
    }
}

static void gcm_inc32(unsigned char ctr[16]) {
    for (int b = 15; b >= 12; b--)
        if (++ctr[b]) break;
}

/* encrypts in->out and returns tag (in and out may alias) */
static void gcm_encrypt(const unsigned char key[16], const unsigned char nonce[12],
                        const unsigned char *aad, size_t aadlen,
                        const unsigned char *in, size_t inlen,
                        unsigned char *out, unsigned char tag[16]) {
    AesKey k;
    aes_expand(&k, key);

    unsigned char h[16] = {0};
    aes_enc_block(&k, h, h);                       /* H = E_K(0^128) */

    unsigned char j0[16];
    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0; j0[15] = 1;

    unsigned char ctr[16];
    memcpy(ctr, j0, 16);
    for (size_t i = 0; i < inlen; i += 16) {
        gcm_inc32(ctr);
        unsigned char ek[16];
        aes_enc_block(&k, ctr, ek);
        size_t blk = inlen - i;
        if (blk > 16) blk = 16;
        for (size_t b = 0; b < blk; b++) out[i + b] = in[i + b] ^ ek[b];
    }

    unsigned char y[16] = {0};
    for (size_t i = 0; i < aadlen; i += 16) {
        unsigned char t[16] = {0};
        size_t blk = aadlen - i;
        if (blk > 16) blk = 16;
        memcpy(t, aad + i, blk);
        for (int b = 0; b < 16; b++) y[b] ^= t[b];
        ghash_mul(y, y, h);
    }
    for (size_t i = 0; i < inlen; i += 16) {
        unsigned char t[16] = {0};
        size_t blk = inlen - i;
        if (blk > 16) blk = 16;
        memcpy(t, out + i, blk);
        for (int b = 0; b < 16; b++) y[b] ^= t[b];
        ghash_mul(y, y, h);
    }

    unsigned char lb[16] = {0};
    uint64_t ab = (uint64_t)aadlen * 8, cb = (uint64_t)inlen * 8;
    for (int i = 0; i < 8; i++) {
        lb[i]     = (unsigned char)(ab >> (56 - 8 * i));
        lb[8 + i] = (unsigned char)(cb >> (56 - 8 * i));
    }
    for (int b = 0; b < 16; b++) y[b] ^= lb[b];
    ghash_mul(y, y, h);

    unsigned char ej[16];
    aes_enc_block(&k, j0, ej);
    for (int b = 0; b < 16; b++) tag[b] = ej[b] ^ y[b];
}

/* decrypts in (ciphertext || tag) -> out; 0 on auth success */
static int gcm_decrypt(const unsigned char key[16], const unsigned char nonce[12],
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *in, size_t inlen,
                       unsigned char *out) {
    if (inlen < 16) return -1;
    size_t clen = inlen - 16;

    AesKey k;
    aes_expand(&k, key);

    unsigned char h[16] = {0};
    aes_enc_block(&k, h, h);

    unsigned char j0[16];
    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0; j0[15] = 1;

    unsigned char ctr[16];
    memcpy(ctr, j0, 16);
    for (size_t i = 0; i < clen; i += 16) {
        gcm_inc32(ctr);
        unsigned char ek[16];
        aes_enc_block(&k, ctr, ek);
        size_t blk = clen - i;
        if (blk > 16) blk = 16;
        for (size_t b = 0; b < blk; b++) out[i + b] = in[i + b] ^ ek[b];
    }

    unsigned char y[16] = {0};
    for (size_t i = 0; i < aadlen; i += 16) {
        unsigned char t[16] = {0};
        size_t blk = aadlen - i;
        if (blk > 16) blk = 16;
        memcpy(t, aad + i, blk);
        for (int b = 0; b < 16; b++) y[b] ^= t[b];
        ghash_mul(y, y, h);
    }
    for (size_t i = 0; i < clen; i += 16) {
        unsigned char t[16] = {0};
        size_t blk = clen - i;
        if (blk > 16) blk = 16;
        memcpy(t, in + i, blk);
        for (int b = 0; b < 16; b++) y[b] ^= t[b];
        ghash_mul(y, y, h);
    }

    unsigned char lb[16] = {0};
    uint64_t ab = (uint64_t)aadlen * 8, cb = (uint64_t)clen * 8;
    for (int i = 0; i < 8; i++) {
        lb[i]     = (unsigned char)(ab >> (56 - 8 * i));
        lb[8 + i] = (unsigned char)(cb >> (56 - 8 * i));
    }
    for (int b = 0; b < 16; b++) y[b] ^= lb[b];
    ghash_mul(y, y, h);

    unsigned char ej[16], expect[16];
    aes_enc_block(&k, j0, ej);
    for (int b = 0; b < 16; b++) expect[b] = ej[b] ^ y[b];

    unsigned char d = 0;
    for (int b = 0; b < 16; b++) d |= (unsigned char)(expect[b] ^ in[clen + b]);
    return d == 0 ? 0 : -1;
}

/* =====================================================================
 * record layer
 * ===================================================================== */
static void tls_nonce(unsigned char out[12], const unsigned char iv[12],
                      uint64_t seq) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++)
        out[4 + i] ^= (unsigned char)(seq >> (56 - 8 * i));
}

/* wait for and read more raw bytes into c->rbbuf */
static int tls_fill(TlsConn *c) {
    if (c->rblen >= c->rbcap) return -1;
    struct pollfd p = { c->fd, POLLIN, 0 };
    int r = poll(&p, 1, c->timeout * 1000);
    if (r <= 0 || !(p.revents & POLLIN)) return -1;
    ssize_t n = read(c->fd, c->rbbuf + c->rblen, c->rbcap - c->rblen);
    if (n <= 0) return -1;
    c->rblen += (size_t)n;
    return 0;
}

/* Fetch the next record's content into out (max cap bytes).
 * Skips ChangeCipherSpec records. Decrypts TLS 1.3 application_data
 * records (using handshake or application keys depending on state) and
 * strips the inner content type.  Returns content length, -1 on error. */
static int tls_next_record(TlsConn *c, unsigned char *out, size_t cap,
                           unsigned char *ctype) {
    for (;;) {
        while (c->rblen - c->rbpos < 5) {
            if (c->rbpos) {
                memmove(c->rbbuf, c->rbbuf + c->rbpos, c->rblen - c->rbpos);
                c->rblen -= c->rbpos; c->rbpos = 0;
            }
            if (tls_fill(c) < 0) return -1;
        }
        unsigned rtype = c->rbbuf[c->rbpos];
        size_t rlen = ((size_t)c->rbbuf[c->rbpos + 3] << 8) |
                      c->rbbuf[c->rbpos + 4];
        if (5 + rlen > c->rbcap) return -1;
        while (c->rblen - c->rbpos < 5 + rlen) {
            if (c->rbpos) {
                memmove(c->rbbuf, c->rbbuf + c->rbpos, c->rblen - c->rbpos);
                c->rblen -= c->rbpos; c->rbpos = 0;
            }
            if (tls_fill(c) < 0) return -1;
        }
        const unsigned char *rec = c->rbbuf + c->rbpos + 5;
        c->rbpos += 5 + rlen;

        if (rtype == 20) continue;                    /* CCS: skip */
        if (rtype == 21) return -1;                   /* alert */
        if (rtype == 22 && !c->handshake_done) {      /* plaintext handshake */
            if (rlen > cap) return -1;
            memcpy(out, rec, rlen);
            *ctype = 22;
            return (int)rlen;
        }
        if (rtype == 23) {
            if (rlen < 17) return -1;
            const unsigned char *key, *iv;
            if (!c->handshake_done) {
                key = c->client_hs_key; iv = c->client_hs_iv;
            } else {
                key = c->client_ap_key; iv = c->client_ap_iv;
            }
            unsigned char nonce[12];
            tls_nonce(nonce, iv, c->seq_in++);
            unsigned char aad[5] = { 23, 3, 3,
                (unsigned char)(rlen >> 8), (unsigned char)rlen };
            size_t ptlen = rlen - 16;
            if (ptlen > c->scratchcap) return -1;
            if (gcm_decrypt(key, nonce, aad, 5, rec, rlen, c->scratch) < 0)
                return -1;
            /* inner plaintext = content || type || zero padding */
            int j = (int)ptlen - 1;
            while (j >= 0 && c->scratch[j] == 0) j--;
            if (j < 0) return -1;
            *ctype = c->scratch[j];
            size_t clen = (size_t)j;
            if (clen > cap) return -1;
            memcpy(out, c->scratch, clen);
            return (int)clen;
        }
        return -1;
    }
}

static void tls_send_alert(int fd, unsigned char desc) {
    unsigned char r[7] = { 21, 3, 3, 0, 2, 2, desc };
    ssize_t ignored = write(fd, r, sizeof(r));
    (void)ignored;
}

/* accumulate handshake messages (possibly fragmented across records) */
static int hs_read_msg(Arena *a, TlsConn *c, unsigned char **out,
                       size_t *outlen, unsigned char *outtype) {
    size_t cap = 65536 + 4, len = 0;
    unsigned char *buf = arena_alloc(a, cap);
    if (!buf) return -1;
    for (;;) {
        if (len >= 4) {
            size_t mlen = 4 + get_u24(buf + 1);
            if (mlen > cap) return -1;
            if (len >= mlen) {
                unsigned char *m = arena_alloc(a, mlen);
                if (!m) return -1;
                memcpy(m, buf, mlen);
                memmove(buf, buf + mlen, len - mlen);
                len -= mlen;
                *out = m; *outlen = mlen; *outtype = m[0];
                return 0;
            }
        }
        unsigned char ctype;
        int clen = tls_next_record(c, buf + len, cap - len, &ctype);
        if (clen < 0) return -1;
        if (ctype == 21) return -1;
        if (ctype != 22) continue;
        len += (size_t)clen;
    }
}

/* =====================================================================
 * certificate chain loading (PEM or single DER)
 * ===================================================================== */
static int pem_b64(const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t outcap) {
    size_t o = 0;
    int quad = 0;
    uint32_t acc = 0;
    for (size_t i = 0; i < inlen && o + 3 <= outcap; i++) {
        int c = in[i];
        int v;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        else return -1;
        acc = (acc << 6) | (uint32_t)v;
        quad++;
        if (quad == 4) {
            out[o++] = (unsigned char)(acc >> 16);
            out[o++] = (unsigned char)(acc >> 8);
            out[o++] = (unsigned char)acc;
            acc = 0; quad = 0;
        }
    }
    if (quad == 3) { out[o++] = (unsigned char)(acc >> 10); out[o++] = (unsigned char)(acc >> 2); }
    else if (quad == 2) { out[o++] = (unsigned char)(acc >> 4); }
    return (int)o;
}

/* ---------------------------------------------------------------------
 * key material loading: done ONCE by the master process (tls_load_key).
 * The httpd child only ever sees the resulting TlsKey.
 * --------------------------------------------------------------------- */

/* advance past one DER TLV; returns pointer after it, or NULL */
static const unsigned char *der_next(const unsigned char *p,
                                     const unsigned char *end) {
    if (p >= end) return NULL;
    p++;                                           /* tag */
    if (p >= end) return NULL;
    size_t len = *p++;
    if (len & 0x80) {
        size_t n = len & 0x7f;
        if (n == 0 || n > 2 || p + n > end) return NULL;
        len = 0;
        while (n--) len = (len << 8) | *p++;
    }
    if (p + len > end) return NULL;
    return p + len;
}

/* find the 32-byte OCTET STRING (the P-256 scalar) inside SEC1 or PKCS#8 */
static int der_scalar_in(const unsigned char *p, const unsigned char *end,
                         unsigned char scalar[32]) {
    if (p >= end) return -1;
    unsigned char tag = *p++;
    if (p >= end) return -1;
    size_t len = *p++;
    if (len & 0x80) {
        size_t n = len & 0x7f;
        if (n == 0 || n > 2 || p + n > end) return -1;
        len = 0;
        while (n--) len = (len << 8) | *p++;
    }
    if (p + len > end) return -1;
    if (tag == 0x04 && len == 32) {
        memcpy(scalar, p, 32);
        return 0;
    }
    if (tag == 0x30 || tag == 0x04 || (tag & 0xe0) == 0xa0) {
        const unsigned char *q = p, *qend = p + len;
        while (q < qend) {
            const unsigned char *nxt = der_next(q, qend);
            if (!nxt) return -1;
            if (der_scalar_in(q, qend, scalar) == 0) return 0;
            q = nxt;
        }
    }
    return -1;
}

/* true if the prime256v1 OID (1.2.840.10045.3.1.7) occurs in the DER */
static int has_oid_prime256(const unsigned char *d, size_t len) {
    static const unsigned char oid[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    };
    for (size_t i = 0; i + sizeof(oid) <= len; i++)
        if (memcmp(d + i, oid, sizeof(oid)) == 0) return 1;
    return 0;
}

/* decode one PEM block with the given BEGIN label into der (cap = dermax);
 * buf must be NUL-terminated */
static int pem_get_block(const char *buf, const char *label,
                         unsigned char *der, size_t *derlen, size_t dermax) {
    char begin[96], end[96];
    size_t ll = strlen(label);
    if (ll < 1 || ll > 63) return -1;
    snprintf(begin, sizeof(begin), "-----BEGIN %s-----", label);
    snprintf(end, sizeof(end), "-----END %s-----", label);

    const char *p = strstr(buf, begin);
    if (!p) return -1;
    p += strlen(begin);
    const char *e = strstr(p, end);
    if (!e) return -1;
    size_t cap2 = (size_t)(e - p) / 4 * 3 + 3;
    if (cap2 > dermax) return -1;
    int dl = pem_b64((const unsigned char *)p, (size_t)(e - p), der, cap2);
    if (dl <= 0) return -1;
    *derlen = (size_t)dl;
    return 0;
}

/* Load the certificate chain and the P-256 private key into the arena.
 * Called by the master before forking. */
TlsKey *tls_load_key(Arena *a, const char *cert_file, const char *key_file) {
    TlsKey *k = arena_alloc(a, sizeof(*k));
    if (!k) return NULL;
    memset(k, 0, sizeof(*k));

    /* ---- certificate chain ---- */
    FILE *f = fopen(cert_file, "rb");
    if (!f) { perror(cert_file); return NULL; }
    size_t cap = 1u << 20;
    unsigned char *cbuf = arena_alloc(a, cap + 1);
    if (!cbuf) { fclose(f); return NULL; }
    size_t clen = fread(cbuf, 1, cap, f);
    fclose(f);
    if (clen >= cap || clen < 4) return NULL;
    cbuf[clen] = 0;                                /* NUL for strstr */

    if (cbuf[0] == 0x30) {                         /* single DER cert */
        k->der[0] = cbuf;
        k->len[0] = clen;
        k->n_certs = 1;
    } else {
        static const char BEG[] = "-----BEGIN CERTIFICATE-----";
        static const char END[] = "-----END CERTIFICATE-----";
        char *p = (char *)cbuf;
        while (k->n_certs < TLS_MAX_CERTS && (p = strstr(p, BEG)) != NULL) {
            p += sizeof(BEG) - 1;
            char *e = strstr(p, END);
            if (!e) break;
            size_t cap2 = (size_t)(e - p) / 4 * 3 + 3;
            unsigned char *der = arena_alloc(a, cap2);
            if (!der) return NULL;
            int dl = pem_b64((unsigned char *)p, (size_t)(e - p), der, cap2);
            if (dl > 0) {
                k->der[k->n_certs] = der;
                k->len[k->n_certs] = (size_t)dl;
                k->n_certs++;
            }
            p = e + sizeof(END) - 1;
        }
    }
    if (k->n_certs <= 0) return NULL;

    /* ---- private key ---- */
    f = fopen(key_file, "rb");
    if (!f) { perror(key_file); return NULL; }
    unsigned char *kbuf = arena_alloc(a, cap + 1);
    if (!kbuf) { fclose(f); return NULL; }
    size_t klen = fread(kbuf, 1, cap, f);
    fclose(f);
    if (klen >= cap || klen < 4) return NULL;
    kbuf[klen] = 0;                                /* NUL for strstr */

    unsigned char *der = arena_alloc(a, 4096);
    if (!der) return NULL;
    size_t derlen = 0;
    if (kbuf[0] == 0x30) {                         /* raw DER */
        if (klen > 4096) return NULL;
        memcpy(der, kbuf, klen);
        derlen = klen;
    } else if (pem_get_block((char *)kbuf, "EC PRIVATE KEY",
                             der, &derlen, 4096) < 0 &&
               pem_get_block((char *)kbuf, "PRIVATE KEY",
                             der, &derlen, 4096) < 0) {
        return NULL;
    }

    if (!has_oid_prime256(der, derlen)) {
        fprintf(stderr, "%s: not a P-256 (prime256v1) EC key\n", key_file);
        return NULL;
    }
    if (der_scalar_in(der, der + derlen, k->priv) < 0) {
        fprintf(stderr, "%s: failed to extract P-256 scalar\n", key_file);
        return NULL;
    }
    return k;
}

/* =====================================================================
 * handshake message helpers
 * ===================================================================== */
static unsigned char *msg_start(Arena *a, unsigned char type, size_t bodylen) {
    unsigned char *m = arena_alloc(a, 4 + bodylen);
    if (!m) return NULL;
    m[0] = type;
    put_u24(m + 1, (unsigned)bodylen);
    return m;
}

/* =====================================================================
 * handshake (RFC 8446)
 * ===================================================================== */
TlsConn *tls_server_handshake(Arena *a, int fd, const TlsKey *key,
                              tls_pick_key_fn pick, void *pick_arg,
                              int timeout) {
    TlsConn *c = calloc(1, sizeof(*c));
    if (!c) die_oom();
    c->fd = fd;
    c->timeout = timeout > 0 ? timeout : 10;
    if (!key) {
        /* no default certificate configured: still read the ClientHello
         * so real TLS clients get a proper alert, but give idle TCP
         * connections (telnet, port scanners) only a brief grace
         * period before closing them */
        c->timeout = 2;
    }
    c->rbbuf = xmalloc(32768); c->rbcap = 32768;
    c->scratch = xmalloc(65536); c->scratchcap = 65536;

    unsigned char alert = 40;              /* handshake_failure */
    int rc = -1;

    /* ---- ClientHello ---- */
    unsigned char *ch;
    size_t chlen;
    unsigned char mtype;
    if (hs_read_msg(a, c, &ch, &chlen, &mtype) < 0) goto fail;
    if (mtype != 1 || chlen < 4 + 38) goto fail;

    const unsigned char *body = ch + 4;
    size_t blen = chlen - 4, off = 0;

    /* legacy_version (2) ignored, random (32), legacy_session_id */
    if (blen < 2 + 32 + 1) goto fail;
    off = 2 + 32;
    unsigned sid_len = body[off++];
    if (sid_len > 32 || off + sid_len > blen) goto fail;
    const unsigned char *sid = body + off;
    off += sid_len;
    /* cipher_suites */
    if (off + 2 > blen) goto fail;
    unsigned cs_len = get_u16(body + off); off += 2;
    if (cs_len < 2 || off + cs_len > blen) goto fail;
    off += cs_len;
    /* legacy_compression_methods */
    if (off + 1 > blen) goto fail;
    unsigned cm_len = body[off++];
    if (off + cm_len > blen) goto fail;
    off += cm_len;

    int has_13 = 0, has_x25519 = 0, has_ecdsa = 0;
    unsigned char client_pub[32];
    char sni[256];
    int has_sni = 0;
    sni[0] = 0;
    if (off + 2 <= blen) {
        unsigned ext_len = get_u16(body + off); off += 2;
        if (off + ext_len > blen) goto fail;
        size_t eend = off + ext_len;
        while (off + 4 <= eend) {
            unsigned et = get_u16(body + off);
            unsigned el = get_u16(body + off + 2);
            off += 4;
            if (off + el > eend) goto fail;
            if (et == 43 && el >= 3) {                 /* supported_versions */
                unsigned n = body[off];
                for (unsigned i = 0; i < n && 1 + 2 * (i + 1) <= el; i++)
                    if (get_u16(body + off + 1 + 2 * i) == 0x0304) has_13 = 1;
            } else if (et == 51 && el >= 2) {          /* key_share */
                unsigned kl = get_u16(body + off);
                size_t p = off + 2, kend = p + kl;
                if (kend <= off + el) {
                    while (p + 4 <= kend) {
                        unsigned g = get_u16(body + p);
                        unsigned gl = get_u16(body + p + 2);
                        if (p + 4 + gl > kend) break;
                        if (g == 29 && gl == 32 && !has_x25519) {
                            memcpy(client_pub, body + p + 4, 32);
                            has_x25519 = 1;
                        }
                        p += 4 + gl;
                    }
                }
            } else if (et == 13 && el >= 2) {          /* signature_algorithms */
                unsigned n = get_u16(body + off);
                for (unsigned i = 0; i < n && 2 + 2 * (i + 1) <= el; i++)
                    if (get_u16(body + off + 2 + 2 * i) == 0x0403) has_ecdsa = 1;
            } else if (et == 0 && el >= 5) {           /* server_name (SNI) */
                /* ServerNameList: uint16 length, then one or more entries
                 * (uint8 NameType, uint16 len, name).  We take the first
                 * host_name; the other types are defined to be illegal. */
                unsigned nl = get_u16(body + off);
                size_t p = off + 2, nend = p + nl;
                if (nend <= off + el) {
                    while (p + 3 <= nend) {
                        unsigned nt = body[p];
                        unsigned nn = get_u16(body + p + 1);
                        if (p + 3 + nn > nend) break;
                        if (nt == 0 && nn > 0 && nn < sizeof(sni)) {
                            memcpy(sni, body + p + 3, nn);
                            sni[nn] = 0;
                            has_sni = 1;
                            break;
                        }
                        p += 3 + nn;
                    }
                }
            }
            off += el;
        }
    }
    if (!has_13) { alert = 70; goto fail; }            /* protocol_version */
    if (!has_x25519 || !has_ecdsa) goto fail;

    /* pick the certificate: SNI -> site key, otherwise the default */
    const TlsKey *skey = key;
    if (pick && has_sni) {
        const TlsKey *k = pick(sni, pick_arg);
        if (k) skey = k;
    }
    if (!skey) goto fail;      /* no certificate: handshake_failure alert */
    if (!key) {
        /* a site certificate was found via SNI: restore the normal
         * timeouts for the rest of the handshake */
        c->timeout = timeout > 0 ? timeout : 10;
    }

    /* ---- key schedule: early/handshake secrets ---- */
    Sha256 tr;
    sha256_init(&tr);
    sha256_update(&tr, ch, chlen);

    unsigned char eph[32], eph_pub[32], ecdhe[32];
    if (random_bytes(eph, 32) < 0) goto fail;
    {
        unsigned char base[32] = {9};
        x25519(eph_pub, eph, base);
    }
    x25519(ecdhe, eph, client_pub);

    unsigned char zeros[32] = {0};
    unsigned char early[32], derived[32], hs_secret[32];
    Sha256 tr_empty;                 /* "derived" secrets use empty messages */
    sha256_init(&tr_empty);
    hkdf_extract(early, zeros, 32, zeros, 32);
    derive_secret(derived, early, "derived", &tr_empty);
    hkdf_extract(hs_secret, derived, 32, ecdhe, 32);

    /* ---- ServerHello ---- */
    size_t sh_body = 2 + 32 + 1 + sid_len + 2 + 1 + 2 + 46;
    unsigned char *sh = msg_start(a, 2, sh_body);
    if (!sh) goto fail;
    {
        unsigned char *p = sh + 4;
        put_u16(p, 0x0303); p += 2;                    /* legacy_version */
        if (random_bytes(p, 32) < 0) goto fail;        /* random */
        p += 32;
        *p++ = (unsigned char)sid_len;                 /* echo session id */
        if (sid_len) { memcpy(p, sid, sid_len); p += sid_len; }
        put_u16(p, 0x1301); p += 2;                    /* TLS_AES_128_GCM_SHA256 */
        *p++ = 0;                                      /* null compression */
        put_u16(p, 46); p += 2;                        /* extensions length */
        /* supported_versions = TLS 1.3 (just the selected version) */
        put_u16(p, 43); put_u16(p + 2, 2);
        put_u16(p + 4, 0x0304); p += 6;
        /* key_share = x25519 */
        put_u16(p, 51); put_u16(p + 2, 36);
        put_u16(p + 4, 29); put_u16(p + 6, 32);
        memcpy(p + 8, eph_pub, 32);
    }
    size_t shlen = 4 + sh_body;
    sha256_update(&tr, sh, shlen);

    /* ---- handshake traffic secrets (transcript = ClientHello..ServerHello) ---- */
    unsigned char chs[32], shs[32];
    derive_secret(chs, hs_secret, "c hs traffic", &tr);
    derive_secret(shs, hs_secret, "s hs traffic", &tr);
    expand_label(c->client_hs_key, 16, chs, "key", NULL, 0);
    expand_label(c->server_hs_key, 16, shs, "key", NULL, 0);
    expand_label(c->client_hs_iv, 12, chs, "iv", NULL, 0);
    expand_label(c->server_hs_iv, 12, shs, "iv", NULL, 0);

    /* ---- EncryptedExtensions ---- */
    unsigned char *ee = msg_start(a, 8, 2);
    if (!ee) goto fail;
    put_u16(ee + 4, 0);                /* no extensions */
    size_t eelen = 6;
    sha256_update(&tr, ee, eelen);

    /* ---- Certificate ---- */
    int ncert = skey->n_certs;
    if (ncert <= 0) goto fail;
    size_t listlen = 0;
    for (int i = 0; i < ncert; i++) listlen += 3 + skey->len[i] + 2;
    unsigned char *certmsg = msg_start(a, 11, 1 + 3 + listlen);
    if (!certmsg) goto fail;
    {
        unsigned char *p = certmsg + 4;
        *p++ = 0;                                      /* request context */
        put_u24(p, (unsigned)listlen); p += 3;
        for (int i = 0; i < ncert; i++) {
            put_u24(p, (unsigned)skey->len[i]);
            memcpy(p + 3, skey->der[i], skey->len[i]);
            put_u16(p + 3 + skey->len[i], 0);          /* no entry extensions */
            p += 3 + skey->len[i] + 2;
        }
    }
    size_t certlen = 4 + 1 + 3 + listlen;
    sha256_update(&tr, certmsg, certlen);

    /* ---- CertificateVerify (ECDSA P-256/SHA-256, in-process) ---- */
    unsigned char *cvcontent = arena_alloc(a, 64 + 33 + 1 + 32);
    if (!cvcontent) goto fail;
    memset(cvcontent, 0x20, 64);
    memcpy(cvcontent + 64, "TLS 1.3, server CertificateVerify", 33);
    cvcontent[64 + 33] = 0;
    {
        Sha256 tc = tr;
        sha256_final(&tc, cvcontent + 64 + 33 + 1);
    }
    unsigned char sigbuf[72];
    size_t siglen;
    {
        unsigned char digest[32];
        sha256_one(digest, cvcontent, 64 + 33 + 1 + 32);
        if (ecdsa_sign(sigbuf, &siglen, skey->priv, digest) < 0) goto fail;
    }
    unsigned char *cv = msg_start(a, 15, 2 + 2 + siglen);
    if (!cv) goto fail;
    put_u16(cv + 4, 0x0403);                           /* ecdsa_secp256r1_sha256 */
    put_u16(cv + 6, (unsigned)siglen);
    memcpy(cv + 8, sigbuf, siglen);
    size_t cvlen = 4 + 2 + 2 + siglen;
    sha256_update(&tr, cv, cvlen);

    /* ---- server Finished ---- */
    unsigned char fkey[32], vd[32];
    expand_label(fkey, 32, shs, "finished", NULL, 0);
    {
        Sha256 tc = tr;
        unsigned char hash[32];
        sha256_final(&tc, hash);
        hmac_sha256(vd, fkey, 32, hash, 32);
    }
    unsigned char *fin = msg_start(a, 20, 32);
    if (!fin) goto fail;
    memcpy(fin + 4, vd, 32);
    size_t finlen = 36;
    sha256_update(&tr, fin, finlen);

    /* ---- application traffic secrets ----
     * Derived over the transcript up to and including the server Finished
     * (OpenSSL/NSS behaviour, RFC 8448 worked example). */
    unsigned char d2[32], master[32], caps[32], saps[32];
    derive_secret(d2, hs_secret, "derived", &tr_empty);
    hkdf_extract(master, d2, 32, zeros, 32);
    derive_secret(caps, master, "c ap traffic", &tr);
    derive_secret(saps, master, "s ap traffic", &tr);
    expand_label(c->client_ap_key, 16, caps, "key", NULL, 0);
    expand_label(c->server_ap_key, 16, saps, "key", NULL, 0);
    expand_label(c->client_ap_iv, 12, caps, "iv", NULL, 0);
    expand_label(c->server_ap_iv, 12, saps, "iv", NULL, 0);

    /* ---- send server flight ---- */
    {
        unsigned char hdr[5] = { 22, 3, 3, (unsigned char)(shlen >> 8),
                                 (unsigned char)shlen };
        if (send_raw_all(fd, hdr, 5) < 0 || send_raw_all(fd, sh, shlen) < 0)
            goto fail;
    }
    {
        size_t flight_len = eelen + certlen + cvlen + finlen;
        unsigned char *flight = arena_alloc(a, flight_len + 1);
        if (!flight) goto fail;
        unsigned char *p = flight;
        memcpy(p, ee, eelen); p += eelen;
        memcpy(p, certmsg, certlen); p += certlen;
        memcpy(p, cv, cvlen); p += cvlen;
        memcpy(p, fin, finlen); p += finlen;
        *p = 0x16;                                     /* inner type: handshake */

        size_t ptlen = flight_len + 1, clen = ptlen + 16;
        unsigned char nonce[12];
        tls_nonce(nonce, c->server_hs_iv, 0);
        unsigned char hdr[5] = { 23, 3, 3, (unsigned char)(clen >> 8),
                                 (unsigned char)clen };
        if (clen > c->scratchcap) goto fail;
        gcm_encrypt(c->server_hs_key, nonce, hdr, 5, flight, ptlen,
                    c->scratch + 0, c->scratch + ptlen);
        if (send_raw_all(fd, hdr, 5) < 0 ||
            send_raw_all(fd, c->scratch, clen) < 0)
            goto fail;
    }

    /* ---- client flight: (CCS) + encrypted Finished ---- */
    {
        unsigned char *cmsg;
        size_t cmlen;
        unsigned char cmtype;
        if (hs_read_msg(a, c, &cmsg, &cmlen, &cmtype) < 0) goto fail;
        if (cmtype != 20 || cmlen != 36) goto fail;    /* Finished */

        unsigned char cfkey[32], expect[32];
        expand_label(cfkey, 32, chs, "finished", NULL, 0);
        Sha256 tc = tr;
        unsigned char hash[32];
        sha256_final(&tc, hash);
        hmac_sha256(expect, cfkey, 32, hash, 32);
        if (!ct_eq32(expect, cmsg + 4)) goto fail;
    }

    c->handshake_done = 1;
    c->seq_in = 0;
    rc = 0;

fail:
    if (rc < 0) {
        tls_send_alert(fd, alert);
        tls_close(c);
        return NULL;
    }
    return c;
}

/* =====================================================================
 * public API
 * ===================================================================== */
ssize_t tls_read(TlsConn *c, void *buf, size_t n) {
    unsigned char *out = buf;

    /* serve pushback bytes first */
    if (c->pb_off < c->pb_len) {
        size_t take = c->pb_len - c->pb_off;
        if (take > n) take = n;
        memcpy(out, c->pb + c->pb_off, take);
        c->pb_off += take;
        return (ssize_t)take;
    }

    /* serve already-decrypted plaintext */
    if (c->ptoff < c->ptlen) {
        size_t take = c->ptlen - c->ptoff;
        if (take > n) take = n;
        memcpy(out, c->ptbuf + c->ptoff, take);
        c->ptoff += take;
        return (ssize_t)take;
    }

    /* fetch exactly one record; read() semantics: block until some data
     * or an error, then return what is available (may be less than n) */
    for (;;) {
        c->ptoff = c->ptlen = 0;
        unsigned char ctype;
        int clen = tls_next_record(c, c->scratch, c->scratchcap, &ctype);
        if (clen < 0) return -1;
        if (ctype == 21) return -1;                    /* close_notify / alert */
        if (ctype != 23) continue;                     /* no tickets: ignore */
        if ((size_t)clen > c->ptcap) {
            size_t ncap = c->ptcap ? c->ptcap : 8192;
            while (ncap < (size_t)clen) ncap *= 2;
            unsigned char *nb = realloc(c->ptbuf, ncap);
            if (!nb) die_oom();
            c->ptbuf = nb;
            c->ptcap = ncap;
        }
        memcpy(c->ptbuf, c->scratch, (size_t)clen);
        c->ptlen = (size_t)clen;
        size_t take = c->ptlen;
        if (take > n) take = n;
        memcpy(out, c->ptbuf, take);
        c->ptoff = take;
        return (ssize_t)take;
    }
}

ssize_t tls_write(TlsConn *c, const void *buf, size_t n) {
    if (n == 0) return 0;
    if (!c->handshake_done) return -1;
    const unsigned char *p = buf;
    while (n > 0) {
        size_t chunk = n > TLS_MAX_PLAINTEXT ? TLS_MAX_PLAINTEXT : n;
        size_t ptlen = chunk + 1;                      /* + inner type */
        size_t clen = ptlen + 16;
        if (clen > c->scratchcap) return -1;
        memcpy(c->scratch, p, chunk);
        c->scratch[chunk] = 0x17;                      /* application_data */
        unsigned char hdr[5] = { 23, 3, 3, (unsigned char)(clen >> 8),
                                 (unsigned char)clen };
        unsigned char nonce[12];
        tls_nonce(nonce, c->server_ap_iv, c->seq_out++);
        gcm_encrypt(c->server_ap_key, nonce, hdr, 5, c->scratch, ptlen,
                    c->scratch, c->scratch + ptlen);
        if (send_raw_all(c->fd, hdr, 5) < 0 ||
            send_raw_all(c->fd, c->scratch, clen) < 0)
            return -1;
        p += chunk;
        n -= chunk;
    }
    return (ssize_t)(p - (const unsigned char *)buf);
}

int tls_pending(TlsConn *c) {
    /* pushback, decrypted plaintext ready, or raw bytes to decrypt */
    return c->pb_off < c->pb_len ||
           c->ptoff < c->ptlen ||
           c->rbpos < c->rblen;
}

/* Return bytes to the connection's stream: they are served by the next
 * tls_read() before anything else.  Used for pipelined data that was
 * over-read beyond an HTTP request. */
void tls_unread(TlsConn *c, const void *data, size_t n) {
    if (n == 0) return;
    size_t keep = c->pb_len - c->pb_off;
    if (c->pb_off) {
        memmove(c->pb, c->pb + c->pb_off, keep);
        c->pb_off = 0;
        c->pb_len = keep;
    }
    if (keep + n > c->pb_cap) {
        size_t ncap = c->pb_cap ? c->pb_cap : 256;
        while (ncap < keep + n) ncap *= 2;
        unsigned char *nb = realloc(c->pb, ncap);
        if (!nb) die_oom();
        c->pb = nb;
        c->pb_cap = ncap;
    }
    memcpy(c->pb + keep, data, n);
    c->pb_len = keep + n;
}

void tls_close(TlsConn *c) {
    if (!c) return;
    if (c->handshake_done) {
        /* best-effort close_notify */
        unsigned char pt[3] = { 1, 0, 0x15 };      /* warning, close_notify */
        size_t clen = 3 + 16;
        unsigned char hdr[5] = { 23, 3, 3, 0, (unsigned char)clen };
        unsigned char nonce[12];
        tls_nonce(nonce, c->server_ap_iv, c->seq_out++);
        gcm_encrypt(c->server_ap_key, nonce, hdr, 5, pt, 3,
                    c->scratch, c->scratch + 3);
        ssize_t ignored;
        ignored = send_raw_all(c->fd, hdr, 5);
        ignored = send_raw_all(c->fd, c->scratch, clen);
        (void)ignored;
    }
    free(c->rbbuf);
    free(c->pb);
    free(c->ptbuf);
    free(c->scratch);
    free(c);
}
