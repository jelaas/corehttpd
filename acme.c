/* acme.c — Let's Encrypt ACME v2 client (HTTP-01), companion to corehttpd.
 *
 * Issues one certificate per site using Let's Encrypt's ACME protocol
 * (RFC 8555) with HTTP-01 verification, and installs the certificate
 * and private key at the paths configured in corehttpd's config file
 * (site cert_file/key_file).  The challenge file is written into the
 * configured letsencrypt_root, where corehttpd serves it under
 * /.well-known/acme-challenge/.
 *
 * HTTPS communication with the ACME server is delegated to the curl
 * program (curl must be installed).  Everything else — account key
 * generation, ES256 JWS signatures, the CSR — is done in-process:
 * SHA-256, HMAC-SHA256 and ECDSA P-256 (RFC 6979) here are verbatim
 * mirrors of the implementations in tls.c, validated by the same test
 * vectors.
 *
 * The ACME flow (RFC 8555):
 *   directory -> newAccount (jwk) -> newOrder (kid) -> authorizations
 *   (HTTP-01 token) -> write challenge file -> self-check -> respond to
 *   challenge -> poll authorization -> finalize (CSR) -> poll order ->
 *   download certificate chain.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *prog = "corehttpd-acme";

static void die(const char *fmt, ...) {
    fprintf(stderr, "%s: ", prog);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) die("out of memory");
    return p;
}

static char *xstrdup(const char *s) {
    char *p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

/* =====================================================================
 * SHA-256 (mirror of tls.c)
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
 * HMAC-SHA256 (mirror of tls.c)
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
 * 256-bit modular arithmetic (mirror of tls.c)
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
 * P-256 (secp256r1) — Jacobian coordinates (mirror of tls.c)
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
 * ECDSA P-256, deterministic nonce (RFC 6979) — mirror of tls.c
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

/* ECDSA-P256-SHA256; writes the raw r||s signature (64 bytes) */
static int ecdsa_sign_raw(unsigned char sig64[64],
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

        m256_to_be(sig64, &r);
        m256_to_be(sig64 + 32, &s);
        return 0;
    }
    return -1;
}

/* DER SEQUENCE { INTEGER r, INTEGER s } (<= 72 bytes) */
static size_t ecdsa_sign_der(unsigned char out[72],
                             const unsigned char d[32],
                             const unsigned char digest[32]) {
    unsigned char raw[64];
    if (ecdsa_sign_raw(raw, d, digest) < 0) return 0;
    M256 r, s;
    m256_from_be(&r, raw);
    m256_from_be(&s, raw + 32);
    unsigned char rbuf[64], sbuf[64];
    size_t rl = 0, sl = 0;
    {
        unsigned char b[32];
        size_t i = 0;
        m256_to_be(b, &r);
        while (i < 31 && b[i] == 0) i++;
        if (b[i] & 0x80) rbuf[rl++] = 0;
        memcpy(rbuf + rl, b + i, 32 - i);
        rl += 32 - i;
    }
    {
        unsigned char b[32];
        size_t i = 0;
        m256_to_be(b, &s);
        while (i < 31 && b[i] == 0) i++;
        if (b[i] & 0x80) sbuf[sl++] = 0;
        memcpy(sbuf + sl, b + i, 32 - i);
        sl += 32 - i;
    }
    size_t total = 2 + rl + 2 + sl;
    out[0] = 0x30;
    out[1] = (unsigned char)total;
    out[2] = 0x02;
    out[3] = (unsigned char)rl;
    memcpy(out + 4, rbuf, rl);
    out[4 + rl] = 0x02;
    out[5 + rl] = (unsigned char)sl;
    memcpy(out + 6 + rl, sbuf, sl);
    return 6 + rl + sl;
}

/* =====================================================================
 * key generation
 * ===================================================================== */
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

/* fresh P-256 keypair; priv in [1, n-1], X/Y = public point */
static int keygen(unsigned char priv[32], unsigned char X[32],
                  unsigned char Y[32]) {
    for (int i = 0; i < 10; i++) {
        if (random_bytes(priv, 32) < 0) return -1;
        M256 d;
        m256_from_be(&d, priv);
        if (m256_is_zero(&d) || m256_cmp(&d, &N256_MOD) >= 0) continue;
        PPoint pub;
        ppoint_mul(&pub, &d, ppoint_base());
        M256 ax, ay;
        if (ppoint_affine(&ax, &ay, &pub) < 0) continue;
        m256_to_be(X, &ax);
        m256_to_be(Y, &ay);
        return 0;
    }
    return -1;
}

/* public point for a private scalar (returns 0, or -1 if invalid) */
static int pub_from_priv(unsigned char X[32], unsigned char Y[32],
                         const unsigned char priv[32]) {
    M256 d;
    m256_from_be(&d, priv);
    if (m256_is_zero(&d) || m256_cmp(&d, &N256_MOD) >= 0) return -1;
    PPoint pub;
    ppoint_mul(&pub, &d, ppoint_base());
    M256 ax, ay;
    if (ppoint_affine(&ax, &ay, &pub) < 0) return -1;
    m256_to_be(X, &ax);
    m256_to_be(Y, &ay);
    return 0;
}

/* =====================================================================
 * base64
 * ===================================================================== */
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
        if (*p == '=' || *p == '\r' || *p == '\n' || *p == ' ' || *p == '\t')
            continue;
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

/* base64url, no padding; returns length excluding NUL, SIZE_MAX on
 * overflow (0 is a valid length: the empty string) */
static size_t b64url_encode(char *out, size_t outcap,
                            const unsigned char *in, size_t n) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = 0;
        size_t left = n - i;
        v |= (uint32_t)in[i] << 16;
        if (left > 1) v |= (uint32_t)in[i + 1] << 8;
        if (left > 2) v |= (uint32_t)in[i + 2];
        size_t cnt = left >= 3 ? 4 : (left == 2 ? 3 : 2);
        if (o + cnt + 1 > outcap) return SIZE_MAX;
        out[o++] = tab[(v >> 18) & 63];
        out[o++] = tab[(v >> 12) & 63];
        if (cnt > 2) out[o++] = tab[(v >> 6) & 63];
        if (cnt > 3) out[o++] = tab[v & 63];
    }
    out[o] = 0;
    return o;
}

/* standard base64 with padding, wrapped at 64 columns */
static char *b64_pem(const unsigned char *in, size_t n) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t outcap = ((n + 2) / 3) * 4 + ((n + 2) / 3) / 16 + 32;
    char *out = xmalloc(outcap);
    size_t o = 0, col = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = 0;
        size_t left = n - i;
        v |= (uint32_t)in[i] << 16;
        if (left > 1) v |= (uint32_t)in[i + 1] << 8;
        if (left > 2) v |= (uint32_t)in[i + 2];
        out[o++] = tab[(v >> 18) & 63];
        out[o++] = tab[(v >> 12) & 63];
        out[o++] = left > 1 ? tab[(v >> 6) & 63] : '=';
        out[o++] = left > 2 ? tab[v & 63] : '=';
        col += 4;
        if (col == 64) { out[o++] = '\n'; col = 0; }
    }
    if (col) out[o++] = '\n';
    out[o] = 0;
    return out;
}

/* =====================================================================
 * ASN.1 / DER building (SEC1 key + PKCS#10 CSR)
 * ===================================================================== */
typedef struct { unsigned char *p; size_t n, cap; } DerBuf;

static int derb_grow(DerBuf *b, size_t extra) {
    if (b->n + extra > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 256;
        while (ncap < b->n + extra) ncap *= 2;
        unsigned char *np = realloc(b->p, ncap);
        if (!np) return -1;
        b->p = np;
        b->cap = ncap;
    }
    return 0;
}

static size_t der_len_bytes(size_t n, unsigned char out[5]) {
    if (n < 0x80) { out[0] = (unsigned char)n; return 1; }
    int nb = 0;
    for (size_t t = n; t; t >>= 8) nb++;
    out[0] = (unsigned char)(0x80 | nb);
    for (int i = 0; i < nb; i++)
        out[1 + i] = (unsigned char)(n >> (8 * (nb - 1 - i)));
    return (size_t)nb + 1;
}

/* append raw bytes */
static int derb_bytes(DerBuf *b, const void *v, size_t n) {
    if (derb_grow(b, n) < 0) return -1;
    if (n) {
        memcpy(b->p + b->n, v, n);
        b->n += n;
    }
    return 0;
}

/* append tag + length + value */
static int derb_tlv(DerBuf *b, unsigned char tag,
                    const void *v, size_t n) {
    unsigned char lb[5];
    size_t ll = der_len_bytes(n, lb);
    if (derb_grow(b, 1 + ll + n) < 0) return -1;
    b->p[b->n++] = tag;
    memcpy(b->p + b->n, lb, ll);
    b->n += ll;
    if (n) {
        memcpy(b->p + b->n, v, n);
        b->n += n;
    }
    return 0;
}

/* SEC1 ECPrivateKey DER for P-256 */
static size_t sec1_der(unsigned char *out, size_t outcap,
                       const unsigned char priv[32],
                       const unsigned char X[32], const unsigned char Y[32]) {
    static const unsigned char oid_p256[] = {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    };
    DerBuf body = {0};
    unsigned char one = 1;
    if (derb_tlv(&body, 0x02, &one, 1) < 0) { free(body.p); return 0; }
    if (derb_tlv(&body, 0x04, priv, 32) < 0) { free(body.p); return 0; }
    DerBuf params = {0};
    if (derb_tlv(&params, 0x06, oid_p256, sizeof oid_p256) < 0 ||
        derb_tlv(&body, 0xa0, params.p, params.n) < 0) {
        free(body.p); free(params.p); return 0;
    }
    /* [1] publicKey: a BIT STRING wrapping the uncompressed point */
    unsigned char bitstr[66] = { 0, 4 };           /* unused bits + 0x04 X Y */
    memcpy(bitstr + 2, X, 32);
    memcpy(bitstr + 34, Y, 32);
    DerBuf pk = {0};
    if (derb_tlv(&pk, 0x03, bitstr, sizeof bitstr) < 0 ||
        derb_tlv(&body, 0xa1, pk.p, pk.n) < 0) {
        free(body.p); free(params.p); free(pk.p); return 0;
    }
    free(params.p);
    free(pk.p);

    DerBuf b = {0};
    if (derb_tlv(&b, 0x30, body.p, body.n) < 0) {
        free(body.p); free(b.p); return 0;
    }
    free(body.p);
    if (b.n > outcap) { free(b.p); return 0; }
    memcpy(out, b.p, b.n);
    size_t n = b.n;
    free(b.p);
    return n;
}

/* build a PKCS#10 CSR (DER) for cn with the given P-256 keypair */
static size_t build_csr(unsigned char *out, size_t outcap, const char *cn,
                        const unsigned char priv[32]) {
    unsigned char X[32], Y[32];
    if (pub_from_priv(X, Y, priv) < 0) return 0;

    static const unsigned char oid_cn[] = { 0x55, 0x04, 0x03 };
    static const unsigned char oid_ecpub[] = {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    };
    static const unsigned char oid_p256[] = {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    };
    static const unsigned char oid_sig[] = {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    };

    DerBuf info_body = {0};
    {   /* version INTEGER 0 */
        unsigned char v = 0;
        if (derb_tlv(&info_body, 0x02, &v, 1) < 0) { free(info_body.p); return 0; }
    }
    {   /* subject: SEQ { SET { SEQ { OID CN, UTF8String cn } } } */
        DerBuf cnv = {0}, set = {0}, seq = {0};
        if (derb_tlv(&cnv, 0x06, oid_cn, sizeof oid_cn) < 0 ||
            derb_tlv(&cnv, 0x0c, cn, strlen(cn)) < 0 ||
            derb_tlv(&set, 0x30, cnv.p, cnv.n) < 0 ||
            derb_tlv(&seq, 0x31, set.p, set.n) < 0 ||
            derb_tlv(&info_body, 0x30, seq.p, seq.n) < 0) {
            free(cnv.p); free(set.p); free(seq.p); free(info_body.p);
            return 0;
        }
        free(cnv.p); free(set.p); free(seq.p);
    }
    {   /* SPKI: SEQ { SEQ { OID ecpub, OID p256 }, BIT STRING 00 04 X Y } */
        DerBuf alg = {0}, spki = {0};
        unsigned char pk[66] = { 0, 4 };
        memcpy(pk + 2, X, 32);
        memcpy(pk + 34, Y, 32);
        if (derb_tlv(&alg, 0x06, oid_ecpub, sizeof oid_ecpub) < 0 ||
            derb_tlv(&alg, 0x06, oid_p256, sizeof oid_p256) < 0 ||
            derb_tlv(&spki, 0x30, alg.p, alg.n) < 0 ||
            derb_tlv(&spki, 0x03, pk, sizeof pk) < 0 ||
            derb_tlv(&info_body, 0x30, spki.p, spki.n) < 0) {
            free(alg.p); free(spki.p); free(info_body.p);
            return 0;
        }
        free(alg.p); free(spki.p);
    }
    {   /* attributes [0] IMPLICIT, empty */
        if (derb_tlv(&info_body, 0xa0, NULL, 0) < 0) {
            free(info_body.p);
            return 0;
        }
    }

    /* CertificationRequestInfo = SEQ { version, subject, SPKI, attrs } */
    DerBuf info = {0};
    if (derb_tlv(&info, 0x30, info_body.p, info_body.n) < 0) {
        free(info_body.p); free(info.p);
        return 0;
    }
    free(info_body.p);

    /* signature over DER(CertificationRequestInfo) */
    unsigned char digest[32];
    sha256_one(digest, info.p, info.n);
    unsigned char sigder[72];
    size_t siglen = ecdsa_sign_der(sigder, priv, digest);
    if (!siglen) { free(info.p); return 0; }

    DerBuf body = {0};
    DerBuf alg2 = {0};
    unsigned char bs[73];
    bs[0] = 0;                                     /* unused bits */
    memcpy(bs + 1, sigder, siglen);
    /* the children of CertificationRequest: the req_info TLV as-is,
     * the signature algorithm, and the signature BIT STRING */
    if (derb_bytes(&body, info.p, info.n) < 0 ||
        derb_tlv(&alg2, 0x06, oid_sig, sizeof oid_sig) < 0 ||
        derb_tlv(&body, 0x30, alg2.p, alg2.n) < 0 ||
        derb_tlv(&body, 0x03, bs, siglen + 1) < 0) {
        free(info.p); free(alg2.p); free(body.p);
        return 0;
    }
    free(info.p); free(alg2.p);

    /* CertificationRequest = SEQ { info, sigalg, signature } */
    DerBuf csr = {0};
    if (derb_tlv(&csr, 0x30, body.p, body.n) < 0) {
        free(body.p); free(csr.p);
        return 0;
    }
    free(body.p);
    if (csr.n > outcap) { free(csr.p); return 0; }
    memcpy(out, csr.p, csr.n);
    size_t n = csr.n;
    free(csr.p);
    return n;
}

/* =====================================================================
 * key/cert parsing
 * ===================================================================== */
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

/* return pointer to the content of the TLV at p (after tag + length) */
static const unsigned char *der_enter(const unsigned char *p,
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
    return p;
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

/* decode one PEM block with the given BEGIN label into der */
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
    /* decode only the base64 between the markers (b64_decode reads a
     * NUL-terminated string) */
    char saved = ((char *)e)[0];
    ((char *)e)[0] = 0;
    size_t cap2 = (size_t)(e - p) / 4 * 3 + 3;
    if (cap2 > dermax) { ((char *)e)[0] = saved; return -1; }
    int dl = b64_decode(p, der, cap2);
    ((char *)e)[0] = saved;
    if (dl <= 0) return -1;
    *derlen = (size_t)dl;
    return 0;
}

/* load an EC private key (SEC1 or PKCS#8, PEM or DER) into priv[32] */
static int load_ec_key(const char *path, unsigned char priv[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    if (n == 0 || n == sizeof buf - 1) return -1;
    buf[n] = 0;

    unsigned char der[4096];
    size_t derlen = 0;
    if (buf[0] == 0x30) {
        if (n > sizeof der) return -1;
        memcpy(der, buf, n);
        derlen = n;
    } else if (pem_get_block((char *)buf, "EC PRIVATE KEY",
                             der, &derlen, sizeof der) < 0 &&
               pem_get_block((char *)buf, "PRIVATE KEY",
                             der, &derlen, sizeof der) < 0) {
        return -1;
    }
    if (!has_oid_prime256(der, derlen)) return -1;
    if (der_scalar_in(der, der + derlen, priv) < 0) return -1;
    return 0;
}

/* days from civil date (Gregorian); 1970-01-01 == 0 */
static long days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (unsigned)((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1);
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (long)era * 146097 + (long)doe - 719468;
}

/* parse an ASN.1 UTCTime/GeneralizedTime TLV at p; days since epoch */
static long asn1_time_days(const unsigned char *p, const unsigned char *end) {
    if (p >= end) return -1;
    int tag = *p++;
    if (p >= end) return -1;
    size_t len = *p++;
    if (len & 0x80) return -1;
    if (p + len > end) return -1;
    int y, mo, d;
    if (tag == 0x17 && len == 13) {                /* UTCTime YYMMDDhhmmssZ */
        y = (p[0]-'0')*10 + (p[1]-'0');
        y += y >= 50 ? 1900 : 2000;
        mo = (p[2]-'0')*10 + (p[3]-'0');
        d  = (p[4]-'0')*10 + (p[5]-'0');
    } else if (tag == 0x18 && len == 15) {         /* GeneralizedTime */
        y  = (p[0]-'0')*1000 + (p[1]-'0')*100 + (p[2]-'0')*10 + (p[3]-'0');
        mo = (p[4]-'0')*10 + (p[5]-'0');
        d  = (p[6]-'0')*10 + (p[7]-'0');
    } else {
        return -1;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return -1;
    return days_from_civil(y, mo, d);
}

/* days until the first certificate in the PEM file expires; -1 on error */
static long cert_days_left(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    if (n == 0 || n == sizeof buf - 1) return -1;
    buf[n] = 0;

    static const char BEG[] = "-----BEGIN CERTIFICATE-----";
    static const char END[] = "-----END CERTIFICATE-----";
    char *p = strstr((char *)buf, BEG);
    if (!p) return -1;
    p += sizeof BEG - 1;
    char *e = strstr(p, END);
    if (!e) return -1;
    *e = 0;                                        /* b64_decode reads to NUL */

    unsigned char der[8192];
    int dl = b64_decode(p, der, sizeof der);
    if (dl <= 0) return -1;
    const unsigned char *end = der + dl;

    /* Certificate -> TBS content: enter the Certificate SEQ, then enter
     * the TBSCertificate SEQ inside it */
    const unsigned char *q = der_enter(der, end);
    if (!q) return -1;
    const unsigned char *c = der_enter(q, end);
    if (!c) return -1;
    if (c < end && *c == 0xa0) {                   /* optional [0] version */
        c = der_next(c, end);
        if (!c) return -1;
    }
    c = der_next(c, end);                          /* serialNumber */
    if (!c) return -1;
    c = der_next(c, end);                          /* signature alg */
    if (!c) return -1;
    c = der_next(c, end);                          /* issuer */
    if (!c) return -1;

    /* validity SEQ { notBefore, notAfter } */
    if (c >= end || *c != 0x30) return -1;
    c = der_enter(c, end);                         /* validity content */
    if (!c) return -1;
    c = der_next(c, end);                          /* skip notBefore */
    if (!c) return -1;
    /* c points at the notAfter TLV */
    long na = asn1_time_days(c, end);
    if (na < 0) return -1;
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    long today = days_from_civil(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return na - today;
}

/* =====================================================================
 * JSON helpers
 * ===================================================================== */
/* strip JSONC comments, preserving strings (malloc'd) */
static char *strip_jsonc(const char *s) {
    size_t n = strlen(s);
    char *out = xmalloc(n + 1);
    size_t o = 0, i = 0;
    while (i < n) {
        if (s[i] == '"') {
            out[o++] = s[i++];
            while (i < n && s[i] != '"') {
                if (s[i] == '\\' && i + 1 < n) out[o++] = s[i++];
                out[o++] = s[i++];
            }
            if (i < n) out[o++] = s[i++];
        } else if (s[i] == '/' && i + 1 < n && s[i+1] == '/') {
            i += 2;
            while (i < n && s[i] != '\n') i++;
        } else if (s[i] == '/' && i + 1 < n && s[i+1] == '*') {
            i += 2;
            while (i + 1 < n && !(s[i] == '*' && s[i+1] == '/')) i++;
            if (i + 1 < n) i += 2;
        } else {
            out[o++] = s[i++];
        }
    }
    out[o] = 0;
    return out;
}

static const char *j_str(json_t *o, const char *k) {
    json_t *v = o ? json_object_get(o, k) : NULL;
    return json_is_string(v) ? json_string_value(v) : NULL;
}

/* =====================================================================
 * HTTP via the curl program
 * ===================================================================== */
#define MAX_HTTP_BODY (1 << 20)

typedef struct {
    int status;
    char *hdr;      /* full header block, NUL-terminated */
    char *body;     /* response body, NUL-terminated */
    size_t bodylen;
    char err[4096]; /* curl's stderr (diagnostics), NUL-terminated */
} HttpResp;

static void http_resp_free(HttpResp *r) {
    free(r->hdr);
    free(r->body);
    memset(r, 0, sizeof(*r));
}

/* case-insensitive header lookup inside r->hdr; value pointer or NULL.
 * The pointer stays valid until the next hdr_get call. */
static const char *hdr_get(const char *hdr, const char *name) {
    static char buf[1024];
    size_t nl = strlen(name);
    const char *p = hdr;
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        if (!eol) eol = p + strlen(p);
        if ((size_t)(eol - p) > nl + 1 && !strncasecmp(p, name, nl) &&
            p[nl] == ':') {
            const char *v = p + nl + 1;
            while (*v == ' ' || *v == '\t') v++;
            size_t l = (size_t)(eol - v);
            if (l >= sizeof buf) l = sizeof buf - 1;
            memcpy(buf, v, l);
            buf[l] = 0;
            return buf;
        }
        p = *eol ? eol + 2 : eol;
    }
    return NULL;
}

/* one curl invocation.  post = NULL for GET; head = send HEAD.
 * Returns 0 and fills r on HTTP-level success (status parsed), -1 when
 * curl itself failed. */
static int http_req(HttpResp *r, const char *url, const char *post,
                    const char *accept, int head) {
    memset(r, 0, sizeof(*r));
    r->status = -1;
    int outp[2], errp[2];
    if (pipe(outp) < 0 || pipe(errp) < 0) return -1;
    int inp[2];
    if (post && pipe(inp) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(outp[1], 1);
        dup2(errp[1], 2);
        close(outp[0]); close(outp[1]);
        close(errp[0]); close(errp[1]);
        if (post) {
            dup2(inp[0], 0);
            close(inp[0]); close(inp[1]);
        }

        char *args[32];
        int na = 0;
        char acc[96];
        args[na++] = "curl";
        args[na++] = "-sS";
        args[na++] = "-D";
        args[na++] = "-";
        if (head) {
            args[na++] = "-I";
            args[na++] = "-o";
            args[na++] = "/dev/null";
        } else {
            args[na++] = "-o";
            args[na++] = "-";
        }
        if (post) {
            args[na++] = "-H";
            args[na++] = "Content-Type: application/jose+json";
            args[na++] = "--data-binary";
            args[na++] = "@-";
        }
        snprintf(acc, sizeof acc, "Accept: %s",
                 accept ? accept : (post ? "application/json" : "*/*"));
        args[na++] = "-H";
        args[na++] = acc;
        args[na++] = (char *)url;
        args[na] = NULL;
        execvp("curl", args);
        fprintf(stderr, "cannot run curl: %s\n", strerror(errno));
        _exit(127);
    }

    close(outp[1]);
    close(errp[1]);
    if (post) {
        close(inp[0]);
        size_t plen = strlen(post);
        const char *pp = post;
        while (plen) {
            ssize_t w = write(inp[1], pp, plen);
            if (w < 0) { if (errno == EINTR) continue; break; }
            pp += w;
            plen -= (size_t)w;
        }
        close(inp[1]);
    }

    /* read curl's output: the header block, then the body */
    r->hdr = xmalloc(65536);
    size_t hdrlen = 0, bodylen = 0;
    int in_body = 0, overflow = 0;
    {
        char buf[65536];
        for (;;) {
            ssize_t n = read(outp[0], buf, sizeof buf);
            if (n <= 0) break;
            for (ssize_t i = 0; i < n; i++) {
                if (!in_body) {
                    if (hdrlen < 65535) r->hdr[hdrlen++] = buf[i];
                    if (hdrlen >= 4 &&
                        !memcmp(r->hdr + hdrlen - 4, "\r\n\r\n", 4)) {
                        r->hdr[hdrlen] = 0;
                        in_body = 1;
                    } else if (hdrlen == 65535) {
                        r->hdr[hdrlen] = 0;
                        in_body = 1;               /* no header end found */
                    }
                } else if (!overflow) {
                    if (bodylen < MAX_HTTP_BODY - 1) {
                        if (!r->body) r->body = xmalloc(MAX_HTTP_BODY);
                        r->body[bodylen++] = buf[i];
                    } else {
                        overflow = 1;
                    }
                }
            }
        }
    }
    if (!r->body) r->body = xmalloc(1);
    r->body[bodylen] = 0;
    r->bodylen = bodylen;

    /* capture curl's stderr so failures can be explained */
    {
        char ebuf[4096];
        size_t elen = 0;
        for (;;) {
            ssize_t n = read(errp[0], ebuf, sizeof ebuf);
            if (n <= 0) break;
            for (ssize_t i = 0; i < n && elen < sizeof r->err - 1; i++)
                r->err[elen++] = ebuf[i];
        }
        r->err[elen] = 0;
    }
    close(outp[0]);
    close(errp[0]);

    int st;
    if (waitpid(pid, &st, 0) != pid) return -1;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        /* curl failed (no -f, so HTTP errors still exit 0) */
        return -1;
    }

    /* status from the first header line */
    const char *hp = strstr(r->hdr, "HTTP/");
    if (hp) {
        const char *sp = strchr(hp, ' ');
        if (sp) {
            char *end;
            long code = strtol(sp + 1, &end, 10);
            if (end != sp + 1) r->status = (int)code;
        }
    }
    return 0;
}

/* =====================================================================
 * corehttpd configuration (the bits the ACME tool needs)
 * ===================================================================== */
typedef struct {
    const char *name;
    const char *cert_file, *key_file;
} AcmeSite;

typedef struct {
    const char *letsencrypt_root;
    const char *acme_account_key;   /* NULL = default location */
    const char *acme_url;           /* NULL = Let's Encrypt */
    AcmeSite *sites;
    int n_sites;
} AcmeCfg;

static AcmeCfg *read_cfg(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) die("%s: %s", path, strerror(errno));
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > (1 << 20)) die("%s: config file too large", path);
    char *raw = xmalloc((size_t)sz + 1);
    if (fread(raw, 1, (size_t)sz, f) != (size_t)sz)
        die("%s: short read", path);
    raw[sz] = 0;
    fclose(f);

    char *js = strip_jsonc(raw);
    free(raw);
    json_error_t err;
    json_t *root = json_loads(js, 0, &err);
    free(js);
    if (!root) die("%s: %s", path, err.text);

    AcmeCfg *c = xmalloc(sizeof(*c));
    c->letsencrypt_root = xstrdup(j_str(root, "letsencrypt_root")
                                  ? j_str(root, "letsencrypt_root")
                                  : "/var/www/letsencrypt");
    c->acme_account_key = j_str(root, "acme_account_key")
                            ? xstrdup(j_str(root, "acme_account_key"))
                            : NULL;
    c->acme_url = j_str(root, "acme_url")
                    ? xstrdup(j_str(root, "acme_url"))
                    : NULL;

    json_t *sites = json_object_get(root, "sites");
    c->n_sites = 0;
    c->sites = NULL;
    if (json_is_array(sites)) {
        size_t n = json_array_size(sites);
        c->sites = xmalloc(sizeof(AcmeSite) * (n ? n : 1));
        for (size_t i = 0; i < n; i++) {
            json_t *s = json_array_get(sites, i);
            const char *nm = j_str(s, "name");
            const char *cf = j_str(s, "cert_file");
            const char *kf = j_str(s, "key_file");
            if (!nm) continue;
            AcmeSite *as = &c->sites[c->n_sites];
            as->name = xstrdup(nm);
            as->cert_file = cf ? xstrdup(cf) : NULL;
            as->key_file = kf ? xstrdup(kf) : NULL;
            c->n_sites++;
        }
    }
    json_decref(root);
    return c;
}

/* =====================================================================
 * ACME client
 * ===================================================================== */
typedef struct {
    char nonce_url[512], new_account[512], new_order[512];
    char *kid;                     /* account URL from newAccount */
    unsigned char acct_priv[32];
    char jwk_x[48], jwk_y[48];     /* base64url public coordinates */
    char thumbprint[48];           /* RFC 7638 JWK thumbprint */
} Acme;

/* fetch the directory and remember the endpoint URLs */
static void acme_init(Acme *a, const char *directory) {
    HttpResp r;
    if (http_req(&r, directory, NULL, NULL, 0) < 0)
        die("cannot fetch directory %s: curl failed%s%s",
            directory, r.err[0] ? ": " : "", r.err);
    if (r.status != 200)
        die("cannot fetch directory %s (status %d)", directory, r.status);
    json_error_t err;
    json_t *d = json_loads(r.body, 0, &err);
    if (!d) die("directory: bad JSON: %s", err.text);
    const char *nn = j_str(d, "newNonce");
    const char *na = j_str(d, "newAccount");
    const char *no = j_str(d, "newOrder");
    if (!nn || !na || !no) die("directory: missing newNonce/newAccount/newOrder");
    snprintf(a->nonce_url, sizeof a->nonce_url, "%s", nn);
    snprintf(a->new_account, sizeof a->new_account, "%s", na);
    snprintf(a->new_order, sizeof a->new_order, "%s", no);
    json_decref(d);
    http_resp_free(&r);
}

/* fetch a fresh replay nonce */
static void acme_nonce(Acme *a, char nonce[512]) {
    HttpResp r;
    if (http_req(&r, a->nonce_url, NULL, NULL, 1) < 0)
        die("cannot fetch nonce: curl failed%s%s",
            r.err[0] ? ": " : "", r.err);
    if (r.status < 200 || r.status >= 300)
        die("cannot fetch nonce (status %d)", r.status);
    const char *v = hdr_get(r.hdr, "Replay-Nonce");
    if (!v) die("no Replay-Nonce in response");
    snprintf(nonce, 512, "%s", v);
    http_resp_free(&r);
}

/* sign the JWS signing input with the account key */
static char *jws_sign(const Acme *a, const char *p64, const char *pay64) {
    char signing[8192];
    int si = snprintf(signing, sizeof signing, "%s.%s", p64, pay64);
    if (si < 0 || (size_t)si >= sizeof signing)
        die("signing input too large");
    unsigned char digest[32];
    sha256_one(digest, signing, (size_t)si);
    unsigned char raw[64];
    if (ecdsa_sign_raw(raw, a->acct_priv, digest) < 0)
        die("ECDSA signing failed");
    char *s64 = xmalloc(128);
    b64url_encode(s64, 128, raw, 64);
    return s64;
}

/* build + POST one signed request; returns the malloc'd body (caller
 * frees).  When loc_out is given, the Location header of the final
 * response is returned there.  Retries on badNonce. */
static char *jws_post(Acme *a, const char *url, const char *payload,
                      int use_kid, const char *accept, char **loc_out) {
    char *result = NULL;
    for (int attempt = 0; attempt < 5; attempt++) {
        char nonce[512];
        acme_nonce(a, nonce);

        json_t *prot = json_object();
        json_object_set_new(prot, "alg", json_string("ES256"));
        json_object_set_new(prot, "nonce", json_string(nonce));
        json_object_set_new(prot, "url", json_string(url));
        if (use_kid) {
            json_object_set_new(prot, "kid", json_string(a->kid));
        } else {
            json_t *jwk = json_object();
            json_object_set_new(jwk, "crv", json_string("P-256"));
            json_object_set_new(jwk, "kty", json_string("EC"));
            json_object_set_new(jwk, "x", json_string(a->jwk_x));
            json_object_set_new(jwk, "y", json_string(a->jwk_y));
            json_object_set_new(prot, "jwk", jwk);
        }
        char *protstr = json_dumps(prot, JSON_COMPACT);
        json_decref(prot);
        if (!protstr) die("json_dumps failed");

        char p64[1024];
        if (b64url_encode(p64, sizeof p64,
                          (unsigned char *)protstr, strlen(protstr)) == SIZE_MAX)
            die("protected header too large");
        char pay64[8192];
        if (b64url_encode(pay64, sizeof pay64,
                          (unsigned char *)payload, strlen(payload)) == SIZE_MAX)
            die("payload too large (%zu bytes)", strlen(payload));
        char *s64 = jws_sign(a, p64, pay64);
        free(protstr);

        json_t *body = json_pack("{s:s,s:s,s:s}", "protected", p64,
                                 "payload", pay64, "signature", s64);
        free(s64);
        char *bodystr = json_dumps(body, JSON_COMPACT);
        json_decref(body);
        if (!bodystr) die("json_dumps failed");

        HttpResp r;
        int ok = http_req(&r, url, bodystr, accept, 0) == 0;
        free(bodystr);
        if (!ok) die("curl POST to %s failed%s%s",
                     url, r.err[0] ? ": " : "", r.err);

        if (r.status >= 400) {
            /* a badNonce may be retried with a fresh nonce */
            if (strstr(r.body, "badNonce")) {
                http_resp_free(&r);
                continue;
            }
            die("ACME server rejected request to %s (status %d):\n%s",
                url, r.status, r.body);
        }
        result = xstrdup(r.body);
        if (loc_out) {
            const char *loc = hdr_get(r.hdr, "Location");
            *loc_out = loc ? xstrdup(loc) : NULL;
        }
        http_resp_free(&r);
        return result;
    }
    die("ACME server kept rejecting our nonces");
    return NULL;
}

/* create (or resume) the account; fills a->kid */
static void acme_account(Acme *a, const char *contact) {
    json_t *payload = json_object();
    json_object_set_new(payload, "termsOfServiceAgreed", json_true());
    if (contact) {
        json_t *arr = json_array();
        char buf[256];
        snprintf(buf, sizeof buf, "mailto:%s", contact);
        json_array_append_new(arr, json_string(buf));
        json_object_set_new(payload, "contact", arr);
    }
    char *ps = json_dumps(payload, JSON_COMPACT);
    json_decref(payload);
    if (!ps) die("json_dumps failed");

    /* newAccount is sent with the JWK, not the kid.  If the account
     * already exists, the server answers 200 with the same Location. */
    char *loc = NULL;
    char *body = jws_post(a, a->new_account, ps, 0, NULL, &loc);
    free(body);
    free(ps);
    if (!loc) die("newAccount: no Location header");
    a->kid = loc;
    printf("account: %s\n", a->kid);
}

/* one HTTP-01 authorization: write the challenge, answer, poll */
static void acme_authorize(Acme *a, const char *authz_url,
                           const char *letsencrypt_root,
                           const char *check_base, const char *domain) {
    char *body = jws_post(a, authz_url, "", 1, NULL, NULL);
    json_error_t err;
    json_t *j = json_loads(body, 0, &err);
    free(body);
    if (!j) die("authorization: bad JSON: %s", err.text);

    json_t *chals = json_object_get(j, "challenges");
    if (!json_is_array(chals)) {
        json_decref(j);
        die("authorization for %s: no challenges", domain);
    }
    const char *token = NULL, *churl = NULL;
    for (size_t i = 0; i < json_array_size(chals); i++) {
        json_t *c = json_array_get(chals, i);
        if (j_str(c, "type") && !strcmp(j_str(c, "type"), "http-01")) {
            token = j_str(c, "token");
            churl = j_str(c, "url");
            break;
        }
    }
    if (!token || !churl) {
        json_decref(j);
        die("authorization for %s offers no http-01 challenge", domain);
    }

    /* validate the token before using it as a file name */
    size_t tl = strlen(token);
    if (tl < 1 || tl > 128 ||
        strspn(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "abcdefghijklmnopqrstuvwxyz0123456789-_") != tl) {
        json_decref(j);
        die("authorization for %s has a malformed token", domain);
    }

    /* key authorization = token || '.' || thumbprint */
    char keyauth[256];
    snprintf(keyauth, sizeof keyauth, "%s.%s", token, a->thumbprint);

    /* write the challenge file where corehttpd serves it from */
    char path[1024];
    int pl = snprintf(path, sizeof path, "%s/%s", letsencrypt_root, token);
    if (pl < 0 || (size_t)pl >= sizeof path) die("challenge path too long");
    FILE *f = fopen(path, "w");
    if (!f) die("cannot write challenge file %s: %s", path, strerror(errno));
    fprintf(f, "%s\n", keyauth);
    fclose(f);
    chmod(path, 0644);

    /* self-check over HTTP before asking the CA to validate */
    char url[1024];
    if (check_base) {
        snprintf(url, sizeof url, "%s", check_base);
    } else {
        snprintf(url, sizeof url, "http://%s", domain);
    }
    size_t ul = strlen(url);
    snprintf(url + ul, sizeof url - ul, "/.well-known/acme-challenge/%s",
             token);
    HttpResp r;
    int ok = 0;
    if (http_req(&r, url, NULL, NULL, 0) == 0 && r.status == 200) {
        char *b = r.body;
        while (*b == ' ' || *b == '\t') b++;
        size_t bl = strlen(b);
        while (bl && (b[bl - 1] == '\n' || b[bl - 1] == '\r' ||
                      b[bl - 1] == ' ' || b[bl - 1] == '\t'))
            b[--bl] = 0;
        ok = !strcmp(b, keyauth);
    }
    http_resp_free(&r);
    if (!ok) {
        unlink(path);
        json_decref(j);
        die("self-check failed: %s did not serve the challenge.\n"
            "Is corehttpd running with letsencrypt_root=%s and the site\n"
            "reachable over plain HTTP on port 80?", url, letsencrypt_root);
    }
    printf("challenge for %s written and verified\n", domain);

    /* answer the challenge */
    body = jws_post(a, churl, "{}", 1, NULL, NULL);
    free(body);

    /* poll the authorization until it is decided */
    const char *status = NULL;
    for (int i = 0; i < 60; i++) {
        sleep(2);
        body = jws_post(a, authz_url, "", 1, NULL, NULL);
        json_t *j2 = json_loads(body, 0, &err);
        free(body);
        if (!j2) die("authorization: bad JSON: %s", err.text);
        const char *st = j_str(j2, "status");
        if (st) status = st;
        if (status && (!strcmp(status, "valid") || !strcmp(status, "invalid"))) {
            json_decref(j2);
            break;
        }
        json_decref(j2);
    }
    json_decref(j);
    if (!status || strcmp(status, "valid")) {
        unlink(path);
        die("authorization for %s not validated (status %s)",
            domain, status ? status : "?");
    }
    unlink(path);                                  /* challenge done */
}

/* true if the first certificate in the PEM file was issued by the
 * Let's Encrypt staging CA (issuer CN/O contains "Fake LE" or
 * "Staging") */
static int cert_is_staging(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    if (n == 0 || n == sizeof buf - 1) return 0;
    buf[n] = 0;

    static const char BEG[] = "-----BEGIN CERTIFICATE-----";
    static const char END[] = "-----END CERTIFICATE-----";
    char *p = strstr((char *)buf, BEG);
    if (!p) return 0;
    p += sizeof BEG - 1;
    char *e = strstr(p, END);
    if (!e) return 0;
    *e = 0;

    unsigned char der[8192];
    int dl = b64_decode(p, der, sizeof der);
    if (dl <= 0) return 0;
    const unsigned char *end = der + dl;

    /* Certificate -> TBS content -> skip version/serial/sigalg */
    const unsigned char *q = der_enter(der, end);
    if (!q) return 0;
    const unsigned char *c = der_enter(q, end);
    if (!c) return 0;
    if (c < end && *c == 0xa0) {
        c = der_next(c, end);
        if (!c) return 0;
    }
    c = der_next(c, end);                          /* serialNumber */
    if (!c) return 0;
    c = der_next(c, end);                          /* signature alg */
    if (!c) return 0;

    /* issuer Name at c: walk SET { SEQ { OID, value } } */
    if (c >= end || *c != 0x30) return 0;
    const unsigned char *is = der_enter(c, end);
    const unsigned char *iend = der_next(c, end);
    if (!is || !iend) return 0;

    const unsigned char *r = is;
    while (r < iend) {
        if (*r != 0x31) {                          /* not a SET: skip */
            r = der_next(r, iend);
            if (!r) break;
            continue;
        }
        const unsigned char *sq = der_enter(r, iend);
        if (sq && *sq == 0x30) {
            const unsigned char *sc = der_enter(sq, iend);
            if (sc && sc[0] == 0x06 && sc[1] == 3 && sc[2] == 0x55 &&
                sc[3] == 0x04 && (sc[4] == 0x03 || sc[4] == 0x0a)) {
                /* OID 2.5.4.3 (CN) or 2.5.4.10 (O) */
                const unsigned char *val = der_next(sc, iend);
                if (val && val[1] < 0x80 &&
                    (val[0] == 0x0c || val[0] == 0x13 || val[0] == 0x16)) {
                    char lb[64];
                    size_t vl = val[1];
                    if (vl > sizeof lb - 1) vl = sizeof lb - 1;
                    memcpy(lb, val + 2, vl);
                    lb[vl] = 0;
                    if (strcasestr(lb, "fake le") || strcasestr(lb, "staging"))
                        return 1;
                }
            }
        }
        r = der_next(r, iend);
        if (!r) break;
    }
    return 0;
}

/* =====================================================================
 * file output
 * ===================================================================== */
static void write_file_atomic(const char *path, const char *content,
                              size_t len, mode_t mode) {
    char tmp[1024];
    int pl = snprintf(tmp, sizeof tmp, "%s.new", path);
    if (pl < 0 || (size_t)pl >= sizeof tmp) die("output path too long: %s", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) die("cannot create %s: %s", tmp, strerror(errno));
    if (fchmod(fd, mode) < 0)
        die("cannot chmod %s: %s", tmp, strerror(errno));
    const char *p = content;
    size_t left = len;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmp);
            die("cannot write %s: %s", tmp, strerror(errno));
        }
        p += w;
        left -= (size_t)w;
    }
    close(fd);
    if (rename(tmp, path) < 0) {
        unlink(tmp);
        die("cannot rename %s to %s: %s", tmp, path, strerror(errno));
    }
}

/* write a DER blob as a PEM file */
static void write_pem(const char *path, const char *label,
                      const unsigned char *der, size_t derlen, mode_t mode) {
    char *b64 = b64_pem(der, derlen);
    size_t cap = strlen(b64) + strlen(label) * 2 + 64;
    char *pem = xmalloc(cap);
    snprintf(pem, cap, "-----BEGIN %s-----\n%s-----END %s-----\n",
             label, b64, label);
    write_file_atomic(path, pem, strlen(pem), mode);
    free(b64);
    free(pem);
}

/* =====================================================================
 * one certificate: order -> authorizations -> finalize -> download
 * ===================================================================== */
static void fetch_cert(Acme *a, char **domains, int n_domains,
                       const char *letsencrypt_root, const char *check_base,
                       const char *cert_file, const char *key_file) {
    /* ---- newOrder ---- */
    json_t *ids = json_array();
    for (int i = 0; i < n_domains; i++)
        json_array_append_new(ids,
            json_pack("{s:s,s:s}", "type", "dns", "value", domains[i]));
    json_t *payload = json_pack("{s:o}", "identifiers", ids);
    char *ps = json_dumps(payload, JSON_COMPACT);
    json_decref(payload);
    if (!ps) die("json_dumps failed");

    char *order_url = NULL;
    char *obody = jws_post(a, a->new_order, ps, 1, NULL, &order_url);
    free(ps);
    if (!order_url) die("newOrder: no Location header");

    json_error_t err;
    json_t *order = json_loads(obody, 0, &err);
    free(obody);
    if (!order) die("newOrder: bad JSON: %s", err.text);
    json_t *auths = json_object_get(order, "authorizations");
    const char *finj = j_str(order, "finalize");
    if (!json_is_array(auths) || !finj) {
        json_decref(order);
        die("newOrder: missing authorizations/finalize");
    }

    /* ---- authorizations ---- */
    for (size_t i = 0; i < json_array_size(auths); i++) {
        const char *aurl = json_string_value(json_array_get(auths, i));
        if (!aurl) continue;
        acme_authorize(a, aurl, letsencrypt_root, check_base,
                       domains[i < (size_t)n_domains ? i : 0]);
    }

    /* ---- wait for the order to be ready ---- */
    int ready = 0;
    for (int i = 0; i < 60; i++) {
        char *ob = jws_post(a, order_url, "", 1, NULL, NULL);
        json_t *oj = json_loads(ob, 0, &err);
        free(ob);
        if (!oj) die("order: bad JSON: %s", err.text);
        const char *st = j_str(oj, "status");
        if (st && !strcmp(st, "ready")) {
            json_decref(oj);
            ready = 1;
            break;
        }
        if (st && (!strcmp(st, "invalid"))) {
            die("order for %s became invalid", domains[0]);
        }
        json_decref(oj);
        sleep(2);
    }
    if (!ready) die("order for %s did not become ready", domains[0]);

    /* ---- certificate keypair + CSR ---- */
    unsigned char kpriv[32], X[32], Y[32];
    if (keygen(kpriv, X, Y) < 0) die("key generation failed");
    unsigned char csrder[1024];
    size_t csrlen = build_csr(csrder, sizeof csrder, domains[0], kpriv);
    if (!csrlen) die("CSR generation failed");
    char csr64[1600];
    if (b64url_encode(csr64, sizeof csr64, csrder, csrlen) == SIZE_MAX)
        die("CSR too large");

    json_t *fp = json_pack("{s:s}", "csr", csr64);
    char *fps = json_dumps(fp, JSON_COMPACT);
    json_decref(fp);
    if (!fps) die("json_dumps failed");
    char *ob = jws_post(a, finj, fps, 1, NULL, NULL);
    free(fps);
    free(ob);

    /* ---- poll the order until the certificate is issued ---- */
    const char *cert_url = NULL;
    char *cert_url_dup = NULL;
    for (int i = 0; i < 60; i++) {
        ob = jws_post(a, order_url, "", 1, NULL, NULL);
        json_t *oj = json_loads(ob, 0, &err);
        free(ob);
        if (!oj) die("order: bad JSON: %s", err.text);
        const char *st = j_str(oj, "status");
        const char *cu = j_str(oj, "certificate");
        if (cu) cert_url_dup = xstrdup(cu);
        if (st && !strcmp(st, "valid") && cert_url_dup) {
            json_decref(oj);
            cert_url = cert_url_dup;
            break;
        }
        if (st && !strcmp(st, "invalid")) {
            json_decref(oj);
            die("order for %s became invalid", domains[0]);
        }
        json_decref(oj);
        free(cert_url_dup);
        cert_url_dup = NULL;
        sleep(2);
    }
    json_decref(order);
    free(order_url);
    if (!cert_url) die("order for %s did not complete", domains[0]);

    /* ---- download the certificate chain ---- */
    ob = jws_post(a, cert_url, "", 1, "application/pem-certificate-chain",
                  NULL);
    free(cert_url_dup);
    if (!strstr(ob, "-----BEGIN CERTIFICATE-----"))
        die("downloaded certificate is not PEM");
    write_file_atomic(cert_file, ob, strlen(ob), 0644);
    free(ob);

    /* ---- save the private key as SEC1 PEM ---- */
    unsigned char der[256];
    size_t dn = sec1_der(der, sizeof der, kpriv, X, Y);
    if (!dn) die("key serialization failed");
    write_pem(key_file, "EC PRIVATE KEY", der, dn, 0600);

    printf("certificate for %s saved to %s (key %s)\n",
           domains[0], cert_file, key_file);
}

/* =====================================================================
 * main
 * ===================================================================== */
static void usage(FILE *out) {
    fprintf(out,
        "Usage: corehttpd-acme [OPTIONS] [CONFIG]\n"
        "\n"
        "Fetch TLS certificates from Let's Encrypt (ACME v2, HTTP-01)\n"
        "and install them where corehttpd's configuration expects them.\n"
        "Talking to the ACME server is delegated to the curl program;\n"
        "all cryptography (account key, ES256 signatures, CSR) happens\n"
        "in-process.\n"
        "\n"
        "CONFIG defaults to /etc/corehttpd/config.jsonc.  The program\n"
        "reads letsencrypt_root from it (HTTP-01 challenge files are\n"
        "written there, where corehttpd serves them), plus the optional\n"
        "acme_account_key (where the account key is stored) and\n"
        "acme_url (directory of the ACME provider).  Without -d it\n"
        "issues one certificate for every site that has its own\n"
        "cert_file/key_file configured.\n"
        "\n"
        "Options:\n"
        "  -d, --domain NAME    domain for the certificate (repeatable)\n"
        "  --cert FILE          output certificate chain (with -d)\n"
        "  --key FILE           output private key (with -d)\n"
        "  --account-key FILE   ECDSA P-256 account key; created with\n"
        "                       mode 0600 if missing (default: the\n"
        "                       acme_account_key from CONFIG, else\n"
        "                       acme-account.pem next to CONFIG)\n"
        "  --contact EMAIL      email to register with the ACME account\n"
        "                       (only used on the first run, when the\n"
        "                       account is created)\n"
        "  --staging            use the Let's Encrypt staging directory\n"
        "  --acme-url URL       ACME directory URL (default: the acme_url\n"
        "                       from CONFIG, else Let's Encrypt\n"
        "                       production)\n"
        "  --renew-days N       skip sites whose certificate is still\n"
        "                       valid for more than N days (default: 30,\n"
        "                       0 = always renew)\n"
        "  --self-check-base U  fetch challenge files from U instead of\n"
        "                       http://<domain> (for testing)\n"
        "  -h, --help           show this help and exit\n"
        "\n"
        "After new certificates are written, restart corehttpd to load\n"
        "them.  Run this program from cron or a systemd timer, e.g.\n"
        "daily, to renew certificates automatically.\n");
}

int main(int argc, char **argv) {
    const char *cfgpath = "/etc/corehttpd/config.jsonc";
    const char *account_key = NULL;
    const char *contact = NULL;
    const char *acme_url = NULL;
    const char *cert_out = NULL, *key_out = NULL;
    const char *check_base = NULL;
    int staging = 0;
    long renew_days = 30;
    char **domains = NULL;
    int n_domains = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(a, "--staging")) {
            staging = 1;
        } else if (!strcmp(a, "-d") || !strcmp(a, "--domain")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            domains = realloc(domains, sizeof(char *) * (size_t)(n_domains + 1));
            if (!domains) die("out of memory");
            domains[n_domains++] = xstrdup(argv[++i]);
        } else if (!strcmp(a, "--cert")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            cert_out = argv[++i];
        } else if (!strcmp(a, "--key")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            key_out = argv[++i];
        } else if (!strcmp(a, "--account-key")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            account_key = argv[++i];
        } else if (!strcmp(a, "--contact")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            contact = argv[++i];
        } else if (!strcmp(a, "--acme-url")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            acme_url = argv[++i];
        } else if (!strcmp(a, "--self-check-base")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            check_base = argv[++i];
        } else if (!strcmp(a, "--renew-days")) {
            if (i + 1 >= argc) die("option %s needs an argument", a);
            char *end;
            renew_days = strtol(argv[++i], &end, 10);
            if (*end || renew_days < 0 || renew_days > 3650)
                die("bad --renew-days value");
        } else if (a[0] == '-') {
            die("unknown option: %s", a);
        } else {
            cfgpath = a;
        }
    }

    AcmeCfg *cfg = read_cfg(cfgpath);

    /* directory URL precedence: --acme-url, then --staging, then the
     * config file's acme_url (so other ACME providers work), then the
     * Let's Encrypt production directory */
    if (!acme_url)
        acme_url = staging
            ? "https://acme-staging-v02.api.letsencrypt.org/directory"
            : (cfg->acme_url ? cfg->acme_url
                             : "https://acme-v02.api.letsencrypt.org/directory");

    /* account key location: --account-key wins, then the config file's
     * acme_account_key, then acme-account.pem next to the config (the
     * config option exists for root filesystems mounted read-only) */
    if (!account_key)
        account_key = cfg->acme_account_key;
    if (!account_key) {
        const char *slash = strrchr(cfgpath, '/');
        size_t dirlen = slash ? (size_t)(slash - cfgpath) : 1;
        char *def = xmalloc(dirlen + 32);
        if (slash) {
            memcpy(def, cfgpath, dirlen);
            def[dirlen] = 0;
        } else {
            strcpy(def, ".");
        }
        strcat(def, "/acme-account.pem");
        account_key = def;
    }

    /* ---- the certificate worklist ---- */
    typedef struct { char **domains; int n; const char *cert, *key; } Job;
    Job *jobs = NULL;
    int n_jobs = 0;
    if (n_domains > 0) {
        /* fall back to the matching site's configured paths */
        if (!cert_out || !key_out) {
            for (int i = 0; i < cfg->n_sites && (!cert_out || !key_out); i++)
                if (!strcmp(cfg->sites[i].name, domains[0])) {
                    if (!cert_out && cfg->sites[i].cert_file)
                        cert_out = cfg->sites[i].cert_file;
                    if (!key_out && cfg->sites[i].key_file)
                        key_out = cfg->sites[i].key_file;
                }
        }
        if (!cert_out || !key_out)
            die("with -d you must also give --cert and --key");
        jobs = xmalloc(sizeof(Job));
        jobs[0].domains = domains;
        jobs[0].n = n_domains;
        jobs[0].cert = cert_out;
        jobs[0].key = key_out;
        n_jobs = 1;
    } else {
        for (int i = 0; i < cfg->n_sites; i++)
            if (cfg->sites[i].cert_file && cfg->sites[i].key_file)
                n_jobs++;
        if (!n_jobs)
            die("no sites with cert_file/key_file in %s; give -d DOMAIN "
                "--cert FILE --key FILE", cfgpath);
        jobs = xmalloc(sizeof(Job) * (size_t)n_jobs);
        int j = 0;
        for (int i = 0; i < cfg->n_sites; i++) {
            AcmeSite *s = &cfg->sites[i];
            if (!s->cert_file || !s->key_file) continue;
            jobs[j].domains = xmalloc(sizeof(char *));
            jobs[j].domains[0] = xstrdup(s->name);
            jobs[j].n = 1;
            jobs[j].cert = s->cert_file;
            jobs[j].key = s->key_file;
            j++;
        }
    }

    /* ---- account key ---- */
    Acme a;
    memset(&a, 0, sizeof a);
    if (load_ec_key(account_key, a.acct_priv) < 0) {
        unsigned char X[32], Y[32];
        printf("creating ECDSA P-256 account key %s\n", account_key);
        if (keygen(a.acct_priv, X, Y) < 0)
            die("key generation failed");
        unsigned char der[256];
        size_t n = sec1_der(der, sizeof der, a.acct_priv, X, Y);
        if (!n) die("key serialization failed");
        write_pem(account_key, "EC PRIVATE KEY", der, n, 0600);
    }
    {
        unsigned char X[32], Y[32];
        if (pub_from_priv(X, Y, a.acct_priv) < 0)
            die("account key is not a valid P-256 key");
        b64url_encode(a.jwk_x, sizeof a.jwk_x, X, 32);
        b64url_encode(a.jwk_y, sizeof a.jwk_y, Y, 32);

        /* RFC 7638 thumbprint: SHA-256 of the canonical JWK */
        json_t *j = json_pack("{s:s,s:s,s:s,s:s}", "crv", "P-256",
                              "kty", "EC", "x", a.jwk_x, "y", a.jwk_y);
        char *canon = json_dumps(j, JSON_COMPACT | JSON_SORT_KEYS);
        json_decref(j);
        if (!canon) die("json_dumps failed");
        unsigned char dg[32];
        sha256_one(dg, canon, strlen(canon));
        b64url_encode(a.thumbprint, sizeof a.thumbprint, dg, 32);
        free(canon);
    }

    /* ---- ACME account + orders ---- */
    acme_init(&a, acme_url);
    acme_account(&a, contact);

    int issued = 0, skipped = 0;
    for (int i = 0; i < n_jobs; i++) {
        Job *job = &jobs[i];
        if (renew_days > 0) {
            long left = cert_days_left(job->cert);
            if (left > renew_days) {
                /* a staging-issued certificate is never kept when
                 * talking to a non-staging directory (the usual
                 * "drop --staging for production" flow) */
                int staging_cert = cert_is_staging(job->cert);
                int staging_run = strstr(acme_url, "staging") != NULL;
                if (!(staging_cert && !staging_run)) {
                    printf("%s: certificate still valid for %ld days, skipping\n",
                           job->cert, left);
                    skipped++;
                    continue;
                }
                printf("%s: certificate was issued by the staging CA, "
                       "renewing\n", job->cert);
            }
        }

        printf("ordering certificate for %s\n", job->domains[0]);
        fetch_cert(&a, job->domains, job->n, cfg->letsencrypt_root,
                   check_base, job->cert, job->key);
        issued++;
    }

    printf("%s: %d issued, %d skipped\n", prog, issued, skipped);
    if (issued)
        printf("restart corehttpd to load the new certificates\n");
    return 0;
}
