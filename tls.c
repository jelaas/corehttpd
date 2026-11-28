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
 * GnuTLS clients.  Everything that touches secrets (ECDSA nonce and
 * key, AES key and state, GHASH key) runs in constant time.
 */
#define _GNU_SOURCE
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
    int  timeout;                 /* seconds: limit for each wait for data */
    int  hs_keys;                 /* ServerHello sent: client records must
                                     be encrypted from now on */
    int  handshake_done;
    int64_t deadline_ms;          /* absolute limit for reads (0 = none) */
    int  pre_fd[2];               /* listening sockets (idle preemption) */
    int64_t last_rx;              /* mono_ms of the last bytes received */

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
#define TLS_MAX_CIPHERTEXT (16384 + 256)

/* zero memory that held secrets; the volatile pointer keeps the
 * compiler from dropping the stores */
static void secure_zero(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}

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
 * 256-bit modular arithmetic, constant time (4 x 64-bit limbs,
 * little-endian).  Montgomery multiplication (CIOS) is used for both
 * the P-256 field prime p and the group order n.  Additions,
 * subtractions and reductions select their result with masks instead
 * of branching, so the running time does not depend on secret values
 * (private key, nonce, intermediate coordinates).
 * ===================================================================== */
typedef unsigned __int128 u128;
typedef struct { uint64_t l[4]; } M256;

typedef struct {
    M256 m;          /* the modulus */
    uint64_t n0;     /* -m^-1 mod 2^64 */
    M256 one;        /* R mod m (Montgomery form of 1), R = 2^256 */
    M256 r2;         /* R^2 mod m */
} Mod;

static const M256 P256_P = { .l = {
    0xffffffffffffffffULL, 0x00000000ffffffffULL,
    0x0000000000000000ULL, 0xffffffff00000001ULL } };

static const M256 P256_N = { .l = {
    0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL,
    0xffffffffffffffffULL, 0xffffffff00000000ULL } };

static const M256 P256_GX = { .l = {
    0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
    0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL } };

static const M256 P256_GY = { .l = {
    0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
    0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL } };

static const M256 P256_B = { .l = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL,
    0xb3ebbd55769886bcULL, 0x5ac635d8aa3a93e7ULL } };

/* r = a - b mod 2^256; returns the borrow (1 if a < b) */
static uint64_t m256_sub_raw(M256 *r, const M256 *a, const M256 *b) {
    uint64_t br = 0;
    for (int i = 0; i < 4; i++) {
        u128 v = (u128)a->l[i] - b->l[i] - br;
        r->l[i] = (uint64_t)v;
        br = (uint64_t)(v >> 64) & 1;
    }
    return br;
}

/* r = bit ? a : r, without branching */
static void m256_cmov(M256 *r, const M256 *a, uint64_t bit) {
    uint64_t mask = 0 - bit;
    for (int i = 0; i < 4; i++)
        r->l[i] = (r->l[i] & ~mask) | (a->l[i] & mask);
}

/* 1 if a == 0, else 0 (constant time) */
static uint64_t m256_is_zero(const M256 *a) {
    uint64_t x = a->l[0] | a->l[1] | a->l[2] | a->l[3];
    return 1 ^ ((x | (0 - x)) >> 63);
}

/* r = a mod m for a < 2m (one masked subtraction) */
static void m256_reduce_once(M256 *r, const M256 *a, const M256 *m) {
    M256 t;
    uint64_t br = m256_sub_raw(&t, a, m);
    *r = *a;
    m256_cmov(r, &t, br ^ 1);
}

/* r = a + b mod m (a, b < m) */
static void f_add(M256 *r, const M256 *a, const M256 *b, const Mod *M) {
    M256 s, t;
    uint64_t c = 0;
    for (int i = 0; i < 4; i++) {
        u128 v = (u128)a->l[i] + b->l[i] + c;
        s.l[i] = (uint64_t)v;
        c = (uint64_t)(v >> 64);
    }
    uint64_t br = m256_sub_raw(&t, &s, &M->m);
    *r = s;
    m256_cmov(r, &t, c | (br ^ 1));    /* subtract when s >= m */
}

/* r = a - b mod m (a, b < m) */
static void f_sub(M256 *r, const M256 *a, const M256 *b, const Mod *M) {
    M256 d;
    uint64_t mask = 0 - m256_sub_raw(&d, a, b);
    uint64_t c = 0;
    for (int i = 0; i < 4; i++) {
        u128 v = (u128)d.l[i] + (M->m.l[i] & mask) + c;
        r->l[i] = (uint64_t)v;
        c = (uint64_t)(v >> 64);
    }
}

/* Montgomery product r = a * b * R^-1 mod m (a, b < m; r may alias) */
static void f_mul(M256 *r, const M256 *a, const M256 *b, const Mod *M) {
    uint64_t t[6] = {0};
    for (int i = 0; i < 4; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 4; j++) {
            u128 v = (u128)a->l[i] * b->l[j] + t[j] + c;
            t[j] = (uint64_t)v;
            c = (uint64_t)(v >> 64);
        }
        u128 v = (u128)t[4] + c;
        t[4] = (uint64_t)v;
        t[5] = (uint64_t)(v >> 64);

        uint64_t u = t[0] * M->n0;
        v = (u128)u * M->m.l[0] + t[0];
        c = (uint64_t)(v >> 64);
        for (int j = 1; j < 4; j++) {
            v = (u128)u * M->m.l[j] + t[j] + c;
            t[j - 1] = (uint64_t)v;
            c = (uint64_t)(v >> 64);
        }
        v = (u128)t[4] + c;
        t[3] = (uint64_t)v;
        t[4] = t[5] + (uint64_t)(v >> 64);
    }
    /* t < 2m: one masked subtraction */
    M256 lo = { .l = { t[0], t[1], t[2], t[3] } }, s;
    uint64_t br = m256_sub_raw(&s, &lo, &M->m);
    m256_cmov(&lo, &s, t[4] | (br ^ 1));
    *r = lo;
}

static void f_sqr(M256 *r, const M256 *a, const Mod *M) { f_mul(r, a, a, M); }

/* to / from Montgomery form */
static void f_to(M256 *r, const M256 *a, const Mod *M) { f_mul(r, a, &M->r2, M); }
static void f_from(M256 *r, const M256 *a, const Mod *M) {
    static const M256 one = { .l = { 1, 0, 0, 0 } };
    f_mul(r, a, &one, M);
}

/* r = a^(m-2) = a^-1 (Montgomery form in and out).  Every step does
 * the same square + multiply; the bit only selects the result. */
static void f_inv(M256 *r, const M256 *a, const Mod *M) {
    static const M256 two = { .l = { 2, 0, 0, 0 } };
    M256 e, res = M->one, t;
    m256_sub_raw(&e, &M->m, &two);
    for (int i = 255; i >= 0; i--) {
        f_sqr(&res, &res, M);
        f_mul(&t, &res, a, M);
        m256_cmov(&res, &t, (e.l[i / 64] >> (i % 64)) & 1);
    }
    *r = res;
}

static void mod_setup(Mod *M, const M256 *m) {
    M->m = *m;
    uint64_t x = m->l[0];                /* m0^-1 mod 2^64 (Newton) */
    for (int i = 0; i < 5; i++) x *= 2 - m->l[0] * x;
    M->n0 = 0 - x;
    static const M256 zero = { .l = { 0, 0, 0, 0 } };
    m256_sub_raw(&M->one, &zero, m);     /* 2^256 - m == R mod m */
    M256 t = M->one;
    for (int i = 0; i < 256; i++) f_add(&t, &t, &t, M);
    M->r2 = t;                           /* R * 2^256 mod m */
}

/* =====================================================================
 * P-256 (secp256r1): homogeneous projective coordinates in Montgomery
 * form, complete addition formulas for a = -3 (Renes, Costello, Batina,
 * "Complete addition formulas for prime order elliptic curves", 2015,
 * algorithms 4 and 6).  The formulas have no special cases (doubling,
 * identity), so point arithmetic never branches.
 * ===================================================================== */
typedef struct { M256 x, y, z; } PPoint;     /* identity: (0 : 1 : 0) */

static Mod MOD_P, MOD_N;
static M256 B_MONT;
static PPoint G_MONT;
static int p256_ready;

static void p256_init(void) {
    if (p256_ready) return;
    mod_setup(&MOD_P, &P256_P);
    mod_setup(&MOD_N, &P256_N);
    f_to(&B_MONT, &P256_B, &MOD_P);
    f_to(&G_MONT.x, &P256_GX, &MOD_P);
    f_to(&G_MONT.y, &P256_GY, &MOD_P);
    G_MONT.z = MOD_P.one;
    p256_ready = 1;
}

static void p_add(PPoint *r, const PPoint *p1, const PPoint *p2) {
    const Mod *F = &MOD_P;
    M256 t0, t1, t2, t3, t4, x3, y3, z3;
    f_mul(&t0, &p1->x, &p2->x, F);           /* t0 = X1 * X2 */
    f_mul(&t1, &p1->y, &p2->y, F);           /* t1 = Y1 * Y2 */
    f_mul(&t2, &p1->z, &p2->z, F);           /* t2 = Z1 * Z2 */
    f_add(&t3, &p1->x, &p1->y, F);           /* t3 = X1 + Y1 */
    f_add(&t4, &p2->x, &p2->y, F);           /* t4 = X2 + Y2 */
    f_mul(&t3, &t3, &t4, F);                 /* t3 = t3 * t4 */
    f_add(&t4, &t0, &t1, F);                 /* t4 = t0 + t1 */
    f_sub(&t3, &t3, &t4, F);                 /* t3 = t3 - t4 */
    f_add(&t4, &p1->y, &p1->z, F);           /* t4 = Y1 + Z1 */
    f_add(&x3, &p2->y, &p2->z, F);           /* X3 = Y2 + Z2 */
    f_mul(&t4, &t4, &x3, F);                 /* t4 = t4 * X3 */
    f_add(&x3, &t1, &t2, F);                 /* X3 = t1 + t2 */
    f_sub(&t4, &t4, &x3, F);                 /* t4 = t4 - X3 */
    f_add(&x3, &p1->x, &p1->z, F);           /* X3 = X1 + Z1 */
    f_add(&y3, &p2->x, &p2->z, F);           /* Y3 = X2 + Z2 */
    f_mul(&x3, &x3, &y3, F);                 /* X3 = X3 * Y3 */
    f_add(&y3, &t0, &t2, F);                 /* Y3 = t0 + t2 */
    f_sub(&y3, &x3, &y3, F);                 /* Y3 = X3 - Y3 */
    f_mul(&z3, &B_MONT, &t2, F);             /* Z3 = b * t2 */
    f_sub(&x3, &y3, &z3, F);                 /* X3 = Y3 - Z3 */
    f_add(&z3, &x3, &x3, F);                 /* Z3 = X3 + X3 */
    f_add(&x3, &x3, &z3, F);                 /* X3 = X3 + Z3 */
    f_sub(&z3, &t1, &x3, F);                 /* Z3 = t1 - X3 */
    f_add(&x3, &t1, &x3, F);                 /* X3 = t1 + X3 */
    f_mul(&y3, &B_MONT, &y3, F);             /* Y3 = b * Y3 */
    f_add(&t1, &t2, &t2, F);                 /* t1 = t2 + t2 */
    f_add(&t2, &t1, &t2, F);                 /* t2 = t1 + t2 */
    f_sub(&y3, &y3, &t2, F);                 /* Y3 = Y3 - t2 */
    f_sub(&y3, &y3, &t0, F);                 /* Y3 = Y3 - t0 */
    f_add(&t1, &y3, &y3, F);                 /* t1 = Y3 + Y3 */
    f_add(&y3, &t1, &y3, F);                 /* Y3 = t1 + Y3 */
    f_add(&t1, &t0, &t0, F);                 /* t1 = t0 + t0 */
    f_add(&t0, &t1, &t0, F);                 /* t0 = t1 + t0 */
    f_sub(&t0, &t0, &t2, F);                 /* t0 = t0 - t2 */
    f_mul(&t1, &t4, &y3, F);                 /* t1 = t4 * Y3 */
    f_mul(&t2, &t0, &y3, F);                 /* t2 = t0 * Y3 */
    f_mul(&y3, &x3, &z3, F);                 /* Y3 = X3 * Z3 */
    f_add(&y3, &y3, &t2, F);                 /* Y3 = Y3 + t2 */
    f_mul(&x3, &t3, &x3, F);                 /* X3 = t3 * X3 */
    f_sub(&x3, &x3, &t1, F);                 /* X3 = X3 - t1 */
    f_mul(&z3, &t4, &z3, F);                 /* Z3 = t4 * Z3 */
    f_mul(&t1, &t3, &t0, F);                 /* t1 = t3 * t0 */
    f_add(&z3, &z3, &t1, F);                 /* Z3 = Z3 + t1 */
    r->x = x3; r->y = y3; r->z = z3;
}

static void p_double(PPoint *r, const PPoint *p) {
    const Mod *F = &MOD_P;
    M256 t0, t1, t2, t3, x3, y3, z3;
    f_sqr(&t0, &p->x, F);                    /* t0 = X^2 */
    f_sqr(&t1, &p->y, F);                    /* t1 = Y^2 */
    f_sqr(&t2, &p->z, F);                    /* t2 = Z^2 */
    f_mul(&t3, &p->x, &p->y, F);             /* t3 = X * Y */
    f_add(&t3, &t3, &t3, F);                 /* t3 = t3 + t3 */
    f_mul(&z3, &p->x, &p->z, F);             /* Z3 = X * Z */
    f_add(&z3, &z3, &z3, F);                 /* Z3 = Z3 + Z3 */
    f_mul(&y3, &B_MONT, &t2, F);             /* Y3 = b * t2 */
    f_sub(&y3, &y3, &z3, F);                 /* Y3 = Y3 - Z3 */
    f_add(&x3, &y3, &y3, F);                 /* X3 = Y3 + Y3 */
    f_add(&y3, &x3, &y3, F);                 /* Y3 = X3 + Y3 */
    f_sub(&x3, &t1, &y3, F);                 /* X3 = t1 - Y3 */
    f_add(&y3, &t1, &y3, F);                 /* Y3 = t1 + Y3 */
    f_mul(&y3, &x3, &y3, F);                 /* Y3 = X3 * Y3 */
    f_mul(&x3, &x3, &t3, F);                 /* X3 = X3 * t3 */
    f_add(&t3, &t2, &t2, F);                 /* t3 = t2 + t2 */
    f_add(&t2, &t2, &t3, F);                 /* t2 = t2 + t3 */
    f_mul(&z3, &B_MONT, &z3, F);             /* Z3 = b * Z3 */
    f_sub(&z3, &z3, &t2, F);                 /* Z3 = Z3 - t2 */
    f_sub(&z3, &z3, &t0, F);                 /* Z3 = Z3 - t0 */
    f_add(&t3, &z3, &z3, F);                 /* t3 = Z3 + Z3 */
    f_add(&z3, &z3, &t3, F);                 /* Z3 = Z3 + t3 */
    f_add(&t3, &t0, &t0, F);                 /* t3 = t0 + t0 */
    f_add(&t0, &t3, &t0, F);                 /* t0 = t3 + t0 */
    f_sub(&t0, &t0, &t2, F);                 /* t0 = t0 - t2 */
    f_mul(&t0, &t0, &z3, F);                 /* t0 = t0 * Z3 */
    f_add(&y3, &y3, &t0, F);                 /* Y3 = Y3 + t0 */
    f_mul(&t0, &p->y, &p->z, F);             /* t0 = Y * Z */
    f_add(&t0, &t0, &t0, F);                 /* t0 = t0 + t0 */
    f_mul(&z3, &t0, &z3, F);                 /* Z3 = t0 * Z3 */
    f_sub(&x3, &x3, &z3, F);                 /* X3 = X3 - Z3 */
    f_mul(&z3, &t0, &t1, F);                 /* Z3 = t0 * t1 */
    f_add(&z3, &z3, &z3, F);                 /* Z3 = Z3 + Z3 */
    f_add(&z3, &z3, &z3, F);                 /* Z3 = Z3 + Z3 */
    r->x = x3; r->y = y3; r->z = z3;
}

/* k * P with a fixed 4-bit window: always 256 doublings and 64
 * additions, and every table entry is read for every lookup */
static void p_mul(PPoint *r, const M256 *k, const PPoint *P) {
    PPoint T[16], acc, sel;
    memset(&T[0], 0, sizeof T[0]);
    T[0].y = MOD_P.one;                      /* identity */
    T[1] = *P;
    for (int i = 2; i < 16; i++) {
        if (i & 1) p_add(&T[i], &T[i - 1], P);
        else       p_double(&T[i], &T[i / 2]);
    }
    acc = T[0];
    for (int w = 63; w >= 0; w--) {
        for (int j = 0; j < 4; j++) p_double(&acc, &acc);
        uint64_t idx = (k->l[w / 16] >> ((w % 16) * 4)) & 15;
        sel = T[0];
        for (uint64_t i = 1; i < 16; i++) {
            uint64_t x = i ^ idx;
            uint64_t eq = 1 ^ ((x | (0 - x)) >> 63);
            m256_cmov(&sel.x, &T[i].x, eq);
            m256_cmov(&sel.y, &T[i].y, eq);
            m256_cmov(&sel.z, &T[i].z, eq);
        }
        p_add(&acc, &acc, &sel);
    }
    *r = acc;
    secure_zero(T, sizeof T);
    secure_zero(&acc, sizeof acc);
    secure_zero(&sel, sizeof sel);
}

/* plain (non-Montgomery) affine coordinates; fails on the identity */
static int p_affine(M256 *ax, M256 *ay, const PPoint *p) {
    if (m256_is_zero(&p->z)) return -1;
    M256 zi, t;
    f_inv(&zi, &p->z, &MOD_P);
    f_mul(&t, &p->x, &zi, &MOD_P);
    f_from(ax, &t, &MOD_P);
    f_mul(&t, &p->y, &zi, &MOD_P);
    f_from(ay, &t, &MOD_P);
    return 0;
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

/* 1 <= d < n */
static int p256_scalar_valid(const unsigned char d[32]) {
    M256 v, t;
    m256_from_be(&v, d);
    return !m256_is_zero(&v) && m256_sub_raw(&t, &v, &P256_N);
}

/* public key (affine, big-endian) for a private scalar */
static int p256_pub(unsigned char X[32], unsigned char Y[32],
                    const unsigned char d[32]) {
    p256_init();
    if (!p256_scalar_valid(d)) return -1;
    M256 k, ax, ay;
    PPoint q;
    m256_from_be(&k, d);
    p_mul(&q, &k, &G_MONT);
    int rc = p_affine(&ax, &ay, &q);
    if (rc == 0) { m256_to_be(X, &ax); m256_to_be(Y, &ay); }
    secure_zero(&k, sizeof k);
    return rc;
}

typedef struct { unsigned char v[32], K[32]; } Rfc6979;

/* RFC 6979 §3.2 init (ECDSA + SHA-256); digest already computed */
static void rfc6979_init(Rfc6979 *st, const unsigned char x[32],
                         const unsigned char digest[32]) {
    /* bits2octets(digest) = digest mod n */
    M256 h1m;
    m256_from_be(&h1m, digest);
    m256_reduce_once(&h1m, &h1m, &P256_N);
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
    secure_zero(msg, sizeof msg);
}

/* next deterministic nonce candidate; returns 1 <= k < n */
static void rfc6979_next(Rfc6979 *st, M256 *k) {
    unsigned char msg[33];
    for (;;) {
        /* V = HMAC_K(V); candidate = bits2int(V) */
        hmac_sha256(st->v, st->K, 32, st->v, 32);
        M256 cand, t;
        m256_from_be(&cand, st->v);
        uint64_t ok = (m256_is_zero(&cand) ^ 1) &
                      m256_sub_raw(&t, &cand, &P256_N);   /* cand < n */
        if (ok) {                     /* rejection happens with p < 2^-32 */
            *k = cand;
            secure_zero(&cand, sizeof cand);
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
 * Returns DER SEQUENCE { INTEGER r, INTEGER s } in out (<= 72 bytes).
 * The nonce and the private key only pass through constant-time code. */
static int ecdsa_sign(unsigned char *out, size_t *outlen,
                      const unsigned char d[32],
                      const unsigned char digest[32]) {
    p256_init();
    const Mod *N = &MOD_N;
    M256 z, zm, dm, k, km, kinv, r, rm, s, t, ax, ay;
    PPoint kg;
    Rfc6979 st;
    int rc = -1;

    m256_from_be(&z, digest);
    m256_reduce_once(&z, &z, &P256_N);
    f_to(&zm, &z, N);
    m256_from_be(&dm, d);                          /* 1 <= d < n (checked at load) */
    f_to(&dm, &dm, N);
    rfc6979_init(&st, d, digest);

    for (int attempt = 0; attempt < 4 && rc < 0; attempt++) {
        rfc6979_next(&st, &k);

        /* r = x(k*G) mod n   (x < p < 2n) */
        p_mul(&kg, &k, &G_MONT);
        if (p_affine(&ax, &ay, &kg) < 0) continue;
        m256_reduce_once(&r, &ax, &P256_N);
        if (m256_is_zero(&r)) continue;

        /* s = k^-1 * (z + r*d) mod n */
        f_to(&km, &k, N);
        f_inv(&kinv, &km, N);
        f_to(&rm, &r, N);
        f_mul(&t, &rm, &dm, N);
        f_add(&t, &t, &zm, N);
        f_mul(&s, &kinv, &t, N);
        f_from(&s, &s, N);
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
        rc = 0;
    }
    secure_zero(&dm, sizeof dm);
    secure_zero(&k, sizeof k);
    secure_zero(&km, sizeof km);
    secure_zero(&kinv, sizeof kinv);
    secure_zero(&t, sizeof t);
    secure_zero(&kg, sizeof kg);
    secure_zero(&st, sizeof st);
    return rc;
}

/* =====================================================================
 * AES-128, constant time.  SubBytes evaluates the Boyar-Peralta S-box
 * circuit ("A depth-16 circuit for the AES S-box", 2011) on bitsliced
 * data — bit i of every state byte packed into one word — so there are
 * no secret-dependent table lookups (cache-timing safe).
 * ===================================================================== */
static void aes_sbox_bs(uint32_t *q) {
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y1, y2, y3, y4, y5, y6, y7, y8, y9;
    uint32_t y10, y11, y12, y13, y14, y15, y16, y17, y18, y19;
    uint32_t y20, y21;
    uint32_t z0, z1, z2, z3, z4, z5, z6, z7, z8, z9;
    uint32_t z10, z11, z12, z13, z14, z15, z16, z17;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t t10, t11, t12, t13, t14, t15, t16, t17, t18, t19;
    uint32_t t20, t21, t22, t23, t24, t25, t26, t27, t28, t29;
    uint32_t t30, t31, t32, t33, t34, t35, t36, t37, t38, t39;
    uint32_t t40, t41, t42, t43, t44, t45, t46, t47, t48, t49;
    uint32_t t50, t51, t52, t53, t54, t55, t56, t57, t58, t59;
    uint32_t t60, t61, t62, t63, t64, t65, t66, t67;
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7;

    /* x0 is the most significant bit */
    x0 = q[7]; x1 = q[6]; x2 = q[5]; x3 = q[4];
    x4 = q[3]; x5 = q[2]; x6 = q[1]; x7 = q[0];

    /* top linear transformation */
    y14 = x3 ^ x5;
    y13 = x0 ^ x6;
    y9 = x0 ^ x3;
    y8 = x0 ^ x5;
    t0 = x1 ^ x2;
    y1 = t0 ^ x7;
    y4 = y1 ^ x3;
    y12 = y13 ^ y14;
    y2 = y1 ^ x0;
    y5 = y1 ^ x6;
    y3 = y5 ^ y8;
    t1 = x4 ^ y12;
    y15 = t1 ^ x5;
    y20 = t1 ^ x1;
    y6 = y15 ^ x7;
    y10 = y15 ^ t0;
    y11 = y20 ^ y9;
    y7 = x7 ^ y11;
    y17 = y10 ^ y11;
    y19 = y10 ^ y8;
    y16 = t0 ^ y11;
    y21 = y13 ^ y16;
    y18 = x0 ^ y16;

    /* non-linear section */
    t2 = y12 & y15;
    t3 = y3 & y6;
    t4 = t3 ^ t2;
    t5 = y4 & x7;
    t6 = t5 ^ t2;
    t7 = y13 & y16;
    t8 = y5 & y1;
    t9 = t8 ^ t7;
    t10 = y2 & y7;
    t11 = t10 ^ t7;
    t12 = y9 & y11;
    t13 = y14 & y17;
    t14 = t13 ^ t12;
    t15 = y8 & y10;
    t16 = t15 ^ t12;
    t17 = t4 ^ t14;
    t18 = t6 ^ t16;
    t19 = t9 ^ t14;
    t20 = t11 ^ t16;
    t21 = t17 ^ y20;
    t22 = t18 ^ y19;
    t23 = t19 ^ y21;
    t24 = t20 ^ y18;

    t25 = t21 ^ t22;
    t26 = t21 & t23;
    t27 = t24 ^ t26;
    t28 = t25 & t27;
    t29 = t28 ^ t22;
    t30 = t23 ^ t24;
    t31 = t22 ^ t26;
    t32 = t31 & t30;
    t33 = t32 ^ t24;
    t34 = t23 ^ t33;
    t35 = t27 ^ t33;
    t36 = t24 & t35;
    t37 = t36 ^ t34;
    t38 = t27 ^ t36;
    t39 = t29 & t38;
    t40 = t25 ^ t39;

    t41 = t40 ^ t37;
    t42 = t29 ^ t33;
    t43 = t29 ^ t40;
    t44 = t33 ^ t37;
    t45 = t42 ^ t41;
    z0 = t44 & y15;
    z1 = t37 & y6;
    z2 = t33 & x7;
    z3 = t43 & y16;
    z4 = t40 & y1;
    z5 = t29 & y7;
    z6 = t42 & y11;
    z7 = t45 & y17;
    z8 = t41 & y10;
    z9 = t44 & y12;
    z10 = t37 & y3;
    z11 = t33 & y4;
    z12 = t43 & y13;
    z13 = t40 & y5;
    z14 = t29 & y2;
    z15 = t42 & y9;
    z16 = t45 & y14;
    z17 = t41 & y8;

    /* bottom linear transformation */
    t46 = z15 ^ z16;
    t47 = z10 ^ z11;
    t48 = z5 ^ z13;
    t49 = z9 ^ z10;
    t50 = z2 ^ z12;
    t51 = z2 ^ z5;
    t52 = z7 ^ z8;
    t53 = z0 ^ z3;
    t54 = z6 ^ z7;
    t55 = z16 ^ z17;
    t56 = z12 ^ t48;
    t57 = t50 ^ t53;
    t58 = z4 ^ t46;
    t59 = z3 ^ t54;
    t60 = t46 ^ t57;
    t61 = z14 ^ t57;
    t62 = t52 ^ t58;
    t63 = t49 ^ t58;
    t64 = z4 ^ t59;
    t65 = t61 ^ t62;
    t66 = z1 ^ t63;
    s0 = t59 ^ t63;
    s6 = t56 ^ ~t62;
    s7 = t48 ^ ~t60;
    t67 = t64 ^ t65;
    s3 = t53 ^ t66;
    s4 = t51 ^ t66;
    s5 = t47 ^ t65;
    s1 = t64 ^ ~s3;
    s2 = t55 ^ ~t67;

    q[7] = s0; q[6] = s1; q[5] = s2; q[4] = s3;
    q[3] = s4; q[2] = s5; q[1] = s6; q[0] = s7;
}

/* S-box applied to n <= 32 bytes in place */
static void aes_sub_bytes(unsigned char *b, int n) {
    uint32_t q[8] = {0};
    for (int j = 0; j < n; j++)
        for (int i = 0; i < 8; i++)
            q[i] |= (uint32_t)((b[j] >> i) & 1) << j;
    aes_sbox_bs(q);
    for (int j = 0; j < n; j++) {
        unsigned v = 0;
        for (int i = 0; i < 8; i++) v |= ((q[i] >> j) & 1u) << i;
        b[j] = (unsigned char)v;
    }
    secure_zero(q, sizeof q);
}

static const unsigned char aes_rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

typedef struct { unsigned char rk[176]; } AesKey;

static void aes_expand(AesKey *k, const unsigned char key[16]) {
    memcpy(k->rk, key, 16);
    for (int i = 4; i < 44; i++) {
        unsigned char t[4];
        memcpy(t, k->rk + 4 * (i - 1), 4);
        if (i % 4 == 0) {
            unsigned char u = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = u;   /* RotWord */
            aes_sub_bytes(t, 4);                               /* SubWord */
            t[0] ^= aes_rcon[i / 4 - 1];
        }
        for (int j = 0; j < 4; j++)
            k->rk[4 * i + j] = k->rk[4 * (i - 4) + j] ^ t[j];
        secure_zero(t, sizeof t);
    }
}

static unsigned char aes_xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ (0x1b & (0 - (x >> 7))));
}

/* in and out may alias; state byte 4*c + r is row r of column c */
static void aes_enc_block(const AesKey *k, const unsigned char in[16],
                          unsigned char out[16]) {
    unsigned char s[16], t[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ k->rk[i];
    for (int r = 1; r <= 10; r++) {
        aes_sub_bytes(s, 16);
        for (int c = 0; c < 4; c++)                     /* ShiftRows */
            for (int j = 0; j < 4; j++)
                t[4 * c + j] = s[4 * ((c + j) & 3) + j];
        if (r < 10) {                                   /* MixColumns */
            for (int c = 0; c < 4; c++) {
                unsigned char a0 = t[4*c], a1 = t[4*c+1], a2 = t[4*c+2], a3 = t[4*c+3];
                unsigned char x0 = aes_xtime(a0), x1 = aes_xtime(a1),
                              x2 = aes_xtime(a2), x3 = aes_xtime(a3);
                s[4*c]   = x0 ^ x1 ^ a1 ^ a2 ^ a3;
                s[4*c+1] = a0 ^ x1 ^ x2 ^ a2 ^ a3;
                s[4*c+2] = a0 ^ a1 ^ x2 ^ x3 ^ a3;
                s[4*c+3] = x0 ^ a0 ^ a1 ^ a2 ^ x3;
            }
        } else {
            memcpy(s, t, 16);
        }
        for (int i = 0; i < 16; i++) s[i] ^= k->rk[16 * r + i];
    }
    memcpy(out, s, 16);
    secure_zero(s, sizeof s);
    secure_zero(t, sizeof t);
}

/* =====================================================================
 * AES-128-GCM
 * ===================================================================== */
static uint64_t ld64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void st64(unsigned char *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (unsigned char)v; v >>= 8; }
}

/* GHASH multiplication per GCM spec (NIST SP 800-38D): bits of X are
 * taken from the left; V is right-shifted each step and R = 0xE1 || 0^120
 * is XORed in when the shifted-out bit was 1.  Both conditional steps
 * use masks, so the timing does not depend on H or the data. */
static void ghash_mul(unsigned char z[16], const unsigned char x[16],
                      const unsigned char y[16]) {
    uint64_t xh = ld64(x), xl = ld64(x + 8);
    uint64_t vh = ld64(y), vl = ld64(y + 8);
    uint64_t zh = 0, zl = 0;
    for (int i = 0; i < 128; i++) {
        uint64_t bit = (i < 64 ? xh >> (63 - i) : xl >> (127 - i)) & 1;
        uint64_t m = 0 - bit;
        zh ^= vh & m;
        zl ^= vl & m;
        uint64_t lsb = vl & 1;
        vl = (vl >> 1) | (vh << 63);
        vh = (vh >> 1) ^ (0xe100000000000000ULL & (0 - lsb));
    }
    st64(z, zh);
    st64(z + 8, zl);
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
        secure_zero(ek, sizeof ek);
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
    secure_zero(&k, sizeof k);
    secure_zero(h, sizeof h);
    secure_zero(ej, sizeof ej);
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
        secure_zero(ek, sizeof ek);
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
    secure_zero(&k, sizeof k);
    secure_zero(h, sizeof h);
    secure_zero(ej, sizeof ej);
    secure_zero(expect, sizeof expect);
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

/* wait for and read more raw bytes into c->rbbuf (bounded by the
 * connection's deadline, per-wait timeout and idle preemption) */
static int tls_fill(TlsConn *c) {
    if (c->rblen >= c->rbcap) return -1;
    if (io_wait(c->fd, c->deadline_ms, c->timeout * 1000, c->pre_fd,
                &c->last_rx) <= 0)
        return -1;
    ssize_t n;
    do n = read(c->fd, c->rbbuf + c->rblen, c->rbcap - c->rblen);
    while (n < 0 && errno == EINTR);
    if (n <= 0) return -1;
    c->rblen += (size_t)n;
    c->last_rx = mono_ms();
    return 0;
}

/* Fetch the next record's content into out (max cap bytes).
 * Drops the compatibility ChangeCipherSpec, decrypts TLS 1.3
 * application_data records (handshake or application keys depending on
 * state) and strips the inner content type.  Enforces the RFC 8446
 * record rules: size limits, plaintext handshake records only before
 * ServerHello, encrypted records only after it.  Returns the content
 * length, -1 on error. */
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
        if (rlen > TLS_MAX_CIPHERTEXT || 5 + rlen > c->rbcap) return -1;
        while (c->rblen - c->rbpos < 5 + rlen) {
            if (c->rbpos) {
                memmove(c->rbbuf, c->rbbuf + c->rbpos, c->rblen - c->rbpos);
                c->rblen -= c->rbpos; c->rbpos = 0;
            }
            if (tls_fill(c) < 0) return -1;
        }
        const unsigned char *rec = c->rbbuf + c->rbpos + 5;
        c->rbpos += 5 + rlen;

        if (rtype == 20) {
            /* middlebox-compatibility CCS: a single 0x01 byte, only
             * during the handshake; dropped (RFC 8446 §5) */
            if (c->handshake_done || rlen != 1 || rec[0] != 1) return -1;
            continue;
        }
        if (rtype == 21) return -1;                   /* plaintext alert */
        if (rtype == 22) {
            /* plaintext handshake: only the ClientHello, before keys */
            if (c->hs_keys || c->handshake_done) return -1;
            if (rlen == 0 || rlen > TLS_MAX_PLAINTEXT || rlen > cap) return -1;
            memcpy(out, rec, rlen);
            *ctype = 22;
            return (int)rlen;
        }
        if (rtype == 23) {
            if (!c->hs_keys && !c->handshake_done) return -1;
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
            unsigned char t = c->scratch[j];
            size_t clen = (size_t)j;
            if (clen > TLS_MAX_PLAINTEXT) return -1;      /* record_overflow */
            if (t != 21 && t != 22 && t != 23) return -1;
            if (t == 23 && !c->handshake_done) return -1;  /* no early data */
            if (t == 22 && clen == 0) return -1;
            if (clen > cap) return -1;
            *ctype = t;
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

/* Read one handshake message (possibly fragmented across records).  The
 * records must hold exactly this message: TLS 1.3 forbids handshake data
 * that spans a key change, and the server reads only single-message
 * flights (ClientHello, client Finished). */
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
                if (len != mlen) return -1;        /* trailing handshake data */
                *out = buf; *outlen = mlen; *outtype = buf[0];
                return 0;
            }
        }
        unsigned char ctype;
        int clen = tls_next_record(c, buf + len, cap - len, &ctype);
        if (clen < 0) return -1;
        if (ctype != 22) return -1;          /* alert or unexpected data */
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
        if (n == 0 || n > 2 || (size_t)(end - p) < n) return NULL;
        len = 0;
        while (n--) len = (len << 8) | *p++;
    }
    if ((size_t)(end - p) < len) return NULL;
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
        if (n == 0 || n > 2 || (size_t)(end - p) < n) return -1;
        len = 0;
        while (n--) len = (len << 8) | *p++;
    }
    if ((size_t)(end - p) < len) return -1;
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
 * Called by the master before forking.  The key must be a valid P-256
 * scalar and must belong to the first (leaf) certificate. */
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
    TlsKey *ret = NULL;
    unsigned char *der = NULL;
    if (klen >= cap || klen < 4) goto out;
    kbuf[klen] = 0;                                /* NUL for strstr */

    der = arena_alloc(a, 4096);
    if (!der) goto out;
    size_t derlen = 0;
    if (kbuf[0] == 0x30) {                         /* raw DER */
        if (klen > 4096) goto out;
        memcpy(der, kbuf, klen);
        derlen = klen;
    } else if (pem_get_block((char *)kbuf, "EC PRIVATE KEY",
                             der, &derlen, 4096) < 0 &&
               pem_get_block((char *)kbuf, "PRIVATE KEY",
                             der, &derlen, 4096) < 0) {
        goto out;
    }

    if (!has_oid_prime256(der, derlen)) {
        fprintf(stderr, "%s: not a P-256 (prime256v1) EC key\n", key_file);
        goto out;
    }
    if (der_scalar_in(der, der + derlen, k->priv) < 0) {
        fprintf(stderr, "%s: failed to extract P-256 scalar\n", key_file);
        goto out;
    }
    if (!p256_scalar_valid(k->priv)) {
        fprintf(stderr, "%s: invalid P-256 private key (out of range)\n",
                key_file);
        goto out;
    }
    {
        /* the leaf certificate must carry this key's public point */
        unsigned char pt[65];
        pt[0] = 0x04;
        if (p256_pub(pt + 1, pt + 33, k->priv) < 0 ||
            !has_oid_prime256(k->der[0], k->len[0]) ||
            !memmem(k->der[0], k->len[0], pt, sizeof pt)) {
            fprintf(stderr, "%s: certificate does not match the private "
                    "key %s\n", cert_file, key_file);
            goto out;
        }
    }
    ret = k;
out:
    /* the PEM/DER copies of the private key are no longer needed */
    secure_zero(kbuf, cap + 1);
    if (der) secure_zero(der, 4096);
    if (!ret) secure_zero(k->priv, sizeof k->priv);
    return ret;
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
                              int timeout, const int pre_fd[2]) {
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
    /* the whole handshake must finish within the timeout */
    c->last_rx = mono_ms();
    c->deadline_ms = c->last_rx + (int64_t)c->timeout * 1000;
    c->pre_fd[0] = pre_fd ? pre_fd[0] : -1;
    c->pre_fd[1] = pre_fd ? pre_fd[1] : -1;
    c->rbbuf = xmalloc(32768); c->rbcap = 32768;
    c->scratch = xmalloc(65536); c->scratchcap = 65536;

    unsigned char alert = 40;              /* handshake_failure */
    int rc = -1;

    /* secrets: declared up front so every exit path wipes them */
    unsigned char eph[32], ecdhe[32], early[32], derived[32], hs_secret[32];
    unsigned char chs[32], shs[32], d2[32], master[32], caps[32], saps[32];
    unsigned char fkey[32], cfkey[32];

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
    /* cipher_suites: TLS_AES_128_GCM_SHA256 must be offered */
    if (off + 2 > blen) goto fail;
    unsigned cs_len = get_u16(body + off); off += 2;
    if (cs_len < 2 || (cs_len & 1) || off + cs_len > blen) goto fail;
    int has_aes128 = 0;
    for (unsigned i = 0; i < cs_len; i += 2)
        if (get_u16(body + off + i) == 0x1301) has_aes128 = 1;
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
    if (!has_x25519 || !has_ecdsa || !has_aes128) goto fail;

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
        c->deadline_ms = c->last_rx + (int64_t)c->timeout * 1000;
    }

    /* ---- key schedule: early/handshake secrets ---- */
    Sha256 tr;
    sha256_init(&tr);
    sha256_update(&tr, ch, chlen);

    unsigned char eph_pub[32];
    if (random_bytes(eph, 32) < 0) goto fail;
    {
        unsigned char base[32] = {9};
        x25519(eph_pub, eph, base);
    }
    x25519(ecdhe, eph, client_pub);
    {
        /* a low-order client share gives the all-zero secret: abort
         * (RFC 8446 §7.4.2) */
        unsigned char acc = 0;
        for (int i = 0; i < 32; i++) acc |= ecdhe[i];
        if (!acc) { alert = 47; goto fail; }       /* illegal_parameter */
    }

    unsigned char zeros[32] = {0};
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
    size_t siglen = 0;
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
    unsigned char vd[32];
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
        unsigned char *flight = arena_alloc(a, flight_len);
        if (!flight) goto fail;
        unsigned char *p = flight;
        memcpy(p, ee, eelen); p += eelen;
        memcpy(p, certmsg, certlen); p += certlen;
        memcpy(p, cv, cvlen); p += cvlen;
        memcpy(p, fin, finlen);

        /* split into records of at most 2^14 bytes of handshake data
         * (record_overflow otherwise, e.g. for long certificate chains) */
        uint64_t seq = 0;
        for (size_t done = 0; done < flight_len; ) {
            size_t chunk = flight_len - done;
            if (chunk > TLS_MAX_PLAINTEXT) chunk = TLS_MAX_PLAINTEXT;
            size_t ptlen = chunk + 1, clen = ptlen + 16;
            if (clen > c->scratchcap) goto fail;
            memcpy(c->scratch, flight + done, chunk);
            c->scratch[chunk] = 0x16;                  /* inner type: handshake */
            unsigned char nonce[12];
            tls_nonce(nonce, c->server_hs_iv, seq++);
            unsigned char hdr[5] = { 23, 3, 3, (unsigned char)(clen >> 8),
                                     (unsigned char)clen };
            gcm_encrypt(c->server_hs_key, nonce, hdr, 5, c->scratch, ptlen,
                        c->scratch, c->scratch + ptlen);
            if (send_raw_all(fd, hdr, 5) < 0 ||
                send_raw_all(fd, c->scratch, clen) < 0)
                goto fail;
            done += chunk;
        }
    }
    c->hs_keys = 1;            /* from now on the client must encrypt */

    /* ---- client flight: (CCS) + encrypted Finished ---- */
    {
        unsigned char *cmsg;
        size_t cmlen;
        unsigned char cmtype;
        if (hs_read_msg(a, c, &cmsg, &cmlen, &cmtype) < 0) goto fail;
        if (cmtype != 20 || cmlen != 36) goto fail;    /* Finished */

        unsigned char expect[32];
        expand_label(cfkey, 32, chs, "finished", NULL, 0);
        Sha256 tc = tr;
        unsigned char hash[32];
        sha256_final(&tc, hash);
        hmac_sha256(expect, cfkey, 32, hash, 32);
        int ok = ct_eq32(expect, cmsg + 4);
        secure_zero(expect, sizeof expect);
        if (!ok) { alert = 51; goto fail; }            /* decrypt_error */
    }

    c->handshake_done = 1;
    c->seq_in = 0;
    c->deadline_ms = 0;        /* the caller sets per-request deadlines */
    rc = 0;

fail:
    secure_zero(eph, sizeof eph);
    secure_zero(ecdhe, sizeof ecdhe);
    secure_zero(early, sizeof early);
    secure_zero(derived, sizeof derived);
    secure_zero(hs_secret, sizeof hs_secret);
    secure_zero(chs, sizeof chs);
    secure_zero(shs, sizeof shs);
    secure_zero(d2, sizeof d2);
    secure_zero(master, sizeof master);
    secure_zero(caps, sizeof caps);
    secure_zero(saps, sizeof saps);
    secure_zero(fkey, sizeof fkey);
    secure_zero(cfkey, sizeof cfkey);
    /* handshake keys are not needed once the handshake is over */
    secure_zero(c->client_hs_key, sizeof c->client_hs_key);
    secure_zero(c->client_hs_iv, sizeof c->client_hs_iv);
    secure_zero(c->server_hs_key, sizeof c->server_hs_key);
    secure_zero(c->server_hs_iv, sizeof c->server_hs_iv);
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
        if (clen == 0) continue;                       /* empty record is legal */
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

void tls_set_deadline(TlsConn *c, int64_t deadline_ms) {
    c->deadline_ms = deadline_ms;
}

int64_t tls_last_rx(TlsConn *c) {
    return c->last_rx;
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
    /* wipe keys and every buffer that held plaintext */
    if (c->rbbuf) secure_zero(c->rbbuf, c->rbcap);
    if (c->pb) secure_zero(c->pb, c->pb_cap);
    if (c->ptbuf) secure_zero(c->ptbuf, c->ptcap);
    if (c->scratch) secure_zero(c->scratch, c->scratchcap);
    free(c->rbbuf);
    free(c->pb);
    free(c->ptbuf);
    free(c->scratch);
    secure_zero(c, sizeof *c);
    free(c);
}
