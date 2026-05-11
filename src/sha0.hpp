#pragma once
#include <cstdint>
#include <cstring>

/* SHA-0 (original SHA, pre-SHA-1). SoftEther uses this for password hashing.
   Ported from SoftEther's Encrypt.c, which in turn comes from AOSP's mincrypt/sha.c.
   The distinguishing feature vs SHA-1: the W expansion has NO rotation on bits 16-79. */

namespace se_detail {

struct Sha0Ctx {
    uint64_t count = 0;
    uint8_t  buf[64]{};
    uint32_t state[8]{};
};

inline uint32_t rol32(int n, uint32_t v) {
    return (v << n) | (v >> (32 - n));
}

inline void sha0_transform(Sha0Ctx &ctx) {
    uint32_t W[80];
    const uint8_t *p = ctx.buf;
    for (int t = 0; t < 16; ++t) {
        W[t] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16
             | (uint32_t)p[2] <<  8 | (uint32_t)p[3];
        p += 4;
    }
    /* SHA-0: no rotation in the expansion (vs SHA-1 which uses rol(1,...)) */
    for (int t = 16; t < 80; ++t)
        W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];

    uint32_t A = ctx.state[0], B = ctx.state[1], C = ctx.state[2],
             D = ctx.state[3], E = ctx.state[4];
    for (int t = 0; t < 80; ++t) {
        uint32_t tmp = rol32(5, A) + E + W[t];
        if      (t < 20) tmp += (D ^ (B & (C ^ D))) + 0x5A827999u;
        else if (t < 40) tmp += (B ^ C ^ D)          + 0x6ED9EBA1u;
        else if (t < 60) tmp += ((B & C) | (D & (B | C))) + 0x8F1BBCDCu;
        else             tmp += (B ^ C ^ D)          + 0xCA62C1D6u;
        E = D; D = C; C = rol32(30, B); B = A; A = tmp;
    }
    ctx.state[0] += A; ctx.state[1] += B; ctx.state[2] += C;
    ctx.state[3] += D; ctx.state[4] += E;
}

inline void sha0_init(Sha0Ctx &ctx) {
    ctx.state[0] = 0x67452301u;
    ctx.state[1] = 0xEFCDAB89u;
    ctx.state[2] = 0x98BADCFEu;
    ctx.state[3] = 0x10325476u;
    ctx.state[4] = 0xC3D2E1F0u;
    ctx.count    = 0;
}

inline void sha0_update(Sha0Ctx &ctx, const void *data, size_t len) {
    const uint8_t *src = static_cast<const uint8_t *>(data);
    int i = static_cast<int>(ctx.count & 63);
    ctx.count += len;
    while (len--) {
        ctx.buf[i++] = *src++;
        if (i == 64) { sha0_transform(ctx); i = 0; }
    }
}

inline void sha0_final(Sha0Ctx &ctx, uint8_t out[20]) {
    uint64_t bits = ctx.count * 8;
    uint8_t pad = 0x80;
    sha0_update(ctx, &pad, 1);
    while ((ctx.count & 63) != 56) {
        uint8_t z = 0;
        sha0_update(ctx, &z, 1);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t b = static_cast<uint8_t>(bits >> (i * 8));
        sha0_update(ctx, &b, 1);
    }
    uint8_t *p = out;
    for (int i = 0; i < 5; ++i) {
        *p++ = ctx.state[i] >> 24;
        *p++ = ctx.state[i] >> 16;
        *p++ = ctx.state[i] >>  8;
        *p++ = ctx.state[i];
    }
}

} // namespace se_detail

/* Hash `len` bytes of `data` into `out[20]` using SHA-0. */
inline void se_sha0(uint8_t out[20], const void *data, size_t len) {
    se_detail::Sha0Ctx ctx;
    se_detail::sha0_init(ctx);
    se_detail::sha0_update(ctx, data, len);
    se_detail::sha0_final(ctx, out);
}
