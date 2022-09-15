#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "digest.h"
#include "util.h"

static void onezero_pad(unsigned char *rest, unsigned int rest_len, unsigned int block_len) {
    rest[rest_len] = 0x80;
    memset(rest + rest_len + 1, 0, block_len - rest_len - 1);
}

static int sha256_init(unsigned char *state) {
    uint32_t hash[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(state, hash, 32);
    memset(state + 32, 0, 8);
    return 1;
}

static int sha256_update(unsigned char *state, unsigned char *message, unsigned int m_len) {
    uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t *hash = (uint32_t*)state;
    uint64_t *len = (uint64_t*)(state + 32);

    for (unsigned int i = 0; i < m_len; i += 64) {
        uint32_t words[64];

        for (uint32_t j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN32(*(uint32_t*)(message + i + j * 4));

        for (uint32_t j = 16; j < 64; j++)
            words[j] = words[j - 16] + (RIGHTROTATE32(words[j - 15], 7) ^ RIGHTROTATE32(words[j - 15], 18) ^ (words[j - 15] >> 3)) + words[j - 7]
                + (RIGHTROTATE32(words[j - 2], 17) ^ RIGHTROTATE32(words[j - 2], 19) ^ (words[j - 2] >> 10));

        uint32_t a = hash[0];
        uint32_t b = hash[1];
        uint32_t c = hash[2];
        uint32_t d = hash[3];
        uint32_t e = hash[4];
        uint32_t f = hash[5];
        uint32_t g = hash[6];
        uint32_t h = hash[7];

        for (uint32_t j = 0; j < 64; ++j) {
            uint32_t s1 = RIGHTROTATE32(e, 6) ^ RIGHTROTATE32(e, 11) ^ RIGHTROTATE32(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + s1 + ch + k[j] + words[j];
            uint32_t s0 = RIGHTROTATE32(a, 2) ^ RIGHTROTATE32(a, 13) ^ RIGHTROTATE32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    *len += m_len * 8;
    return 1;
}

static int core_sha256_final(unsigned char *state, unsigned char *rest, unsigned int rest_len) {
    uint64_t *len = (uint64_t*)(state + 32);
    *len += rest_len * 8;
    *len = SWAPENDIAN64(*len);

    onezero_pad(rest, rest_len, 64);
    if (rest_len >= 56) {
        if (!sha256_update(state, rest, 64))
            return 0;
        rest[0] = 0;
        rest_len = 0;
    }
    memset(rest + rest_len + 1, 0, 56 - rest_len - 1);
    memcpy(rest + 56, len, 8); // footer
    if (!sha256_update(state, rest, 64))
        return 0;
    return 1;
}


static int sha256_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md) {
    if (!core_sha256_final(state, rest, rest_len))
        return 0;
    for (unsigned int i = 0; i < 8; ++i)
        ((uint32_t*)md)[i] = SWAPENDIAN32(((uint32_t*)state)[i]);
    return 1;
}

static int sha224_init(unsigned char *state) {
    uint32_t hash[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    memcpy(state, hash, 32);
    memset(state + 32, 0, 8);
    return 1;
}

static int sha224_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md) {
    if (!core_sha256_final(state, rest, rest_len))
        return 0;
    for (unsigned int i = 0; i < 7; ++i)
        ((uint32_t*)md)[i] = SWAPENDIAN32(((uint32_t*)state)[i]);

    return 1;
}

static int sha512_init(unsigned char *state) {
    uint64_t hash[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    memcpy(state, hash, 64);
    memset(state + 64, 0, 16);
    return 1;
}

static int sha512_update(unsigned char *state, unsigned char *message, unsigned int m_len) {
    uint64_t k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };
    uint64_t *hash = (uint64_t*)state;
    uint64_t *len_high = (uint64_t*)(state + 64);
    uint64_t *len_low = (uint64_t*)(state + 72);

    for (unsigned int i = 0; i < m_len; i += 128) {
        uint64_t words[80];

        for (uint32_t j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN64(*(uint64_t*)(message + i + j * 8));

        for (uint32_t j = 16; j < 80; j++)
            words[j] = words[j - 16] + (RIGHTROTATE64(words[j - 15], 1) ^ RIGHTROTATE64(words[j - 15], 8) ^ (words[j - 15] >> 7)) + words[j - 7]
                + (RIGHTROTATE64(words[j - 2], 19) ^ RIGHTROTATE64(words[j - 2], 61) ^ (words[j - 2] >> 6));

        uint64_t a = hash[0];
        uint64_t b = hash[1];
        uint64_t c = hash[2];
        uint64_t d = hash[3];
        uint64_t e = hash[4];
        uint64_t f = hash[5];
        uint64_t g = hash[6];
        uint64_t h = hash[7];

        for (uint32_t j = 0; j < 80; ++j) {
            uint64_t s1 = RIGHTROTATE64(e, 14) ^ RIGHTROTATE64(e, 18) ^ RIGHTROTATE64(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = h + s1 + ch + k[j] + words[j];
            uint64_t s0 = RIGHTROTATE64(a, 28) ^ RIGHTROTATE64(a, 34) ^ RIGHTROTATE64(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }
    // assume 8 * UINT_MAX <= 2^64 - 1
    // TODO: get rid of that assumption
    uint64_t t_len_low = *len_low;
    *len_low += (uint64_t)m_len * 8;
    if (*len_low < t_len_low)
        (*len_high)++;
    return 1;
}

static int core_sha512_final(unsigned char *state, unsigned char *rest, unsigned int rest_len) {
    uint64_t *len_high = (uint64_t*)(state + 64);
    uint64_t *len_low = (uint64_t*)(state + 72);
    uint64_t t_len_low = *len_low;
    // assume 8 * UINT_MAX <= 2^64 - 1
    // TODO: get rid of that assumption
    *len_low += (uint64_t)rest_len * 8;
    if (*len_low < t_len_low)
        (*len_high)++;
    *len_high = SWAPENDIAN64(*len_high);
    *len_low = SWAPENDIAN64(*len_low);

    onezero_pad(rest, rest_len, 128);
    if (rest_len >= 112) {
        if (!sha512_update(state, rest, 128))
            return 0;
        rest[0] = 0;
        rest_len = 0;
    }
    memset(rest + rest_len + 1, 0, 112 - rest_len - 1);
    memcpy(rest + 112, state + 64, 16); // footer
    if (!sha512_update(state, rest, 128))
        return 0;
    return 1;
}

static int sha512_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md) {
    if (!core_sha512_final(state, rest, rest_len))
        return 0;
    for (unsigned int i = 0; i < 8; ++i)
        ((uint64_t*)md)[i] = SWAPENDIAN64(((uint64_t*)state)[i]);
    return 1;
}

static int sha384_init(unsigned char *state) {
    uint64_t hash[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
    memcpy(state, hash, 64);
    memset(state + 64, 0, 16);
    return 1;
}

static int sha384_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md) {
    if (!core_sha512_final(state, rest, rest_len))
        return 0;
    for (unsigned int i = 0; i < 6; ++i)
        ((uint64_t*)md)[i] = SWAPENDIAN64(((uint64_t*)state)[i]);
    return 1;
}

DIGEST sha256() {
    DIGEST digest = {
        .digest_size = 32,
        .block_size = 64,
        .state_size = 40,

        .state_init = sha256_init,
        .update = sha256_update,
        .final = sha256_final
    };
    return digest;
}

DIGEST sha224() {
    DIGEST digest = {
        .digest_size = 28,
        .block_size = 64,
        .state_size = 40,

        .state_init = sha224_init,
        .update = sha256_update,
        .final = sha224_final
    };
    return digest;
}

DIGEST sha512() {
    DIGEST digest = {
        .digest_size = 64,
        .block_size = 128,
        .state_size = 80,

        .state_init = sha512_init,
        .update = sha512_update,
        .final = sha512_final
    };
    return digest;
}

DIGEST sha384() {
    DIGEST digest = {
        .digest_size = 48,
        .block_size = 128,
        .state_size = 80,

        .state_init = sha384_init,
        .update = sha512_update,
        .final = sha384_final
    };
    return digest;
}
