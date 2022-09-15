#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
