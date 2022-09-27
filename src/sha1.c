#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <crp/digest.h>

#include "digest_internal.h"
#include "util.h"

static int sha1_init(unsigned char *state) {
    uint32_t hash[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    memcpy(state, hash, 20);
    memset(state + 20, 0, 8);
    return 1;
}

static int sha1_update(unsigned char *state, unsigned char *message, unsigned int m_len) {
    uint32_t *h = (uint32_t*)state;
    uint64_t *len = (uint64_t*)(state + 20);
    for (unsigned int i = 0; i < m_len; i += 64) {
        uint32_t words[80];

        for (uint32_t j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN32(*(uint32_t*)(message + i + j * 4));

        for (uint32_t j = 16; j < 80; j++)
            words[j] = LEFTROTATE32(words[j-3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16], 1);

        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        for (uint32_t j = 0; j < 80; ++j) {
            uint32_t f, k;
            if (j <= 19) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            }
            else if (j >= 20 && j <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j >= 40 && j <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else if (j >= 60 && j <= 79) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t temp = LEFTROTATE32(a, 5) + f + e + k + words[j];
            e = d;
            d = c;
            c = LEFTROTATE32(b, 30);
            b = a;
            a = temp;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    *len += m_len * 8;
    return 1;
}

static int sha1_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md) {
    uint64_t *len = (uint64_t*)(state + 20);
    *len += rest_len * 8;
    *len = SWAPENDIAN64(*len);
    rest[rest_len] = 0x80;
    if (rest_len >= 56) {
        memset(rest + rest_len, 0, 64 - rest_len - 1);
        if (!sha1_update(state, rest, 64))
            return 0;
        rest[0] = 0;
        rest_len = 0;
    }
    memset(rest + rest_len + 1, 0, 56 - rest_len - 1);
    memcpy(rest + 56, len, 8); // footer
    if (!sha1_update(state, rest, 64))
        return 0;
    for (unsigned int i = 0; i < 5; ++i) {
        ((uint32_t*)md)[i] = SWAPENDIAN32(((uint32_t*)state)[i]);
    } 
    return 1;
}

static DIGEST md_sha1 = {
    .digest_size = 20,
    .block_size = 64,
    .state_size = 28,

    .state_init = sha1_init,
    .update = sha1_update,
    .final = sha1_final
};

DIGEST *sha1() {
    return &md_sha1;
}
