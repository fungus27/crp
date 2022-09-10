#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "digest.h"
#include "util.h"

static int md5_init(unsigned char *state) {
    uint32_t hash[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    memcpy(state, hash, 16);
    memset(state + 16, 0, 8);
    return 1;
}

static int md5_update(unsigned char *state, unsigned char *message, unsigned int m_len) {
    static const uint32_t shifts[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    static const uint32_t K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    uint32_t *output = (uint32_t*)state;
    uint64_t *len = (uint64_t*)(state + 16);

    for (unsigned int i = 0; i < m_len; i += 64) {
        uint32_t words[16];
        memcpy(words, message + i, 64);
        uint32_t a = output[0];
        uint32_t b = output[1];
        uint32_t c = output[2];
        uint32_t d = output[3];
        for (uint32_t j = 0; j < 64; ++j) {
            uint32_t f, g;
            if (j <= 15) {
                f = (b & c) | (~b & d);
                g = j;
            }
            else if (j >= 16 && j <= 31) {
                f = (d & b) | (~d & c);
                g = (5 * j + 1) % 16;
            }
            else if (j >= 32 && j <= 47) {
                f = b ^ c ^ d;
                g = (3 * j + 5) % 16;
            }
            else if (j >= 48 && j <= 63) {
                f = c ^ (b | ~d);
                g = (7 * j) % 16;
            }
            f = f + a + K[j] + words[g];
            a = d;
            d = c;
            c = b;
            b = b + LEFTROTATE32(f, shifts[j]);
        }
        output[0] += a;
        output[1] += b;
        output[2] += c;
        output[3] += d;
    }
    *len += m_len * 8;
    return 1;
}

static int md5_final(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md, unsigned int *md_len) {
    uint64_t *len = (uint64_t*)(state + 16);
    *len += rest_len * 8;
    rest[rest_len] = 0x80;
    if (rest_len >= 56) {
        memset(rest + rest_len, 0, 64 - rest_len - 1);
        if (!md5_update(state, rest, 64))
            return 0;
        rest[0] = 0;
        rest_len = 0;
    }
    memset(rest + rest_len + 1, 0, 56 - rest_len - 1);
    memcpy(rest + 56, state + 16, 8); // footer
    if (!md5_update(state, rest, 64))
        return 0;
    *md_len = 64;
    memcpy(md, state, 16);
    return 1;
}

DIGEST md5() {
    DIGEST digest = {
        .digest_size = 16,
        .block_size = 64,
        .state_size = 24,

        .state_init = md5_init,
        .update = md5_update,
        .final = md5_final
    };
    return digest;
}
