#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define CRP_ERR 0
#define CRP_OK 1

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;

#define MAX(a, b) ( ((a) > (b)) ? (a) : (b) )
#define MIN(a, b) ( ((a) < (b)) ? (a) : (b) )

#define LEFTROTATE8(n, d) ( ( (n) << (d) ) | ( (n) >> (8 - (d)) ) )
#define RIGHTROTATE8(n, d) ( ( (n) >> (d) ) | ( (n) << (8 - (d)) ) )

#define LEFTROTATE32(n, d) ( ( (n) << (d) ) | ( (n) >> (32 - (d)) ) )
#define RIGHTROTATE32(n, d) ( ( (n) >> (d) ) | ( (n) << (32 - (d)) ) )
#define SWAPENDIAN32(n) ( ( ( (n) & 0xff ) << 24 ) | ( ( (n) & 0xff00 ) << 8 ) | ( ( (n) & 0xff0000 ) >> 8 ) | ( ( (n) & 0xff000000 ) >> 24 ) )

#define LEFTROTATE64(n, d) ( ( (n) << (d) ) | ( (n) >> (64 - (d)) ) )
#define RIGHTROTATE64(n, d) ( ( (n) >> (d) ) | ( (n) << (64 - (d)) ) )
#define SWAPENDIAN64(n) ( ( ( (n) & 0xff ) << 56 ) | ( ( (n) & 0xff00 ) << 40 ) | ( ( (n) & 0xff0000 ) << 24 ) | ( ( (n) & 0xff000000 ) << 8 ) \
        | ( ( (n) & 0xff00000000 ) >> 8 ) | ( ( (n) & 0xff0000000000 ) >> 24 ) | ( ( (n) & 0xff000000000000 ) >> 40) | ( ( (n) & 0xff00000000000000 ) >> 56 ) )

typedef struct ENC_CIPHER {
    u32 block_size; // block_size = 0 for stream ciphers
    u32 key_size, iv_size;
    u32 state_size;
    i32 (*state_init)(u8 *key, u8 *iv, u8 *state);
    i32 (*encrypt_update)(u8 *plaintext, u32 pt_len, u8 *ciphertext);
    i32 (*padder)(u8 *block, u32 pt_size, u32 block_size);
} ENC_CIPHER;

typedef struct ENC_CTX {
    u64 pt_len;
    ENC_CIPHER ciph;
    u8 *state;
    u32 queue_size;
    u8 *queue_buf;
} ENC_CTX;

void hexdump(u8 *in, u32 len) {
    for (u32 i = 0; i < len; ++i)
        printf("%.2hhx", in[i]);
    printf("\n");
}

i32 rand_bytes(u8 *out, u32 size) {
    FILE *urand = fopen("/dev/urandom", "r");
    if (!urand) {
        printf("cannot open '/dev/urandom/'. %s\n", strerror(errno));
        fclose(urand);
        return CRP_ERR;
    }

    u32 seed;
    if(!fread(&seed, sizeof(u32), 1, urand)) {
        printf("couldn't read seed from '/dev/urandom/'.\n");
        fclose(urand);
        return CRP_ERR;
    }
    srand(seed);

    while (size--) {
        u8 combine;
        if(!fread(&combine, 1, 1, urand)) {
            printf("couldn't read byte from '/dev/urandom/'.\n");
            fclose(urand);
            return CRP_ERR;
        }
        u8 res = (rand() * combine) + 0x1485914;
        res ^= ((rand() * 0x7fbfb + 2) / 3 + seed >> 2);

        out[size] = res;
    }
    fclose(urand);
    return CRP_OK;
}

u8 gf_mul(u8 a, u8 b) {
    u8 prod = 0;
    for (u32 k = 0; k < 8; ++k) {
        prod ^= (b & 1) ? a : 0;
        b >>= 1;
        u8 carry = a & 0x80;
        a <<= 1;
        a ^= carry ? 0x1b : 0;
    }
    return prod;
}

// TODO: make hash function work on large input

// digestlen: 16
i32 hash_md5(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(16);
        if (!*digest)
            return CRP_ERR;
    }
    static const u32 shifts[64] = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };
    static const u32 K[64] = {
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
    u32 output[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

    u32 padded_len = 64 * ((pt_len + 64 - 1) / 64);
    if (pt_len % 64 == 0 || pt_len % 64 >= 56) padded_len += 64;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 9);
    u64 footer = pt_len * 8;
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);

    for (u32 i = 0; i < padded_len; i += 64) {
        u32 words[16];
        memcpy(words, pad_plaintext + i, 64);
        u32 a = output[0];
        u32 b = output[1];
        u32 c = output[2];
        u32 d = output[3];
        for (u32 j = 0; j < 64; ++j) {
            u32 f, g;
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
    memcpy(*digest, output, 16);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 20
i32 hash_sha1(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(20);
        if (!*digest)
            return CRP_ERR;
    }
    u32 h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    u32 padded_len = 64 * ((pt_len + 64 - 1) / 64);
    if (pt_len % 64 == 0 || pt_len % 64 >= 56) padded_len += 64;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 9);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 64) {
        u32 words[80];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN32(*(unsigned int*)(pad_plaintext + i + j * 4));

        for (u32 j = 16; j < 80; j++)
            words[j] = LEFTROTATE32(words[j-3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16], 1);

        u32 a = h[0];
        u32 b = h[1];
        u32 c = h[2];
        u32 d = h[3];
        u32 e = h[4];
        for (u32 j = 0; j < 80; ++j) {
            u32 f, k;
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
            u32 temp = LEFTROTATE32(a, 5) + f + e + k + words[j];
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
    h[0] = SWAPENDIAN32(h[0]);
    h[1] = SWAPENDIAN32(h[1]);
    h[2] = SWAPENDIAN32(h[2]);
    h[3] = SWAPENDIAN32(h[3]);
    h[4] = SWAPENDIAN32(h[4]);
    memcpy(*digest, h, 20);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 28
i32 hash_sha224(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(32);
        if (!*digest)
            return CRP_ERR;
    }
    u32 hash[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    u32 k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    u32 padded_len = 64 * ((pt_len + 64 - 1) / 64);
    if (pt_len % 64 == 0 || pt_len % 64 >= 56) padded_len += 64;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 9);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 64) {
        u32 words[64];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN32(*(unsigned int*)(pad_plaintext + i + j * 4));

        for (u32 j = 16; j < 64; j++)
            words[j] = words[j - 16] + (RIGHTROTATE32(words[j - 15], 7) ^ RIGHTROTATE32(words[j - 15], 18) ^ (words[j - 15] >> 3)) + words[j - 7]
                + (RIGHTROTATE32(words[j - 2], 17) ^ RIGHTROTATE32(words[j - 2], 19) ^ (words[j - 2] >> 10));

        u32 a = hash[0];
        u32 b = hash[1];
        u32 c = hash[2];
        u32 d = hash[3];
        u32 e = hash[4];
        u32 f = hash[5];
        u32 g = hash[6];
        u32 h = hash[7];

        for (u32 j = 0; j < 64; ++j) {
            u32 s1 = RIGHTROTATE32(e, 6) ^ RIGHTROTATE32(e, 11) ^ RIGHTROTATE32(e, 25);
            u32 ch = (e & f) ^ (~e & g);
            u32 t1 = h + s1 + ch + k[j] + words[j];
            u32 s0 = RIGHTROTATE32(a, 2) ^ RIGHTROTATE32(a, 13) ^ RIGHTROTATE32(a, 22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 t2 = s0 + maj;

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
    for (u32 i = 0; i < 7; ++i)
        hash[i] = SWAPENDIAN32(hash[i]);
    memcpy(*digest, hash, 28);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 32
i32 hash_sha256(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(32);
        if (!*digest)
            return CRP_ERR;
    }
    u32 hash[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    u32 k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    u32 padded_len = 64 * ((pt_len + 64 - 1) / 64);
    if (pt_len % 64 == 0 || pt_len % 64 >= 56) padded_len += 64;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 9);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 64) {
        u32 words[64];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN32(*(u32*)(pad_plaintext + i + j * 4));

        for (u32 j = 16; j < 64; j++)
            words[j] = words[j - 16] + (RIGHTROTATE32(words[j - 15], 7) ^ RIGHTROTATE32(words[j - 15], 18) ^ (words[j - 15] >> 3)) + words[j - 7]
                + (RIGHTROTATE32(words[j - 2], 17) ^ RIGHTROTATE32(words[j - 2], 19) ^ (words[j - 2] >> 10));

        u32 a = hash[0];
        u32 b = hash[1];
        u32 c = hash[2];
        u32 d = hash[3];
        u32 e = hash[4];
        u32 f = hash[5];
        u32 g = hash[6];
        u32 h = hash[7];

        for (u32 j = 0; j < 64; ++j) {
            u32 s1 = RIGHTROTATE32(e, 6) ^ RIGHTROTATE32(e, 11) ^ RIGHTROTATE32(e, 25);
            u32 ch = (e & f) ^ (~e & g);
            u32 t1 = h + s1 + ch + k[j] + words[j];
            u32 s0 = RIGHTROTATE32(a, 2) ^ RIGHTROTATE32(a, 13) ^ RIGHTROTATE32(a, 22);
            u32 maj = (a & b) ^ (a & c) ^ (b & c);
            u32 t2 = s0 + maj;

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
    for (u32 i = 0; i < 8; ++i)
        hash[i] = SWAPENDIAN32(hash[i]);
    memcpy(*digest, hash, 32);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 48
i32 hash_sha384(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(64);
        if (!*digest)
            return CRP_ERR;
    }
    u64 hash[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
    u64 k[80] = {
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
    u32 padded_len = 128 * ((pt_len + 128 - 1) / 128);
    if (pt_len % 128 == 0 || pt_len % 128 >= 112) padded_len += 128;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 17);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memset(pad_plaintext + padded_len - 16, 0, 8);
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 128) {
        u64 words[80];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN64(*(u64*)(pad_plaintext + i + j * 8));

        for (u32 j = 16; j < 80; j++)
            words[j] = words[j - 16] + (RIGHTROTATE64(words[j - 15], 1) ^ RIGHTROTATE64(words[j - 15], 8) ^ (words[j - 15] >> 7)) + words[j - 7]
                + (RIGHTROTATE64(words[j - 2], 19) ^ RIGHTROTATE64(words[j - 2], 61) ^ (words[j - 2] >> 6));

        u64 a = hash[0];
        u64 b = hash[1];
        u64 c = hash[2];
        u64 d = hash[3];
        u64 e = hash[4];
        u64 f = hash[5];
        u64 g = hash[6];
        u64 h = hash[7];

        for (u32 j = 0; j < 80; ++j) {
            u64 s1 = RIGHTROTATE64(e, 14) ^ RIGHTROTATE64(e, 18) ^ RIGHTROTATE64(e, 41);
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h + s1 + ch + k[j] + words[j];
            u64 s0 = RIGHTROTATE64(a, 28) ^ RIGHTROTATE64(a, 34) ^ RIGHTROTATE64(a, 39);
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = s0 + maj;

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
    for (u32 i = 0; i < 6; ++i)
        hash[i] = SWAPENDIAN64(hash[i]);
    memcpy(*digest, hash, 48);
    free(pad_plaintext);
    return CRP_OK;
}


// digestlen: 64
i32 hash_sha512(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(64);
        if (!*digest)
            return CRP_ERR;
    }
    u64 hash[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
    u64 k[80] = {
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
    u32 padded_len = 128 * ((pt_len + 128 - 1) / 128);
    if (pt_len % 128 == 0 || pt_len % 128 >= 112) padded_len += 128;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 17);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memset(pad_plaintext + padded_len - 16, 0, 8);
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 128) {
        u64 words[80];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN64(*(u64*)(pad_plaintext + i + j * 8));

        for (u32 j = 16; j < 80; j++)
            words[j] = words[j - 16] + (RIGHTROTATE64(words[j - 15], 1) ^ RIGHTROTATE64(words[j - 15], 8) ^ (words[j - 15] >> 7)) + words[j - 7]
                + (RIGHTROTATE64(words[j - 2], 19) ^ RIGHTROTATE64(words[j - 2], 61) ^ (words[j - 2] >> 6));

        u64 a = hash[0];
        u64 b = hash[1];
        u64 c = hash[2];
        u64 d = hash[3];
        u64 e = hash[4];
        u64 f = hash[5];
        u64 g = hash[6];
        u64 h = hash[7];

        for (u32 j = 0; j < 80; ++j) {
            u64 s1 = RIGHTROTATE64(e, 14) ^ RIGHTROTATE64(e, 18) ^ RIGHTROTATE64(e, 41);
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h + s1 + ch + k[j] + words[j];
            u64 s0 = RIGHTROTATE64(a, 28) ^ RIGHTROTATE64(a, 34) ^ RIGHTROTATE64(a, 39);
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = s0 + maj;

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
    for (u32 i = 0; i < 8; ++i)
        hash[i] = SWAPENDIAN64(hash[i]);
    memcpy(*digest, hash, 64);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 28
i32 hash_sha512_224(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(28);
        if (!*digest)
            return CRP_ERR;
    }
    u64 hash[8] = {0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1};
    u64 k[80] = {
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
    u32 padded_len = 128 * ((pt_len + 128 - 1) / 128);
    if (pt_len % 128 == 0 || pt_len % 128 >= 112) padded_len += 128;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 17);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memset(pad_plaintext + padded_len - 16, 0, 8);
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 128) {
        u64 words[80];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN64(*(u64*)(pad_plaintext + i + j * 8));

        for (u32 j = 16; j < 80; j++)
            words[j] = words[j - 16] + (RIGHTROTATE64(words[j - 15], 1) ^ RIGHTROTATE64(words[j - 15], 8) ^ (words[j - 15] >> 7)) + words[j - 7]
                + (RIGHTROTATE64(words[j - 2], 19) ^ RIGHTROTATE64(words[j - 2], 61) ^ (words[j - 2] >> 6));

        u64 a = hash[0];
        u64 b = hash[1];
        u64 c = hash[2];
        u64 d = hash[3];
        u64 e = hash[4];
        u64 f = hash[5];
        u64 g = hash[6];
        u64 h = hash[7];

        for (u32 j = 0; j < 80; ++j) {
            u64 s1 = RIGHTROTATE64(e, 14) ^ RIGHTROTATE64(e, 18) ^ RIGHTROTATE64(e, 41);
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h + s1 + ch + k[j] + words[j];
            u64 s0 = RIGHTROTATE64(a, 28) ^ RIGHTROTATE64(a, 34) ^ RIGHTROTATE64(a, 39);
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = s0 + maj;

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
    for (u32 i = 0; i < 4; ++i)
        hash[i] = SWAPENDIAN64(hash[i]);
    memcpy(*digest, hash, 28);
    free(pad_plaintext);
    return CRP_OK;
}

// digestlen: 32
i32 hash_sha512_256(u8 *plaintext, u32 pt_len, u8 **digest) {
    if (!*digest) {
        *digest = malloc(32);
        if (!*digest)
            return CRP_ERR;
    }
    u64 hash[8] = {0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2};
    u64 k[80] = {
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
    u32 padded_len = 128 * ((pt_len + 128 - 1) / 128);
    if (pt_len % 128 == 0 || pt_len % 128 >= 112) padded_len += 128;
    u8 *pad_plaintext = malloc(padded_len);
    memcpy(pad_plaintext, plaintext, pt_len);
    pad_plaintext[pt_len] = 0x80;
    memset(pad_plaintext + pt_len + 1, 0, padded_len - pt_len - 17);
    u64 footer = SWAPENDIAN64((u64)(pt_len * 8));
    memset(pad_plaintext + padded_len - 16, 0, 8);
    memcpy(pad_plaintext + padded_len - 8, &footer, 8);
    for (u32 i = 0; i < padded_len; i += 128) {
        u64 words[80];

        for (u32 j = 0; j < 16; ++j)
            words[j] = SWAPENDIAN64(*(u64*)(pad_plaintext + i + j * 8));

        for (u32 j = 16; j < 80; j++)
            words[j] = words[j - 16] + (RIGHTROTATE64(words[j - 15], 1) ^ RIGHTROTATE64(words[j - 15], 8) ^ (words[j - 15] >> 7)) + words[j - 7]
                + (RIGHTROTATE64(words[j - 2], 19) ^ RIGHTROTATE64(words[j - 2], 61) ^ (words[j - 2] >> 6));

        u64 a = hash[0];
        u64 b = hash[1];
        u64 c = hash[2];
        u64 d = hash[3];
        u64 e = hash[4];
        u64 f = hash[5];
        u64 g = hash[6];
        u64 h = hash[7];

        for (u32 j = 0; j < 80; ++j) {
            u64 s1 = RIGHTROTATE64(e, 14) ^ RIGHTROTATE64(e, 18) ^ RIGHTROTATE64(e, 41);
            u64 ch = (e & f) ^ (~e & g);
            u64 t1 = h + s1 + ch + k[j] + words[j];
            u64 s0 = RIGHTROTATE64(a, 28) ^ RIGHTROTATE64(a, 34) ^ RIGHTROTATE64(a, 39);
            u64 maj = (a & b) ^ (a & c) ^ (b & c);
            u64 t2 = s0 + maj;

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
    for (u32 i = 0; i < 4; ++i)
        hash[i] = SWAPENDIAN64(hash[i]);
    memcpy(*digest, hash, 32);
    free(pad_plaintext);
    return CRP_OK;
}

i32 encrypt_init(ENC_CTX *ctx, ENC_CIPHER cipher, u8 *key, u8 *iv) {
    ctx->ciph = cipher;
    ctx->pt_len = 0;
    ctx->state = malloc(cipher.state_size);
    if (!ctx->state)
        return CRP_ERR;
    ctx->queue_buf = cipher.block_size ? malloc(cipher.block_size) : NULL;
    ctx->queue_size = 0;
    if (!ctx->queue_buf)
        return CRP_ERR;
    return cipher.state_init(key, iv, ctx->state);
}

i32 encrypt_update(ENC_CTX *ctx, u8 *plaintext, u32 pt_len, u8 *ciphertext, u32 *ct_len) {
    *ct_len = 0;
    if (ctx->ciph.block_size) {
        while (pt_len >= ctx->ciph.block_size) {
            memcpy(ctx->queue_buf + ctx->queue_size, plaintext, ctx->ciph.block_size - ctx->queue_size);
            if (!ctx->ciph.encrypt_update(ctx->queue_buf, ctx->ciph.block_size, ciphertext))
                    return CRP_ERR;
            plaintext += ctx->ciph.block_size - ctx->queue_size;
            pt_len -= ctx->ciph.block_size - ctx->queue_size;
            ciphertext += ctx->ciph.block_size;
            *ct_len += ctx->ciph.block_size;
            ctx->queue_size = 0;
        }
        memcpy(ctx->queue_buf + ctx->queue_size, plaintext, pt_len);
        ctx->queue_size = pt_len;
    }
    else {
        // TODO: fill
    }
    return CRP_OK;
}

i32 encrypt_final(ENC_CTX *ctx, u8 *ciphertext, u32 *ct_len) {
    if (!ctx->ciph.padder(ctx->queue_buf, ctx->queue_size, ctx->ciph.block_size))
        return CRP_ERR;
    if (!ctx->ciph.encrypt_update(ctx->queue_buf, ctx->ciph.block_size, ciphertext))
        return CRP_ERR;
    *ct_len = ctx->ciph.block_size;
    free(ctx->state);
    if (ctx->queue_buf)
        free(ctx->queue_buf);
    return CRP_OK;
}

// if *ciphertext is NULL, the cipher function mallocs the needed memory which is handed to the user

// prototype (TODO: optimize), single block aes256 encryption
// ptlen: 16, keylen: 32, ctlen: 16
i32 enc_aes256(u8 *plaintext, u8 *key, u8 **ciphertext) {
    const u8 r = 15, n = 8; // TODO: implement other key sizes for aes
    if (!*ciphertext) {
        *ciphertext = malloc(16);
        if (!*ciphertext)
            return CRP_ERR;
    }

    // sbox generation by bruteforce (TODO: implement more efficient way of generation or just hardcode the table in)
    u8 sbox[256];
    for (u32 i = 0; i < 256; ++i) {
        for (u32 j = 0; j < 256; ++j) {
            u8 prod = gf_mul(i, j);
            if (prod == 1) {
                u8 t = j;
                t ^= LEFTROTATE8(t, 1) ^ LEFTROTATE8(t, 2) ^ LEFTROTATE8(t, 3) ^ LEFTROTATE8(t, 4) ^ 0x63;
                sbox[i] = t;
                break;
            }
        }
    }
    sbox[0] = 0x63;

    // key expansion
    u8 rc = 1;
    u32 exp_key[r * 4];
    memcpy(exp_key, key, n * 4);
    for (u32 i = n; i < r * 4; ++i) {
        u32 t = exp_key[i - 1];
        if (i % n == 0) {
            u32 rcon = rc;
            t = RIGHTROTATE32(exp_key[i - 1], 8);
            t = (sbox[((t & 0xff000000) >> 24)] << 24) | (sbox[((t & 0xff0000) >> 16)] << 16) | (sbox[((t & 0xff00) >> 8)] << 8) | sbox[t & 0xff];
            t ^= rcon;
            rc = (rc << 1) ^ (rc >= 0x80 ? 0x1b : 0);
        }
        else if (n > 6 && i % n == 4)
            t = (sbox[((exp_key[i-1] & 0xff000000) >> 24)] << 24) | (sbox[((exp_key[i-1] & 0xff0000) >> 16)] << 16) | (sbox[((exp_key[i-1] & 0xff00) >> 8)] << 8) | sbox[exp_key[i-1] & 0xff];
        exp_key[i] = exp_key[i - n] ^ t;
    }

    // initial round
    for (u32 i = 0; i < 16; ++i)
        (*ciphertext)[i] = plaintext[i] ^ ((u8*)exp_key)[i];

    // main rounds
    for (u32 i = 0; i < r - 2; ++i) {
        // subbytes
        for (u32 j = 0; j < 16; ++j) {
            (*ciphertext)[j] = sbox[(*ciphertext)[j]];
        }
        // shiftrows
        u8 temp[16];
        memcpy(temp, (*ciphertext), 16);
        for (u32 j = 0; j < 16; ++j) {
            (*ciphertext)[j] = temp[(j * 5) % 16];
        }
        // mixcolumns
        for (u32 j = 0; j < 4; ++j) {
            u8 *r = (*ciphertext) + j * 4;
            u8 a[4];
            u8 b[4];
            u8 h;
            for (u8 c = 0; c < 4; ++c) {
                a[c] = r[c];
                h = (r[c] >> 7) & 1;
                b[c] = r[c] << 1;
                b[c] ^= h * 0x1b;
            }
            r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
            r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
            r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
            r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
        }
        // addroundkey
        for (u32 j = 0; j < 16; ++j)
            (*ciphertext)[j] ^= ((u8*)exp_key)[(i + 1) * 16 + j];
    }

    // final round
    // subbytes
    for (u32 j = 0; j < 16; ++j) {
        (*ciphertext)[j] = sbox[(*ciphertext)[j]];
    }
    // shiftrows
    u8 temp[16];
    memcpy(temp, (*ciphertext), 16);
    for (u32 j = 0; j < 16; ++j) {
        (*ciphertext)[j] = temp[(j * 5) % 16];
    }
    // addroundkey
    for (u32 j = 0; j < 16; ++j)
        (*ciphertext)[j] ^= ((u8*)exp_key)[(r - 1) * 16 + j];

    return CRP_OK;
}

// prototype (TODO: optimize), single block aes256 decryption
// ctlen: 16, keylen: 32, ptlen: 16
i32 dec_aes256(u8 *ciphertext, u8 *key, u8 **plaintext) {
    const u8 r = 15, n = 8;
    if (!*plaintext) {
        *plaintext = malloc(16);
        if (!*plaintext)
            return CRP_ERR;
    }

    // sbox and inv_sbox generation by bruteforce
    u8 sbox[256];
    u8 inv_sbox[256];
    for (u32 i = 0; i < 256; ++i) {
        for (u32 j = 0; j < 256; ++j) {
            u8 prod = gf_mul(i, j);
            if (prod == 1) {
                u8 t = j;
                t ^= LEFTROTATE8(t, 1) ^ LEFTROTATE8(t, 2) ^ LEFTROTATE8(t, 3) ^ LEFTROTATE8(t, 4) ^ 0x63;
                sbox[i] = t;
                inv_sbox[t] = i;
                break;
            }
        }
    }
    sbox[0] = 0x63;
    inv_sbox[0] = 0x52;

    // key expansion
    u8 rc = 1;
    u32 exp_key[r * 4];
    memcpy(exp_key, key, n * 4);
    for (u32 i = n; i < r * 4; ++i) {
        u32 t = exp_key[i - 1];
        if (i % n == 0) {
            u32 rcon = rc;
            t = RIGHTROTATE32(exp_key[i - 1], 8);
            t = (sbox[((t & 0xff000000) >> 24)] << 24) | (sbox[((t & 0xff0000) >> 16)] << 16) | (sbox[((t & 0xff00) >> 8)] << 8) | sbox[t & 0xff];
            t ^= rcon;
            rc = (rc << 1) ^ (rc >= 0x80 ? 0x1b : 0);
        }
        else if (n > 6 && i % n == 4)
            t = (sbox[((exp_key[i-1] & 0xff000000) >> 24)] << 24) | (sbox[((exp_key[i-1] & 0xff0000) >> 16)] << 16) | (sbox[((exp_key[i-1] & 0xff00) >> 8)] << 8) | sbox[exp_key[i-1] & 0xff];
        exp_key[i] = exp_key[i - n] ^ t;
    }

    // final round
    // addroundkey
    for (u32 i = 0; i < 16; ++i)
        (*plaintext)[i] = ciphertext[i] ^ ((u8*)exp_key)[(r - 1) * 16 + i];
    // inv_shiftrows
    u8 temp[16];
    memcpy(temp, (*plaintext), 16);
    for (u32 j = 0; j < 16; ++j) {
        (*plaintext)[j] = temp[(16 - j * 3) % 16];
    }
    // inv_subbytes
    for (u32 j = 0; j < 16; ++j) {
        (*plaintext)[j] = inv_sbox[(*plaintext)[j]];
    }

    // main rounds
    for (i32 i = r - 3; i >= 0; --i) {
        // addroundkey
        for (u32 j = 0; j < 16; ++j)
            (*plaintext)[j] ^= ((u8*)exp_key)[(i + 1) * 16 + j];

        // inv_mixcolumns (TODO: very inefficient. optimize (lookup table))
        for (u32 j = 0; j < 4; ++j) {
            u8 *r = (*plaintext) + j * 4;
            u8 a[4];
            memcpy(a, r, 4);
            r[0] = gf_mul(a[0], 14) ^ gf_mul(a[1], 11) ^ gf_mul(a[2], 13) ^ gf_mul(a[3], 9);
            r[1] = gf_mul(a[0], 9) ^ gf_mul(a[1], 14) ^ gf_mul(a[2], 11) ^ gf_mul(a[3], 13);
            r[2] = gf_mul(a[0], 13) ^ gf_mul(a[1], 9) ^ gf_mul(a[2], 14) ^ gf_mul(a[3], 11);
            r[3] = gf_mul(a[0], 11) ^ gf_mul(a[1], 13) ^ gf_mul(a[2], 9) ^ gf_mul(a[3], 14);
        }
        // inv_shiftrows
        u8 temp1[16];
        memcpy(temp1, (*plaintext), 16);
        for (u32 j = 0; j < 16; ++j) {
            (*plaintext)[j] = temp1[(16 - j * 3) % 16];
        }
        // inv_subbytes
        for (u32 j = 0; j < 16; ++j) {
            (*plaintext)[j] = inv_sbox[(*plaintext)[j]];
        }
    }

    // initial round
    for (u32 j = 0; j < 16; ++j)
        (*plaintext)[j] ^= ((u8*)exp_key)[j];

    return CRP_OK;
}

// to decrypt swap ciphertext with plaintext
// keylen: messagelen, ciphertextlen: messagelen
i32 ciph_otp(u8 *plaintext, u32 pt_len, u8 *key, u8 **ciphertext, u32 *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }

    u32 i;
    for (i = 0; i < pt_len; ++i)
        (*ciphertext)[i] = plaintext[i] ^ key[i];
    *ct_len = i;

    return CRP_OK;
}

// to decrypt swap ciphertext with plaintext
// keylen: <1, 256>, cipheretxtlen: messagelen
i32 ciph_rc4(u8 *plaintext, u32 pt_len, u8 *key, u32 key_len, u8 **ciphertext, u32 *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }

    u8 s[256];
    u8 i = 0, j = 0;
    for (i = 0; i < 255; ++i)
        s[i] = i;
    for (i = 0; i < 255; ++i) {
        j = (j + s[i] + key[i % key_len]) % 256;
        u8 temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    u32 k = i = j = 0;
    for (k = 0; k < pt_len; ++k) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        u8 temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        (*ciphertext)[k] = plaintext[k] ^ s[(s[i] + s[j]) % 256];
    }
    *ct_len = k;

    return CRP_OK;
}

int main() {
    u8 pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    u8 key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    u8 *ct = NULL;

    printf("key:\t\t\t");
    hexdump(key, 32);
    printf("\n");

    printf("plaintext:\t\t");
    hexdump(pt, 16);

    enc_aes256(pt, key, &ct);
    printf("ciphertext:\t\t");
    hexdump(ct, 16);

    u8 *pt_t = pt;
    dec_aes256(ct, key, &pt_t);
    printf("decrypted ciphertext:\t");
    hexdump(pt, 16);

    free(ct);
}
