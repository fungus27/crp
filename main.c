#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define CRP_ERR 0
#define CRP_OK 1

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;
typedef int i32;

#define LEFTROTATE32(n, d) ( ( (n) << (d) ) | ( (n) >> (32 - (d)) ) )

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

// if *ciphertext is NULL, the cipher function mallocs the needed memory which is handed to the user

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

i32 main() {
    u8 pt[5] = "zupa.";
    u8 *digest = NULL;
    hash_md5(pt, 5, &digest);
    printf("digest: ");
    hexdump(digest, 16);
    free(digest);
}
