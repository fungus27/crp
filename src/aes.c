#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cipher.h"
#include "util.h"

static unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char prod = 0;
    for (unsigned int k = 0; k < 8; ++k) {
        prod ^= (b & 1) ? a : 0;
        b >>= 1;
        unsigned char carry = a & 0x80;
        a <<= 1;
        a ^= carry ? 0x1b : 0;
    }
    return prod;
}

static int block_init_enc_aes(unsigned char *key, unsigned int r, unsigned int n, unsigned char *state) {
    // sbox generation by bruteforce (TODO: implement more efficient way of generation or just hardcode the table in)
    unsigned char *sbox = state;
    for (unsigned int i = 0; i < 256; ++i) {
        for (unsigned int j = 0; j < 256; ++j) {
            unsigned char prod = gf_mul((unsigned char)i, (unsigned char)j);
            if (prod == 1) {
                unsigned char t = j;
                t ^= LEFTROTATE8(t, 1) ^ LEFTROTATE8(t, 2) ^ LEFTROTATE8(t, 3) ^ LEFTROTATE8(t, 4) ^ 0x63;
                sbox[i] = t;
                break;
            }
        }
    }
    sbox[0] = 0x63;

    // key expansion
    unsigned char rc = 1;
    uint32_t *exp_key = (uint32_t*)(state + 256);
    memcpy(exp_key, key, n * 4);
    for (unsigned int i = n; i < r * 4; ++i) {
        uint32_t t = exp_key[i - 1];
        if (i % n == 0) {
            uint32_t rcon = rc;
            t = RIGHTROTATE32(exp_key[i - 1], 8);
            t = (sbox[((t & 0xff000000) >> 24)] << 24) | (sbox[((t & 0xff0000) >> 16)] << 16) | (sbox[((t & 0xff00) >> 8)] << 8) | sbox[t & 0xff];
            t ^= rcon;
            rc = (rc << 1) ^ (rc >= 0x80 ? 0x1b : 0);
        }
        else if (n > 6 && i % n == 4)
            t = (sbox[((exp_key[i-1] & 0xff000000) >> 24)] << 24) | (sbox[((exp_key[i-1] & 0xff0000) >> 16)] << 16) | (sbox[((exp_key[i-1] & 0xff00) >> 8)] << 8) | sbox[exp_key[i-1] & 0xff];
        exp_key[i] = exp_key[i - n] ^ t;
    }

    return 1;
}

// TODO: get rid of this function by hardcoding the sbox and inv_sbox
static int block_init_dec_aes(unsigned char *key, unsigned int r, unsigned int n, unsigned char *state) {
    // sbox and inv_sbox generation by bruteforce
    unsigned char sbox[256];
    unsigned char *inv_sbox = state;
    for (unsigned int i = 0; i < 256; ++i) {
        for (unsigned int j = 0; j < 256; ++j) {
            unsigned char prod = gf_mul((unsigned char)i, (unsigned char)j);
            if (prod == 1) {
                unsigned char t = j;
                t ^= LEFTROTATE8(t, 1) ^ LEFTROTATE8(t, 2) ^ LEFTROTATE8(t, 3) ^ LEFTROTATE8(t, 4) ^ 0x63;
                sbox[i] = t;
                inv_sbox[t] = i;
                break;
            }
        }
    }
    sbox[0] = 0x63;
    inv_sbox[0x63] = 0;

    // key expansion
    unsigned char rc = 1;
    uint32_t *exp_key = (uint32_t*)(state + 256);
    memcpy(exp_key, key, n * 4);
    for (unsigned int i = n; i < r * 4; ++i) {
        uint32_t t = exp_key[i - 1];
        if (i % n == 0) {
            uint32_t rcon = rc;
            t = RIGHTROTATE32(exp_key[i - 1], 8);
            t = (sbox[((t & 0xff000000) >> 24)] << 24) | (sbox[((t & 0xff0000) >> 16)] << 16) | (sbox[((t & 0xff00) >> 8)] << 8) | sbox[t & 0xff];
            t ^= rcon;
            rc = (rc << 1) ^ (rc >= 0x80 ? 0x1b : 0);
        }
        else if (n > 6 && i % n == 4)
            t = (sbox[((exp_key[i-1] & 0xff000000) >> 24)] << 24) | (sbox[((exp_key[i-1] & 0xff0000) >> 16)] << 16) | (sbox[((exp_key[i-1] & 0xff00) >> 8)] << 8) | sbox[exp_key[i-1] & 0xff];
        exp_key[i] = exp_key[i - n] ^ t;
    }

    return 1;
}

// single block aes256 encryption (TODO: optimize)
static int block_enc_aes(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *exp_key, unsigned char *sbox, unsigned int r, unsigned int n) {
    // initial round
    for (unsigned int i = 0; i < 16; ++i)
        ciphertext[i] = plaintext[i] ^ ((unsigned char*)exp_key)[i];

    // main rounds
    for (unsigned int i = 0; i < r - 2; ++i) {
        // subbytes
        for (unsigned int j = 0; j < 16; ++j) {
            ciphertext[j] = sbox[ciphertext[j]];
        }
        // shiftrows
        unsigned char temp[16];
        memcpy(temp, ciphertext, 16);
        for (unsigned int j = 0; j < 16; ++j) {
            ciphertext[j] = temp[(j * 5) % 16];
        }
        // mixcolumns
        for (unsigned int j = 0; j < 4; ++j) {
            unsigned char *r = ciphertext + j * 4;
            unsigned char a[4];
            unsigned char b[4];
            unsigned char h;
            for (unsigned char c = 0; c < 4; ++c) {
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
        for (unsigned int j = 0; j < 16; ++j)
            ciphertext[j] ^= ((unsigned char*)exp_key)[(i + 1) * 16 + j];
    }

    // final round
    // subbytes
    for (unsigned int j = 0; j < 16; ++j) {
        ciphertext[j] = sbox[ciphertext[j]];
    }
    // shiftrows
    unsigned char temp[16];
    memcpy(temp, ciphertext, 16);
    for (unsigned int j = 0; j < 16; ++j) {
        ciphertext[j] = temp[(j * 5) % 16];
    }
    // addroundkey
    for (unsigned int j = 0; j < 16; ++j)
        ciphertext[j] ^= ((unsigned char*)exp_key)[(r - 1) * 16 + j];

    return 1;
}

// single block aes256 decryption (TODO: optimize)
static int block_dec_aes(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *exp_key, unsigned char *inv_sbox, unsigned int r, unsigned int n) {
    // final round
    // addroundkey
    for (unsigned int i = 0; i < 16; ++i)
        plaintext[i] = ciphertext[i] ^ ((unsigned char*)exp_key)[(r - 1) * 16 + i];
    // inv_shiftrows
    unsigned char temp[16];
    memcpy(temp, plaintext, 16);
    for (unsigned int j = 0; j < 16; ++j) {
        plaintext[j] = temp[(16 - j * 3) % 16];
    }
    // inv_subbytes
    for (unsigned int j = 0; j < 16; ++j) {
        plaintext[j] = inv_sbox[plaintext[j]];
    }

    // main rounds
    for (int i = r - 3; i >= 0; --i) {
        // addroundkey
        for (unsigned int j = 0; j < 16; ++j)
            plaintext[j] ^= ((unsigned char*)exp_key)[(i + 1) * 16 + j];
        // inv_mixcolumns (TODO: very inefficient. optimize (lookup table))
        for (unsigned int j = 0; j < 4; ++j) {
            unsigned char *r = plaintext + j * 4;
            unsigned char a[4];
            memcpy(a, r, 4);
            r[0] = gf_mul(a[0], 14) ^ gf_mul(a[1], 11) ^ gf_mul(a[2], 13) ^ gf_mul(a[3], 9);
            r[1] = gf_mul(a[0], 9) ^ gf_mul(a[1], 14) ^ gf_mul(a[2], 11) ^ gf_mul(a[3], 13);
            r[2] = gf_mul(a[0], 13) ^ gf_mul(a[1], 9) ^ gf_mul(a[2], 14) ^ gf_mul(a[3], 11);
            r[3] = gf_mul(a[0], 11) ^ gf_mul(a[1], 13) ^ gf_mul(a[2], 9) ^ gf_mul(a[3], 14);
        }
        // inv_shiftrows
        unsigned char temp1[16];
        memcpy(temp1, plaintext, 16);
        for (unsigned int j = 0; j < 16; ++j) {
            plaintext[j] = temp1[(16 - j * 3) % 16];
        }
        // inv_subbytes
        for (unsigned int j = 0; j < 16; ++j) {
            plaintext[j] = inv_sbox[plaintext[j]];
        }
    }

    // initial round
    for (unsigned int j = 0; j < 16; ++j)
        plaintext[j] ^= ((unsigned char*)exp_key)[j];

    return 1;
}

static int enc_ecb_aes256_init(unsigned char *key, unsigned char *iv, unsigned char *state) {
    return block_init_enc_aes(key, 15, 8, state);
}

static int dec_ecb_aes256_init(unsigned char *key, unsigned char *iv, unsigned char *state) {
    return block_init_dec_aes(key, 15, 8, state);
}

static int enc_ecb_aes256_update(unsigned char *state, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext) {
    return block_enc_aes(plaintext, ciphertext, state + 256, state, 15, 8);
}

static int dec_ecb_aes256_update(unsigned char *state, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext) {
    return block_dec_aes(ciphertext, plaintext, state + 256, state, 15, 8);
}

CIPHER ecb_aes256() {
    CIPHER ciph = {
        .block_size = 16,
        .key_size = 32, .iv_size = 0,

        .enc_state_size = 496,
        .enc_state_init = enc_ecb_aes256_init,
        .encrypt_update = enc_ecb_aes256_update,
        .padder = util_pad_pkcs,

        .dec_state_size = 496,
        .dec_state_init = dec_ecb_aes256_init,
        .decrypt_update = dec_ecb_aes256_update,
        .unpadder = util_unpad_pkcs,
    };
    return ciph;
}

