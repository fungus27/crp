#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <crp/sym.h>
#include "sym_internal.h"

static int rc4_init(unsigned char *key, unsigned char *iv, unsigned char *state) {
    const unsigned int key_len = 16; // TODO: implement variable key lenght
    unsigned char *s = state;
    unsigned char i = 0, j = 0;
    for (i = 0; i < 255; ++i)
        s[i] = i;
    for (i = 0; i < 255; ++i) {
        j = (j + s[i] + key[i % key_len]) % 256;
        unsigned char temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    memset(state + 256, 0, 8);
    return 1;
}

static int enc_rc4_update(unsigned char *state, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext) {
    unsigned char *s = state;
    uint32_t k;
    uint32_t *i = (uint32_t*)(state + 256), *j = (uint32_t*)(state + 256 + 4);
    for (k = 0; k < pt_len; ++k) {
        *i = (*i + 1) % 256;
        *j = (*j + s[*i]) % 256;

        unsigned char temp = s[*i];
        s[*i] = s[*j];
        s[*j] = temp;

        ciphertext[k] = plaintext[k] ^ s[(s[*i] + s[*j]) % 256];
    }

    return 1;
}

static int dec_rc4_update(unsigned char *state, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext) {
    return enc_rc4_update(state, ciphertext, ct_len, plaintext);
}

static SYM_CIPH ciph_rc4 = {
    .block_size = 0,
    .key_size = 16, .iv_size = 0,

    .enc_state_size = 264,
    .enc_state_init = rc4_init,
    .encrypt_update = enc_rc4_update,
    .padder = NULL,

    .dec_state_size = 264,
    .dec_state_init = rc4_init,
    .decrypt_update = dec_rc4_update,
    .unpadder = NULL,
};

SYM_CIPH *rc4() {
    return &ciph_rc4;
}

