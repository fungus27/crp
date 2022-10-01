#ifndef CIPHER_INT_H
#define CIPHER_INT_H

#include <crp/sym.h>

struct sym_cipher {
    unsigned int block_size; // block_size = 0 for stream ciphers
    unsigned int key_size, iv_size;

    unsigned int enc_state_size;
    int (*enc_state_init)(unsigned char *key, unsigned char *iv, unsigned char *state);
    int (*encrypt_update)(unsigned char *state, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext);
    int (*padder)(unsigned char *block, unsigned int pt_size, unsigned int block_size);

    unsigned int dec_state_size;
    int (*dec_state_init)(unsigned char *key, unsigned char *iv, unsigned char *state);
    int (*decrypt_update)(unsigned char *state, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext);
    int (*unpadder)(unsigned char *block, unsigned int block_size, unsigned int *cutoff);
}; /* SYM_CIPH */

struct sym_cipher_context {
    SYM_CIPH *ciph;
    unsigned char *state;
    unsigned int queue_size;
    unsigned char *queue_buf;
}; /* SYM_CTX */

#endif // CIPHER_INT_H
