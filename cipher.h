#ifndef CIPHER_H
#define CIPHER_H

#define CRP_OK 1
#define CRP_ERR 0

typedef struct CIPHER {
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
} CIPHER;

typedef struct CIPH_CTX {
    CIPHER ciph;
    unsigned char *state;
    unsigned int queue_size;
    unsigned char *queue_buf;
} CIPH_CTX;


int encrypt_init(CIPH_CTX *ctx, CIPHER cipher, unsigned char *key, unsigned char *iv);
int encrypt_update(CIPH_CTX *ctx, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext, unsigned int *ct_len);
int encrypt_final(CIPH_CTX *ctx, unsigned char *ciphertext, unsigned int *ct_len);

int decrypt_init(CIPH_CTX *ctx, CIPHER cipher, unsigned char *key, unsigned char *iv);
int decrypt_update(CIPH_CTX *ctx, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext, int *pt_len);
int decrypt_final(CIPH_CTX *ctx, unsigned char *plaintext, int *pt_len);

// ciphers
CIPHER ecb_aes256();

#endif // CIPHER_H
