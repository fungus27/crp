#ifndef CIPHER_H
#define CIPHER_H

typedef struct cipher CIPHER;
typedef struct cipher_context CIPH_CTX;

CIPH_CTX *alloc_ciph_ctx();
void free_ciph_ctx(CIPH_CTX *ptr);

int encrypt_init(CIPH_CTX *ctx, CIPHER *cipher, unsigned char *key, unsigned char *iv);
int encrypt_update(CIPH_CTX *ctx, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext, unsigned int *ct_len);
int encrypt_final(CIPH_CTX *ctx, unsigned char *ciphertext, unsigned int *ct_len);

int decrypt_init(CIPH_CTX *ctx, CIPHER *cipher, unsigned char *key, unsigned char *iv);
int decrypt_update(CIPH_CTX *ctx, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext, int *pt_len);
int decrypt_final(CIPH_CTX *ctx, unsigned char *plaintext, int *pt_len);

// ciphers
CIPHER *ecb_aes256();
CIPHER *rc4();

#endif // CIPHER_H
