#ifndef CIPHER_H
#define CIPHER_H

typedef struct sym_cipher SYM_CIPH;
typedef struct sym_cipher_context SYM_CTX;

SYM_CTX *alloc_sym_ctx();
void free_sym_ctx(SYM_CTX *ptr);

int encrypt_init(SYM_CTX *ctx, SYM_CIPH *cipher, unsigned char *key, unsigned char *iv);
int encrypt_update(SYM_CTX *ctx, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext, unsigned int *ct_len);
int encrypt_final(SYM_CTX *ctx, unsigned char *ciphertext, unsigned int *ct_len);

int decrypt_init(SYM_CTX *ctx, SYM_CIPH *cipher, unsigned char *key, unsigned char *iv);
int decrypt_update(SYM_CTX *ctx, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext, int *pt_len);
int decrypt_final(SYM_CTX *ctx, unsigned char *plaintext, int *pt_len);

// ciphers
SYM_CIPH *ecb_aes256();
SYM_CIPH *rc4();

#endif // CIPHER_H
