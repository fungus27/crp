#include <stdlib.h>
#include <string.h>

#include <crp/sym.h>
#include "sym_internal.h"

SYM_CTX *alloc_sym_ctx() {
    return malloc(sizeof(SYM_CTX));
}

void free_sym_ctx(SYM_CTX *ptr) {
    free(ptr);
}

int encrypt_init(SYM_CTX *ctx, SYM_CIPH *cipher, unsigned char *key, unsigned char *iv) {
    ctx->ciph = cipher;
    ctx->state = NULL;
    if (cipher->enc_state_size) {
        ctx->state = malloc(cipher->enc_state_size);
        if (!ctx->state)
            return 0;
    }
    ctx->queue_buf = NULL;
    if (cipher->block_size) {
        ctx->queue_buf = malloc(cipher->block_size);
        if (!ctx->queue_buf)
            return 0;
    }
    ctx->queue_size = 0;
    return cipher->enc_state_init(key, iv, ctx->state);
}

int encrypt_update(SYM_CTX *ctx, unsigned char *plaintext, unsigned int pt_len, unsigned char *ciphertext, unsigned int *ct_len) {
    *ct_len = 0;
    if (ctx->ciph->block_size) {
        while (pt_len >= ctx->ciph->block_size) {
            memcpy(ctx->queue_buf + ctx->queue_size, plaintext, ctx->ciph->block_size - ctx->queue_size);
            if (!ctx->ciph->encrypt_update(ctx->state, ctx->queue_buf, ctx->ciph->block_size, ciphertext))
                    return 0;
            plaintext += ctx->ciph->block_size - ctx->queue_size;
            pt_len -= ctx->ciph->block_size - ctx->queue_size;
            ciphertext += ctx->ciph->block_size;
            *ct_len += ctx->ciph->block_size;
            ctx->queue_size = 0;
        }
        memcpy(ctx->queue_buf + ctx->queue_size, plaintext, pt_len);
        ctx->queue_size += pt_len;
    }
    else {
        if (!ctx->ciph->encrypt_update(ctx->state, plaintext, pt_len, ciphertext))
            return 0;
        *ct_len = pt_len;
    }
    return 1;
}

int encrypt_final(SYM_CTX *ctx, unsigned char *ciphertext, unsigned int *ct_len) {
    if (ctx->ciph->padder)
        if (!ctx->ciph->padder(ctx->queue_buf, ctx->queue_size, ctx->ciph->block_size))
            return 0;
    if (ctx->queue_buf) {
        if (!ctx->ciph->encrypt_update(ctx->state, ctx->queue_buf, ctx->ciph->block_size, ciphertext))
            return 0;
        free(ctx->queue_buf);
    }
    *ct_len = ctx->ciph->block_size;
    if (ctx->state)
        free(ctx->state);
    return 1;
}

int decrypt_init(SYM_CTX *ctx, SYM_CIPH *cipher, unsigned char *key, unsigned char *iv) {
    ctx->ciph = cipher;
    ctx->state = NULL;
    if (cipher->dec_state_size) {
        ctx->state = malloc(cipher->dec_state_size);
        if (!ctx->state)
            return 0;
    }
    ctx->queue_buf = NULL;
    if (cipher->block_size) {
        ctx->queue_buf = malloc(cipher->block_size);
        if (!ctx->queue_buf)
            return 0;
    }
    ctx->queue_size = 0;
    return cipher->dec_state_init(key, iv, ctx->state);
}

int decrypt_update(SYM_CTX *ctx, unsigned char *ciphertext, unsigned int ct_len, unsigned char *plaintext, int *pt_len) {
    *pt_len = 0;
    if (ctx->ciph->block_size) {
        while (ct_len > ctx->ciph->block_size) {
            memcpy(ctx->queue_buf + ctx->queue_size, ciphertext, ctx->ciph->block_size - ctx->queue_size);
            if (!ctx->ciph->decrypt_update(ctx->state, ctx->queue_buf, ctx->ciph->block_size, plaintext))
                    return 0;
            ciphertext += ctx->ciph->block_size - ctx->queue_size;
            ct_len -= ctx->ciph->block_size - ctx->queue_size;
            plaintext += ctx->ciph->block_size;
            *pt_len += ctx->ciph->block_size;
            ctx->queue_size = 0;
        }
        memcpy(ctx->queue_buf + ctx->queue_size, ciphertext, ct_len);
        ctx->queue_size += ct_len;
    }
    else {
        if (!ctx->ciph->decrypt_update(ctx->state, ciphertext, ct_len, plaintext))
            return 0;
        *pt_len = ct_len;
    }
    return 1;
}

int decrypt_final(SYM_CTX *ctx, unsigned char *plaintext, int *pt_len) {
    if (ctx->queue_buf) {
        if (!ctx->ciph->decrypt_update(ctx->state, ctx->queue_buf, ctx->ciph->block_size, plaintext))
            return 0;
        free(ctx->queue_buf);
    }
    *pt_len = ctx->ciph->block_size;
    if (ctx->ciph->unpadder) {
        unsigned int cutoff;
        if (!ctx->ciph->unpadder(plaintext, ctx->ciph->block_size, &cutoff))
            return 0;
        *pt_len -= cutoff;
    }
    if (ctx->state)
        free(ctx->state);
    return 1;
}

