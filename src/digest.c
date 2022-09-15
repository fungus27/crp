#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "digest.h"
#include "util.h"

int digest_init(MD_CTX *ctx, DIGEST digest) {
    ctx->digest = digest;
    ctx->state = NULL;
    if (digest.state_size) {
        ctx->state = malloc(digest.state_size);
        if (!ctx->state)
            return 0;
    }
    ctx->queue_buf = NULL;
    if (digest.block_size) {
        ctx->queue_buf = malloc(digest.block_size);
        if (!ctx->queue_buf)
            return 0;
    }
    ctx->queue_size = 0;
    return digest.state_init(ctx->state);
}

int digest_update(MD_CTX *ctx, unsigned char *message, unsigned int m_len) {
    if (ctx->digest.block_size) {
        while (m_len >= ctx->digest.block_size) {
            memcpy(ctx->queue_buf + ctx->queue_size, message, ctx->digest.block_size - ctx->queue_size);
            if (!ctx->digest.update(ctx->state, ctx->queue_buf, ctx->digest.block_size))
                    return 0;
            message += ctx->digest.block_size - ctx->queue_size;
            m_len -= ctx->digest.block_size - ctx->queue_size;
            ctx->queue_size = 0;
        }
        memcpy(ctx->queue_buf + ctx->queue_size, message, m_len);
        ctx->queue_size += m_len;
    }
    else {
        if (!ctx->digest.update(ctx->state, message, m_len))
            return 0;
    }
    return 1;
}

int digest_final(MD_CTX *ctx, unsigned char *md, unsigned int *md_len) {
    if (!ctx->digest.final(ctx->state, ctx->queue_buf, ctx->queue_size, md))
        return 0;
    if (ctx->state)
        free(ctx->state);
    if (ctx->queue_buf)
        free(ctx->queue_buf);
    *md_len = ctx->digest.digest_size;
    return 1;
}
