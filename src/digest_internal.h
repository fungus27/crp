#ifndef DIGEST_INT_H
#define DIGEST_INT_H

#include <crp/digest.h>

struct digest {
    unsigned int digest_size;
    unsigned int block_size;
    unsigned int state_size;

    int (*state_init)(unsigned char *state);
    int (*update)(unsigned char *state, unsigned char *message, unsigned int m_len);
    int (*final)(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md);
}; /* DIGEST */

struct md_context {
    DIGEST *digest;
    unsigned char *state;
    unsigned int queue_size;
    unsigned char *queue_buf;
}; /* MD_CTX */

#endif // DIGEST_INT_H
