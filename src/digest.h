#ifndef DIGEST_H
#define DIGEST_H

typedef struct DIGEST {
    unsigned int digest_size;
    unsigned int block_size;
    unsigned int state_size;

    int (*state_init)(unsigned char *state);
    int (*update)(unsigned char *state, unsigned char *message, unsigned int m_len);
    int (*final)(unsigned char *state, unsigned char *rest, unsigned int rest_len, unsigned char *md);
} DIGEST;

typedef struct MD_CTX {
    DIGEST digest;
    unsigned char *state;
    unsigned int queue_size;
    unsigned char *queue_buf;
} MD_CTX;

int digest_init(MD_CTX *ctx, DIGEST digest);
int digest_update(MD_CTX *ctx, unsigned char *message, unsigned int m_len);
int digest_final(MD_CTX *ctx, unsigned char *md, unsigned int *md_len);

// TODO: break up code into the core hash functions and general structures (like the merkle-damgard construction)
DIGEST md5();
DIGEST sha1();
DIGEST sha256();
DIGEST sha224();
DIGEST sha512();
DIGEST sha384();
DIGEST sha512_256();
DIGEST sha512_224();

#endif // DIGEST_H
