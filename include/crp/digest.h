#ifndef DIGEST_H
#define DIGEST_H

typedef struct digest DIGEST;
typedef struct md_context MD_CTX;

MD_CTX *alloc_md_ctx();
void free_md_ctx(MD_CTX *ptr);

int digest_init(MD_CTX *ctx, DIGEST *digest);
int digest_update(MD_CTX *ctx, unsigned char *message, unsigned int m_len);
int digest_final(MD_CTX *ctx, unsigned char *md, unsigned int *md_len);

// TODO: break up code into the core hash functions and general structures (like the merkle-damgard construction)
DIGEST *md5();
DIGEST *sha1();
DIGEST *sha256();
DIGEST *sha224();
DIGEST *sha512();
DIGEST *sha384();
DIGEST *sha512_256();
DIGEST *sha512_224();

#endif // DIGEST_H
