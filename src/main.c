#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "cipher.h"
#include "digest.h"

void hexdump(unsigned char *in, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i)
        printf("%.2hhx", in[i]);
    printf("\n");
}

int rand_bytes(unsigned char *out, unsigned int size) {
    FILE *urand = fopen("/dev/urandom", "r");
    if (!urand) {
        fclose(urand);
        return 0;
    }

    unsigned int seed;
    if(!fread(&seed, sizeof(unsigned int), 1, urand)) {
        fclose(urand);
        return 0;
    }
    srand(seed);

    while (size--) {
        unsigned char combine;
        if(!fread(&combine, 1, 1, urand)) {
            fclose(urand);
            return 0;
        }
        unsigned char res = (rand() * combine) + 0x1485914;
        res ^= ((rand() * 0x7fbfb + 2) / 3 + seed) >> 2;

        out[size] = res;
    }
    fclose(urand);
    return 1;
}

// TODO: make hash api, make some arguments const, rework context api (make it be defined in a source file)

int main() {
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    unsigned char md[16];
    unsigned int md_len;
    MD_CTX ctx;
    digest_init(&ctx, md5());
    digest_update(&ctx, pt, sizeof(pt) - 1 - 7);
    digest_update(&ctx, pt + sizeof(pt) - 1 - 7, 7);
    digest_final(&ctx, md, &md_len);

    printf("md_len: %u\n", md_len);
    hexdump(md, md_len);
}