#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <crp/cipher.h>

#include "util.h"
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

// TODO: make some arguments const, rework context, cipher and digest api (make the structs private)
// change project structure, remove redundant returns for errors, reduce duplicate code, add comments, move constants to
// global file scope, clean up code, add tests, make code bulletproof

int main() {
    unsigned char pt[] = "zupa";
    unsigned char key[32] = {0};
    unsigned char ct[32];
    unsigned int ct_len;
    CIPH_CTX *ctx = alloc_ciph_ctx();
    encrypt_init(ctx, ecb_aes256(), key, NULL);
    encrypt_update(ctx, pt, sizeof(pt), ct, &ct_len);
    unsigned int t_ct_len;
    encrypt_final(ctx, ct, &t_ct_len);
    ct_len += t_ct_len;
    printf("ct_len: %u\n", ct_len);
    hexdump(ct, ct_len);

    unsigned char d_pt[32];
    int pt_len;
    decrypt_init(ctx, ecb_aes256(), key, NULL);
    decrypt_update(ctx, ct, ct_len, d_pt, &pt_len);
    int t_pt_len;
    decrypt_final(ctx, d_pt, &t_pt_len);
    pt_len += t_pt_len;
    printf("pt_len: %u\n", pt_len);
    printf("pt: %s", d_pt);
    free_ciph_ctx(ctx);
}
