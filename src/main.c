#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "cipher.h"

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
    unsigned char pt[] = "zupa zupa zupa zupa zupa zupa zupa zupa";
    unsigned char key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char *ct = malloc(sizeof(pt) + 16);
    unsigned int ct_len, final_ct_len;

    printf("\n\n\n\nkey:\t\t\t");
    hexdump(key, sizeof(key));
    printf("\n");

    printf("plaintext lenght: %u\n", (unsigned int)sizeof(pt));
    printf("plaintext:\t\t");
    hexdump(pt, sizeof(pt));
    printf("(ascii): %s\n", pt);

    CIPH_CTX ctx;
    encrypt_init(&ctx, rc4(), key, NULL);
    encrypt_update(&ctx, pt, (unsigned int)sizeof(pt) - 7, ct, &ct_len);
    final_ct_len = ct_len;
    encrypt_update(&ctx, pt + (unsigned int)sizeof(pt) - 7, 7, ct + final_ct_len, &ct_len);
    final_ct_len += ct_len;
    encrypt_final(&ctx, ct + final_ct_len, &ct_len);
    final_ct_len += ct_len;

    printf("\n\nciphertext lenght: %u\n", final_ct_len);
    printf("ciphertext:\t\t");
    hexdump(ct, final_ct_len);

    unsigned char *dec_pt = malloc(sizeof(pt));
    int pt_len, final_pt_len;
    decrypt_init(&ctx, rc4(), key, NULL);
    decrypt_update(&ctx, ct, final_ct_len - 13, dec_pt, &pt_len);
    final_pt_len = pt_len;
    decrypt_update(&ctx, ct + final_ct_len - 13, 13, dec_pt + final_pt_len, &pt_len);
    final_pt_len += pt_len;
    decrypt_final(&ctx, dec_pt + final_pt_len, &pt_len);
    final_pt_len += pt_len;
    printf("decrypted ciphertext len: %i\n", final_pt_len);
    printf("decrypted ciphertext:\t");
    hexdump(dec_pt, (unsigned int)final_pt_len);
    printf("(ascii): %s\n", dec_pt);

    //free(ct);
}
