#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

int util_pad_pkcs(unsigned char *block, unsigned int pt_size, unsigned int block_size) {
    memset(block + pt_size, block_size - pt_size, block_size - pt_size);
    return 1;
}

int util_unpad_pkcs(unsigned char *block, unsigned int block_size, unsigned int *cutoff) {
    *cutoff = block[block_size - 1];
    return 1;
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

void hexdump(unsigned char *in, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i)
        printf("%.2hhx", in[i]);
    printf("\n");
}
