#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define CRP_ERR -1
#define CRP_OK 0
typedef unsigned char byte;

int basic_rand(byte *out, unsigned int size) {
    FILE *urand = fopen("/dev/urandom", "r");
    if (!urand) {
        printf("cannot open '/dev/urandom/'. %s\n", strerror(errno));
        return CRP_ERR;
    }

    unsigned int seed;
    if(!fread(&seed, sizeof(unsigned int), 1, urand)) {
        printf("couldn't read seed from '/dev/urandom/'.\n");
        return CRP_ERR;
    }
    srand(seed);

    while (size--) {
        byte combine;
        if(!fread(&combine, 1, 1, urand)) {
            printf("couldn't read byte from '/dev/urandom/'.\n");
            return CRP_ERR;
        }
        byte res = (rand() * combine) + 0x1485914;
        res ^= ((rand() * 0x7fbfb + 2) / 3 + seed >> 2);

        out[size] = res;
    }
    return CRP_OK;
}

int main() {
    unsigned int random;
    basic_rand((byte*)&random, sizeof(unsigned int));
    printf("%u\n", random);
}
