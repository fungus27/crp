#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define CRP_ERR 0
#define CRP_OK 1
typedef unsigned char byte;

int rand_bytes(byte *out, unsigned int size) {
    FILE *urand = fopen("/dev/urandom", "r");
    if (!urand) {
        printf("cannot open '/dev/urandom/'. %s\n", strerror(errno));
        fclose(urand);
        return CRP_ERR;
    }

    unsigned int seed;
    if(!fread(&seed, sizeof(unsigned int), 1, urand)) {
        printf("couldn't read seed from '/dev/urandom/'.\n");
        fclose(urand);
        return CRP_ERR;
    }
    srand(seed);

    while (size--) {
        byte combine;
        if(!fread(&combine, 1, 1, urand)) {
            printf("couldn't read byte from '/dev/urandom/'.\n");
            fclose(urand);
            return CRP_ERR;
        }
        byte res = (rand() * combine) + 0x1485914;
        res ^= ((rand() * 0x7fbfb + 2) / 3 + seed >> 2);

        out[size] = res;
    }
    fclose(urand);
    return CRP_OK;
}

// if *ciphertext is NULL, the cipher function mallocs the needed memory which is handed to the user

// to decrypt swap ciphertext with plaintext
// keylen: messagelen, ciphertextlen: messagelen
int ciph_otp(byte *plaintext, unsigned int pt_len, byte *key, byte **ciphertext, unsigned int *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }

    *ct_len = pt_len;
    while (pt_len--)
        (*ciphertext)[pt_len] = plaintext[pt_len] ^ key[pt_len];

    return CRP_OK;
}

int main() {
    byte pt[] = "zupa.";
    byte *key = malloc(sizeof(pt));
    byte *ct = NULL;

    rand_bytes(key, sizeof(pt));
    unsigned int ct_len;
    ciph_otp(pt, sizeof(pt), key, &ct, &ct_len);

    printf("plaintext: %s\n", pt);

    printf("ciphertext (hex): ");
    for (unsigned int i = 0; i < sizeof(pt); ++i)
        printf("%hhx", ct[i]);
    printf("\n");

    byte *dec_ct = NULL;
    unsigned int dec_ct_len;
    ciph_otp(ct, ct_len, key, &dec_ct, &dec_ct_len);

    printf("decrypted ciphertext: %s\n", dec_ct);

    free(dec_ct);
    free(ct);
}
