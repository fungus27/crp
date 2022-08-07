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

    unsigned int i;
    for (i = 0; i < pt_len; ++i)
        (*ciphertext)[i] = plaintext[i] ^ key[i];
    *ct_len = i;

    return CRP_OK;
}

// to decrypt swap ciphertext with plaintext
// keylen: <1, 256>, cipheretxtlen: messagelen
int ciph_rc4(byte *plaintext, unsigned int pt_len, byte *key, unsigned int key_len, byte **ciphertext, unsigned int *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }
    
    byte s[256];
    byte i = 0, j = 0;
    for (i = 0; i < 255; ++i)
        s[i] = i;
    for (i = 0; i < 255; ++i) {
        j = (j + s[i] + key[i % key_len]) % 256;
        byte temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    unsigned int k = i = j = 0;
    for (k = 0; k < pt_len; ++k) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        byte temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        (*ciphertext)[k] = plaintext[k] ^ s[(s[i] + s[j]) % 256];
    }
    *ct_len = k;

    return CRP_OK;
}

int main() {
    byte pt[] = "zupa.";
    byte *key = malloc(32);
    byte *ct = NULL;

    rand_bytes(key, 32);
    unsigned int ct_len;
    ciph_rc4(pt, sizeof(pt), key, 32, &ct, &ct_len);

    printf("plaintext: %s\n", pt);

    printf("ciphertext (hex): ");
    for (unsigned int i = 0; i < sizeof(pt); ++i)
        printf("%hhx", ct[i]);
    printf("\n");

    byte *dec_ct = NULL;
    unsigned int dec_ct_len;
    ciph_rc4(ct, ct_len, key, 32, &dec_ct, &dec_ct_len);

    printf("decrypted ciphertext: %s\n", dec_ct);

    free(key);
    free(dec_ct);
    free(ct);
}
