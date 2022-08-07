#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define CRP_ERR 0
#define CRP_OK 1

typedef unsigned char u8;
typedef unsigned int u32;
typedef int i32;

void hexdump(u8 *in, u32 len) {
    for (u32 i = 0; i < len; ++i)
        printf("%hhx", in[i]);
    printf("\n");
}

i32 rand_bytes(u8 *out, u32 size) {
    FILE *urand = fopen("/dev/urandom", "r");
    if (!urand) {
        printf("cannot open '/dev/urandom/'. %s\n", strerror(errno));
        fclose(urand);
        return CRP_ERR;
    }

    u32 seed;
    if(!fread(&seed, sizeof(u32), 1, urand)) {
        printf("couldn't read seed from '/dev/urandom/'.\n");
        fclose(urand);
        return CRP_ERR;
    }
    srand(seed);

    while (size--) {
        u8 combine;
        if(!fread(&combine, 1, 1, urand)) {
            printf("couldn't read byte from '/dev/urandom/'.\n");
            fclose(urand);
            return CRP_ERR;
        }
        u8 res = (rand() * combine) + 0x1485914;
        res ^= ((rand() * 0x7fbfb + 2) / 3 + seed >> 2);

        out[size] = res;
    }
    fclose(urand);
    return CRP_OK;
}

// if *ciphertext is NULL, the cipher function mallocs the needed memory which is handed to the user

// to decrypt swap ciphertext with plaintext
// keylen: messagelen, ciphertextlen: messagelen
i32 ciph_otp(u8 *plaintext, u32 pt_len, u8 *key, u8 **ciphertext, u32 *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }

    u32 i;
    for (i = 0; i < pt_len; ++i)
        (*ciphertext)[i] = plaintext[i] ^ key[i];
    *ct_len = i;

    return CRP_OK;
}

// to decrypt swap ciphertext with plaintext
// keylen: <1, 256>, cipheretxtlen: messagelen
i32 ciph_rc4(u8 *plaintext, u32 pt_len, u8 *key, u32 key_len, u8 **ciphertext, u32 *ct_len) {
    if (!*ciphertext) {
        *ciphertext = malloc(pt_len);
        if (!*ciphertext)
            return CRP_ERR;
    }
    
    u8 s[256];
    u8 i = 0, j = 0;
    for (i = 0; i < 255; ++i)
        s[i] = i;
    for (i = 0; i < 255; ++i) {
        j = (j + s[i] + key[i % key_len]) % 256;
        u8 temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    u32 k = i = j = 0;
    for (k = 0; k < pt_len; ++k) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        u8 temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        (*ciphertext)[k] = plaintext[k] ^ s[(s[i] + s[j]) % 256];
    }
    *ct_len = k;

    return CRP_OK;
}

i32 main() {
    u8 pt[] = "zupa.";
    u8 *key = malloc(32);
    u8 *ct = NULL;

    rand_bytes(key, 32);
    u32 ct_len;
    ciph_rc4(pt, sizeof(pt), key, 32, &ct, &ct_len);

    printf("plaintext: %s\n", pt);

    printf("ciphertext (hex): ");
    hexdump(ct, ct_len);

    u8 *dec_ct = NULL;
    u32 dec_ct_len;
    ciph_rc4(ct, ct_len, key, 32, &dec_ct, &dec_ct_len);

    printf("decrypted ciphertext: %s\n", dec_ct);

    free(key);
    free(dec_ct);
    free(ct);
}
