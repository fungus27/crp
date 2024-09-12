#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <crp/sym.h>
#include <crp/digest.h>

// TODO: make some arguments const,
// remove redundant returns for errors, reduce duplicate code, add comments, move constants to
// global file scope, clean up code, add tests, make code bulletproof

void hex_print(unsigned char *in, unsigned int len) {
    for (unsigned int i = 0; i < len; ++i)
        printf("%.2hhx", in[i]);
    printf("\n");
}

int main() {
    unsigned char pt[] = "zupa";
    printf("Plaintext: %s\n", pt);
    unsigned char md[32];
    unsigned int md_len;
    MD_CTX *d_ctx = alloc_md_ctx();

    digest_init(d_ctx, sha256());
    digest_update(d_ctx, pt, sizeof(pt) - 1);
    digest_final(d_ctx, md, &md_len);
    free_md_ctx(d_ctx);

    printf("SHA256: ");
    hex_print(md, md_len);


    unsigned char key[32] = "01234567890123456789012345678912";
    unsigned char iv[16] = "zupazupazupazupa";
    unsigned char *ct = malloc(sizeof(pt - 1) + 16);
    unsigned int ct_len;
    SYM_CTX *s_ctx = alloc_sym_ctx();

    encrypt_init(s_ctx, ecb_aes256(), key, iv);
    encrypt_update(s_ctx, pt, sizeof(pt) - 1, ct, &ct_len);
    encrypt_final(s_ctx, ct, &ct_len);

    printf("AES with key %.32s and iv %.16s: ", key, iv);
    hex_print(ct, ct_len);

    unsigned char *r_pt = malloc(ct_len);
    int r_pt_len;
    decrypt_init(s_ctx, ecb_aes256(), key, iv);
    decrypt_update(s_ctx, ct, ct_len, r_pt, &r_pt_len);
    decrypt_final(s_ctx, r_pt, &r_pt_len);

    printf("Decrypted ciphertext: %.*s\n", r_pt_len, r_pt);

    free(ct);
    free(r_pt);
    free_sym_ctx(s_ctx);
}
