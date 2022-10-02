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

int main() {
    unsigned char pt[] = "zupa";
    unsigned char md[32];
    unsigned int md_len;
    MD_CTX *ctx = alloc_md_ctx();

    digest_init(ctx, sha256());
    digest_update(ctx, pt, sizeof(pt) - 1);
    digest_final(ctx, md, &md_len);

    free_md_ctx(ctx);
}
