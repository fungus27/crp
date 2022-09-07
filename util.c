#include <string.h>
#include "util.h"

#define CRP_OK 1
#define CRP_ERR 0

int pad_pkcs(unsigned char *block, unsigned int pt_size, unsigned int block_size) {
    memset(block + pt_size, block_size - pt_size, block_size - pt_size);
    return CRP_OK;
}

int unpad_pkcs(unsigned char *block, unsigned int block_size, unsigned int *cutoff) {
    *cutoff = block[block_size - 1];
    return CRP_OK;
}
