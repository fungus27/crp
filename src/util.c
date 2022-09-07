#include <string.h>
#include "util.h"

int pad_pkcs(unsigned char *block, unsigned int pt_size, unsigned int block_size) {
    memset(block + pt_size, block_size - pt_size, block_size - pt_size);
    return 1;
}

int unpad_pkcs(unsigned char *block, unsigned int block_size, unsigned int *cutoff) {
    *cutoff = block[block_size - 1];
    return 1;
}
