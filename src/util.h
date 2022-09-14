#ifndef UTIL_H
#define UTIL_H

#define MAX(a, b) ( ((a) > (b)) ? (a) : (b) )
#define MIN(a, b) ( ((a) < (b)) ? (a) : (b) )

#define LEFTROTATE8(n, d) ( ( (n) << (d) ) | ( (n) >> (8 - (d)) ) )
#define RIGHTROTATE8(n, d) ( ( (n) >> (d) ) | ( (n) << (8 - (d)) ) )

#define LEFTROTATE32(n, d) ( ( (n) << (d) ) | ( (n) >> (32 - (d)) ) )
#define RIGHTROTATE32(n, d) ( ( (n) >> (d) ) | ( (n) << (32 - (d)) ) )
#define SWAPENDIAN32(n) ( ( ( (n) & 0xff ) << 24 ) | ( ( (n) & 0xff00 ) << 8 ) | ( ( (n) & 0xff0000 ) >> 8 ) | ( ( (n) & 0xff000000 ) >> 24 ) )

#define LEFTROTATE64(n, d) ( ( (n) << (d) ) | ( (n) >> (64 - (d)) ) )
#define RIGHTROTATE64(n, d) ( ( (n) >> (d) ) | ( (n) << (64 - (d)) ) )
#define SWAPENDIAN64(n) ( ( ( (n) & 0xff ) << 56 ) | ( ( (n) & 0xff00 ) << 40 ) | ( ( (n) & 0xff0000 ) << 24 ) | ( ( (n) & 0xff000000 ) << 8 ) \
        | ( ( (n) & 0xff00000000 ) >> 8 ) | ( ( (n) & 0xff0000000000 ) >> 24 ) | ( ( (n) & 0xff000000000000 ) >> 40) | ( ( (n) & 0xff00000000000000 ) >> 56 ) )

int util_pad_pkcs(unsigned char *block, unsigned int pt_size, unsigned int block_size);
int util_unpad_pkcs(unsigned char *block, unsigned int block_size, unsigned int *cutoff);

#endif // UTIL_H
