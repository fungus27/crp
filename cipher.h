#ifndef CIPHER_H
#define CIPHER_H

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;

typedef struct CIPHER {
    u32 block_size; // block_size = 0 for stream ciphers
    u32 key_size, iv_size;

    u32 enc_state_size;
    i32 (*enc_state_init)(u8 *key, u8 *iv, u8 *state);
    i32 (*encrypt_update)(u8 *state, u8 *plaintext, u32 pt_len, u8 *ciphertext);
    i32 (*padder)(u8 *block, u32 pt_size, u32 block_size);

    u32 dec_state_size;
    i32 (*dec_state_init)(u8 *key, u8 *iv, u8 *state);
    i32 (*decrypt_update)(u8 *state, u8 *ciphertext, u32 ct_len, u8 *plaintext);
    i32 (*unpadder)(u8 *block, u32 block_size, u32 *cutoff);
} CIPHER;

typedef struct CIPH_CTX {
    CIPHER ciph;
    u8 *state;
    u32 queue_size;
    u8 *queue_buf;
} CIPH_CTX;

#endif // CIPHER_H
