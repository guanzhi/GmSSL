#ifndef HEADER_SIMON_H
#define HEADER_SIMON_H

#ifndef CIPHER_CONSTANTS
#define CIPHER_CONSTANTS
enum mode_t { ECB, CTR, CBC, CFB, OFB };
#endif

#include <stdint.h>

enum simon_cipher_config_t { simon_64_32,
                       simon_72_48,
                       simon_96_48,
                       simon_96_64,
                       simon_128_64,
                       simon_96_96,
                       simon_144_96,
                       simon_128_128,
                       simon_192_128,
                       simon_256_128
}; 

typedef struct {
  enum simon_cipher_config_t cipher_cfg;
  uint8_t key_size;
  uint8_t block_size;
  uint8_t round_limit;
  uint8_t init_vector[16];
  uint8_t counter[16];  
  uint8_t key_schedule[576];
  uint8_t z_seq;
} simon_cipher;

typedef struct _bword_24{
  uint32_t data: 24;
} bword_24;

typedef struct _bword_48{
  uint64_t data: 48;
} bword_48;


#ifdef __cplusplus
extern "C"{
#endif
    uint8_t simon_init(simon_cipher *cipher_object, enum simon_cipher_config_t cipher_cfg, enum mode_t c_mode, void *key, uint8_t *iv, uint8_t *counter);
    uint8_t simon_encrypt(simon_cipher cipher_object, void *plaintext, void *ciphertext);
    uint8_t simon_decrypt(simon_cipher cipher_object, void *ciphertext, void *plaintext);
    
    void simon_encrypt32(uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
    void simon_encrypt48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
    void simon_encrypt64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
    void simon_encrypt96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);
    void simon_encrypt128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *plaintext, uint8_t *ciphertext);


    void simon_decrypt32(uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
    void simon_decrypt48(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
    void simon_decrypt64(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
    void simon_decrypt96(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
    void simon_decrypt128(uint8_t round_limit, uint8_t *key_schedule, uint8_t *ciphertext, uint8_t *plaintext);
#ifdef __cplusplus
}
#endif


#endif
