#ifndef SECURELINK_CRYPTO_H
#define SECURELINK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SL_AES_KEY_LEN 32
#define SL_GCM_NONCE_LEN 12
#define SL_GCM_TAG_LEN 16

int sl_aes_gcm_encrypt(const uint8_t key[SL_AES_KEY_LEN],
                       const uint8_t nonce[SL_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext,
                       uint8_t tag[SL_GCM_TAG_LEN]);

int sl_aes_gcm_decrypt(const uint8_t key[SL_AES_KEY_LEN],
                       const uint8_t nonce[SL_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[SL_GCM_TAG_LEN],
                       uint8_t *plaintext);

#endif
