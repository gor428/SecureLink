#include "crypto.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    const unsigned char key[SL_AES_KEY_LEN] = {0};
    const unsigned char nonce[SL_GCM_NONCE_LEN] = {1};
    const unsigned char aad[] = "SecureLink test AAD";
    const unsigned char message[] = "Confidential TCP payload";
    unsigned char ciphertext[sizeof(message)];
    unsigned char recovered[sizeof(message)];
    unsigned char tag[SL_GCM_TAG_LEN];

    if (!sl_aes_gcm_encrypt(key, nonce, aad, sizeof(aad) - 1,
                            message, sizeof(message), ciphertext, tag)) {
        fprintf(stderr, "encrypt failed\n");
        return 1;
    }

    if (!sl_aes_gcm_decrypt(key, nonce, aad, sizeof(aad) - 1,
                            ciphertext, sizeof(ciphertext), tag, recovered)) {
        fprintf(stderr, "decrypt failed\n");
        return 1;
    }

    if (memcmp(message, recovered, sizeof(message)) != 0) {
        fprintf(stderr, "round-trip mismatch\n");
        return 1;
    }

    tag[0] ^= 0x01;
    if (sl_aes_gcm_decrypt(key, nonce, aad, sizeof(aad) - 1,
                           ciphertext, sizeof(ciphertext), tag, recovered)) {
        fprintf(stderr, "tampered tag was incorrectly accepted\n");
        return 1;
    }

    puts("PASS: AES-256-GCM round-trip and tamper rejection");
    return 0;
}
