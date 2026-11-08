#include "crypto.h"

#include <limits.h>
#include <openssl/evp.h>

int sl_aes_gcm_encrypt(const uint8_t key[SL_AES_KEY_LEN],
                       const uint8_t nonce[SL_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *plaintext, size_t plaintext_len,
                       uint8_t *ciphertext,
                       uint8_t tag[SL_GCM_TAG_LEN])
{
    int out_len = 0, total = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    if (!key || !nonce || (!plaintext && plaintext_len) ||
        (!ciphertext && plaintext_len) || !tag ||
        aad_len > INT_MAX || plaintext_len > INT_MAX ||
        (!aad && aad_len))
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SL_GCM_NONCE_LEN, NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    if (aad_len &&
        EVP_EncryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) != 1)
        goto done;

    if (plaintext_len) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext,
                              (int)plaintext_len) != 1)
            goto done;
        total = out_len;
    }

    if (EVP_EncryptFinal_ex(ctx,
                            plaintext_len ? ciphertext + total : NULL,
                            &out_len) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            SL_GCM_TAG_LEN, tag) != 1)
        goto done;

    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int sl_aes_gcm_decrypt(const uint8_t key[SL_AES_KEY_LEN],
                       const uint8_t nonce[SL_GCM_NONCE_LEN],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[SL_GCM_TAG_LEN],
                       uint8_t *plaintext)
{
    int out_len = 0, total = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int ok = 0;

    if (!key || !nonce || (!ciphertext && ciphertext_len) ||
        (!plaintext && ciphertext_len) || !tag ||
        aad_len > INT_MAX || ciphertext_len > INT_MAX ||
        (!aad && aad_len))
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            SL_GCM_NONCE_LEN, NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    if (aad_len &&
        EVP_DecryptUpdate(ctx, NULL, &out_len, aad, (int)aad_len) != 1)
        goto done;

    if (ciphertext_len) {
        if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext,
                              (int)ciphertext_len) != 1)
            goto done;
        total = out_len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            SL_GCM_TAG_LEN, (void *)tag) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(ctx,
                            ciphertext_len ? plaintext + total : NULL,
                            &out_len) != 1)
        goto done;

    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
