#include "handshake.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string.h>

static const uint8_t AUTH_DOMAIN[] = "SecureLink handshake authentication v1";
static const uint8_t KDF_INFO[] = "SecureLink directional traffic keys v1";

int sl_x25519_generate(sl_x25519_keypair *out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    size_t private_len = SL_X25519_KEY_LEN;
    size_t public_len = SL_X25519_KEY_LEN;
    int ok = 0;

    if (!out)
        return 0;

    memset(out, 0, sizeof(*out));
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
        goto done;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0)
        goto done;

    if (EVP_PKEY_get_raw_private_key(key, out->private_key,
                                     &private_len) <= 0 ||
        EVP_PKEY_get_raw_public_key(key, out->public_key,
                                    &public_len) <= 0)
        goto done;

    if (private_len != SL_X25519_KEY_LEN ||
        public_len != SL_X25519_KEY_LEN)
        goto done;

    ok = 1;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    if (!ok)
        OPENSSL_cleanse(out, sizeof(*out));
    return ok;
}

int sl_x25519_shared(const uint8_t private_key[SL_X25519_KEY_LEN],
                     const uint8_t peer_public_key[SL_X25519_KEY_LEN],
                     uint8_t shared_secret[SL_X25519_KEY_LEN])
{
    EVP_PKEY *local = NULL, *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len = SL_X25519_KEY_LEN;
    int ok = 0;

    if (!private_key || !peer_public_key || !shared_secret)
        return 0;

    local = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                         private_key, SL_X25519_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                       peer_public_key, SL_X25519_KEY_LEN);
    if (!local || !peer)
        goto done;

    ctx = EVP_PKEY_CTX_new(local, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
        EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0)
        goto done;

    if (secret_len != SL_X25519_KEY_LEN)
        goto done;

    /* Reject an all-zero result (including low-order peer public keys). */
    {
        uint8_t acc = 0;
        size_t i;
        for (i = 0; i < SL_X25519_KEY_LEN; ++i)
            acc |= shared_secret[i];
        if (acc == 0)
            goto done;
    }

    ok = 1;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(local);
    EVP_PKEY_free(peer);
    if (!ok)
        OPENSSL_cleanse(shared_secret, SL_X25519_KEY_LEN);
    return ok;
}

int sl_handshake_auth(const uint8_t *psk, size_t psk_len,
                      const uint8_t client_public[SL_X25519_KEY_LEN],
                      const uint8_t server_public[SL_X25519_KEY_LEN],
                      const uint8_t salt[SL_SALT_LEN],
                      uint8_t mac[SL_HANDSHAKE_MAC_LEN])
{
    uint8_t transcript[sizeof(AUTH_DOMAIN) - 1 +
                       2 * SL_X25519_KEY_LEN + SL_SALT_LEN];
    unsigned int mac_len = 0;
    size_t offset = 0;
    int ok = 0;

    if (!psk || psk_len < SL_PSK_MIN_LEN || !client_public ||
        !server_public || !salt || !mac)
        return 0;

    memcpy(transcript + offset, AUTH_DOMAIN, sizeof(AUTH_DOMAIN) - 1);
    offset += sizeof(AUTH_DOMAIN) - 1;
    memcpy(transcript + offset, client_public, SL_X25519_KEY_LEN);
    offset += SL_X25519_KEY_LEN;
    memcpy(transcript + offset, server_public, SL_X25519_KEY_LEN);
    offset += SL_X25519_KEY_LEN;
    memcpy(transcript + offset, salt, SL_SALT_LEN);

    if (HMAC(EVP_sha256(), psk, (int)psk_len,
             transcript, sizeof(transcript), mac, &mac_len) != NULL &&
        mac_len == SL_HANDSHAKE_MAC_LEN)
        ok = 1;

    OPENSSL_cleanse(transcript, sizeof(transcript));
    if (!ok)
        OPENSSL_cleanse(mac, SL_HANDSHAKE_MAC_LEN);
    return ok;
}

int sl_handshake_auth_verify(const uint8_t *psk, size_t psk_len,
                             const uint8_t client_public[SL_X25519_KEY_LEN],
                             const uint8_t server_public[SL_X25519_KEY_LEN],
                             const uint8_t salt[SL_SALT_LEN],
                             const uint8_t received_mac[SL_HANDSHAKE_MAC_LEN])
{
    uint8_t expected[SL_HANDSHAKE_MAC_LEN];
    int ok;

    if (!received_mac ||
        !sl_handshake_auth(psk, psk_len, client_public, server_public,
                           salt, expected))
        return 0;

    ok = (CRYPTO_memcmp(expected, received_mac,
                        SL_HANDSHAKE_MAC_LEN) == 0);
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

int sl_derive_directional_keys(
    const uint8_t shared_secret[SL_X25519_KEY_LEN],
    const uint8_t salt[SL_SALT_LEN],
    const uint8_t client_public[SL_X25519_KEY_LEN],
    const uint8_t server_public[SL_X25519_KEY_LEN],
    sl_directional_keys *keys)
{
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t info[sizeof(KDF_INFO) - 1 + 2 * SL_X25519_KEY_LEN];
    size_t out_len = 2 * SL_SESSION_KEY_LEN;
    uint8_t output[2 * SL_SESSION_KEY_LEN];
    int ok = 0;

    if (!shared_secret || !salt || !client_public ||
        !server_public || !keys)
        return 0;

    memset(keys, 0, sizeof(*keys));
    memcpy(info, KDF_INFO, sizeof(KDF_INFO) - 1);
    memcpy(info + sizeof(KDF_INFO) - 1, client_public,
           SL_X25519_KEY_LEN);
    memcpy(info + sizeof(KDF_INFO) - 1 + SL_X25519_KEY_LEN,
           server_public, SL_X25519_KEY_LEN);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx)
        goto done;

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, SL_SALT_LEN) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret,
                                   SL_X25519_KEY_LEN) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)) <= 0 ||
        EVP_PKEY_derive(ctx, output, &out_len) <= 0)
        goto done;

    if (out_len != sizeof(output))
        goto done;

    memcpy(keys->client_to_server, output, SL_SESSION_KEY_LEN);
    memcpy(keys->server_to_client, output + SL_SESSION_KEY_LEN,
           SL_SESSION_KEY_LEN);
    ok = 1;

done:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(info, sizeof(info));
    OPENSSL_cleanse(output, sizeof(output));
    if (!ok)
        OPENSSL_cleanse(keys, sizeof(*keys));
    return ok;
}

void sl_handshake_clear_keypair(sl_x25519_keypair *keypair)
{
    if (keypair)
        OPENSSL_cleanse(keypair, sizeof(*keypair));
}

void sl_handshake_clear_keys(sl_directional_keys *keys)
{
    if (keys)
        OPENSSL_cleanse(keys, sizeof(*keys));
}
