#include "handshake.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    sl_x25519_keypair client, server;
    sl_directional_keys client_keys, server_keys;
    uint8_t client_secret[SL_X25519_KEY_LEN];
    uint8_t server_secret[SL_X25519_KEY_LEN];
    uint8_t psk[32];
    uint8_t salt[SL_SALT_LEN];
    uint8_t mac[SL_HANDSHAKE_MAC_LEN];
    size_t i;
    int result = 1;

    memset(psk, 0x5a, sizeof(psk));
    memset(salt, 0xa5, sizeof(salt));

    if (!sl_x25519_generate(&client) || !sl_x25519_generate(&server)) {
        fprintf(stderr, "X25519 key generation failed\n");
        goto cleanup;
    }

    if (!sl_x25519_shared(client.private_key, server.public_key,
                          client_secret) ||
        !sl_x25519_shared(server.private_key, client.public_key,
                          server_secret)) {
        fprintf(stderr, "X25519 shared-secret derivation failed\n");
        goto cleanup;
    }

    if (memcmp(client_secret, server_secret, sizeof(client_secret)) != 0) {
        fprintf(stderr, "DH shared secrets do not match\n");
        goto cleanup;
    }

    if (!sl_handshake_auth(psk, sizeof(psk), client.public_key,
                           server.public_key, salt, mac) ||
        !sl_handshake_auth_verify(psk, sizeof(psk), client.public_key,
                                  server.public_key, salt, mac)) {
        fprintf(stderr, "handshake authentication failed\n");
        goto cleanup;
    }

    mac[0] ^= 0x80;
    if (sl_handshake_auth_verify(psk, sizeof(psk), client.public_key,
                                 server.public_key, salt, mac)) {
        fprintf(stderr, "tampered handshake MAC was accepted\n");
        goto cleanup;
    }
    mac[0] ^= 0x80;

    if (!sl_derive_directional_keys(client_secret, salt, client.public_key,
                                    server.public_key, &client_keys) ||
        !sl_derive_directional_keys(server_secret, salt, client.public_key,
                                    server.public_key, &server_keys)) {
        fprintf(stderr, "HKDF key derivation failed\n");
        goto cleanup;
    }

    if (memcmp(&client_keys, &server_keys, sizeof(client_keys)) != 0) {
        fprintf(stderr, "directional keys differ between peers\n");
        goto cleanup;
    }

    if (memcmp(client_keys.client_to_server,
               client_keys.server_to_client, SL_SESSION_KEY_LEN) == 0) {
        fprintf(stderr, "directional keys unexpectedly identical\n");
        goto cleanup;
    }

    for (i = 0; i < sizeof(psk); ++i)
        psk[i] = 0;

    puts("PASS: X25519 shared secret, PSK transcript authentication, "
         "HKDF directional keys, and tamper rejection");
    result = 0;

cleanup:
    sl_handshake_clear_keypair(&client);
    sl_handshake_clear_keypair(&server);
    sl_handshake_clear_keys(&client_keys);
    sl_handshake_clear_keys(&server_keys);
    OPENSSL_cleanse(client_secret, sizeof(client_secret));
    OPENSSL_cleanse(server_secret, sizeof(server_secret));
    OPENSSL_cleanse(psk, sizeof(psk));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(mac, sizeof(mac));
    return result;
}
