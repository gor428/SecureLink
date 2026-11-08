#ifndef SECURELINK_HANDSHAKE_H
#define SECURELINK_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#define SL_X25519_KEY_LEN 32
#define SL_PSK_MIN_LEN 32
#define SL_SALT_LEN 32
#define SL_HANDSHAKE_MAC_LEN 32
#define SL_SESSION_KEY_LEN 32

typedef struct {
    uint8_t private_key[SL_X25519_KEY_LEN];
    uint8_t public_key[SL_X25519_KEY_LEN];
} sl_x25519_keypair;

typedef struct {
    uint8_t client_to_server[SL_SESSION_KEY_LEN];
    uint8_t server_to_client[SL_SESSION_KEY_LEN];
} sl_directional_keys;

/* Generates an ephemeral X25519 keypair. Returns 1 on success. */
int sl_x25519_generate(sl_x25519_keypair *out);

/* Computes the X25519 shared secret. Returns 1 on success. */
int sl_x25519_shared(const uint8_t private_key[SL_X25519_KEY_LEN],
                     const uint8_t peer_public_key[SL_X25519_KEY_LEN],
                     uint8_t shared_secret[SL_X25519_KEY_LEN]);

/*
 * Computes an HMAC-SHA256 authenticator over a domain-separated,
 * ordered handshake transcript. Both peers must use the same ordering:
 * client public key, server public key, then salt.
 */
int sl_handshake_auth(const uint8_t *psk, size_t psk_len,
                      const uint8_t client_public[SL_X25519_KEY_LEN],
                      const uint8_t server_public[SL_X25519_KEY_LEN],
                      const uint8_t salt[SL_SALT_LEN],
                      uint8_t mac[SL_HANDSHAKE_MAC_LEN]);

/* Constant-time comparison of a received handshake authenticator. */
int sl_handshake_auth_verify(const uint8_t *psk, size_t psk_len,
                             const uint8_t client_public[SL_X25519_KEY_LEN],
                             const uint8_t server_public[SL_X25519_KEY_LEN],
                             const uint8_t salt[SL_SALT_LEN],
                             const uint8_t received_mac[SL_HANDSHAKE_MAC_LEN]);

/*
 * Derives independent directional AES-256 keys from the DH secret.
 * Both peers pass the same transcript ordering and salt.
 */
int sl_derive_directional_keys(
    const uint8_t shared_secret[SL_X25519_KEY_LEN],
    const uint8_t salt[SL_SALT_LEN],
    const uint8_t client_public[SL_X25519_KEY_LEN],
    const uint8_t server_public[SL_X25519_KEY_LEN],
    sl_directional_keys *keys);

void sl_handshake_clear_keypair(sl_x25519_keypair *keypair);
void sl_handshake_clear_keys(sl_directional_keys *keys);

#endif
