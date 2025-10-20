#ifndef HYBRID_KEX_H
#define HYBRID_KEX_H

#include "hybrid_common.h"

// Generate a hybrid keypair: SM2 (pub65||priv32) + ML-KEM (pub||sk)
int hybrid_kex_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
);

// Server derives shared secret and produces response for client
// server_response := server_sm2_pub(65) || mlkem_ciphertext
int hybrid_kex_server_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    uint8_t **server_response, size_t *server_response_len,
    const uint8_t *client_public_key, size_t client_public_key_len,
    const uint8_t *server_private_key, size_t server_private_key_len
);

// Client derives shared secret from server response
int hybrid_kex_client_derive(
    uint8_t **shared_secret, size_t *shared_secret_len,
    const uint8_t *server_response, size_t server_response_len,
    const uint8_t *client_private_key, size_t client_private_key_len
);

#endif /* HYBRID_KEX_H */

