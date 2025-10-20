#ifndef HYBRID_SIG_H
#define HYBRID_SIG_H

#include "hybrid_common.h"

// Generate composite signature keypair: SM2 + ML-DSA
int hybrid_sig_keygen(
    uint8_t **public_key, size_t *public_key_len,
    uint8_t **private_key, size_t *private_key_len
);

// Sign a message digest (SM3 digest expected by caller)
int hybrid_sig_sign(
    uint8_t **signature, size_t *signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *private_key, size_t private_key_len
);

// Verify a composite signature over a message digest
int hybrid_sig_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message_digest, size_t digest_len,
    const uint8_t *public_key, size_t public_key_len
);

#endif /* HYBRID_SIG_H */

