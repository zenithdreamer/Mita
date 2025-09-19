#ifndef CRYPTO_SERVICE_H
#define CRYPTO_SERVICE_H

#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <esp_random.h>
#include "../../shared/protocol/protocol_types.h"

class CryptoService
{
private:
    uint8_t session_key[SESSION_KEY_SIZE];
    uint32_t iv_counter;
    bool session_key_valid;

public:
    CryptoService();
    ~CryptoService() = default;

    // Nonce generation
    uint32_t generateNonce();

    // HMAC operations
    bool computeHMAC(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *hmac);

    // Session key management
    bool deriveSessionKey(const String &shared_secret, uint32_t nonce1, uint32_t nonce2);
    bool hasValidSessionKey() const;
    void clearSessionKey();

    // Encryption/Decryption
    bool encryptPayload(const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext, size_t &ciphertext_len);
    bool decryptPayload(const uint8_t *encrypted_data, unsigned int encrypted_length,
                        uint8_t *decrypted_data, unsigned int &decrypted_length);

    // Utility
    uint8_t calculateSimpleChecksum(const uint8_t *data, size_t length);
    bool verifySimpleChecksum(const uint8_t *data, size_t length, uint8_t expected);
};

#endif // CRYPTO_SERVICE_H