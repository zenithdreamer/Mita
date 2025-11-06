#ifndef CRYPTO_SERVICE_H
#define CRYPTO_SERVICE_H

#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <esp_random.h>
#include "../../shared/protocol/protocol_types.h"

class CryptoService
{
private:
    uint8_t session_key[SESSION_KEY_SIZE];
    bool session_key_valid;
    
    // Counter-based IV to prevent IV reuse
    uint64_t iv_counter;
    uint32_t session_salt;  // Random salt generated once per session

    // Helper for key derivation
    bool deriveSubkey(const uint8_t *key, size_t key_len, const char *info, uint8_t *output);

public:
    CryptoService();
    ~CryptoService() = default;

    // Nonce generation
    void generateNonce(uint8_t *nonce_out);

    // HMAC operations
    bool computeHMAC(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *hmac);

    // Per-device PSK derivation (matches router implementation)
    // Derives: Device_PSK = HMAC-SHA256(master_secret, "DEVICE_PSK" || device_id)
    static bool deriveDevicePSK(const String &master_secret, const String &device_id, 
                               uint8_t *device_psk_out);

    // Session key management
    bool deriveSessionKey(const String &shared_secret, const uint8_t *nonce1, const uint8_t *nonce2);
    bool rekeySession(const uint8_t *nonce3, const uint8_t *nonce4);  // Rekey from old session key
    bool hasValidSessionKey() const;
    void clearSessionKey();
    void getSessionKey(uint8_t *key_out) const;  // Get copy of session key for logging

    // AES-GCM Authenticated Encryption (recommended)
    bool encryptGCM(const uint8_t *plaintext, size_t plaintext_len,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *output, size_t &output_len);
    bool decryptGCM(const uint8_t *input, size_t input_len,
                    const uint8_t *aad, size_t aad_len,
                    uint8_t *plaintext, size_t &plaintext_len);

    // Utility
    uint8_t calculateSimpleChecksum(const uint8_t *data, size_t length);
    bool verifySimpleChecksum(const uint8_t *data, size_t length, uint8_t expected);
};

#endif // CRYPTO_SERVICE_H