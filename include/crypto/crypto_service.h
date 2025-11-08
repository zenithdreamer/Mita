#ifndef CRYPTO_SERVICE_H
#define CRYPTO_SERVICE_H

#include <cstring>
#include <cstdint>
#include <string>
#include <esp_random.h>
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/crypto/crypto_utils.h"
#include "../../shared/crypto/gcm_crypto.h"

class CryptoService
{
private:
    uint8_t session_key[SESSION_KEY_SIZE];
    uint8_t encryption_key[SESSION_KEY_SIZE];
    bool session_key_valid;
    
    uint64_t iv_counter;
    uint32_t session_salt;

public:
    CryptoService();
    ~CryptoService() = default;

    void generateNonce(uint8_t *nonce_out);

    bool computeHMAC(const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *hmac);

    static bool deriveDevicePSK(const std::string &master_secret, const std::string &device_id, 
                               uint8_t *device_psk_out);

    bool deriveSessionKey(const std::string &shared_secret, const uint8_t *nonce1, const uint8_t *nonce2);
    bool rekeySession(const uint8_t *nonce3, const uint8_t *nonce4);
    bool hasValidSessionKey() const;
    void clearSessionKey();
    void getSessionKey(uint8_t *key_out) const;

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