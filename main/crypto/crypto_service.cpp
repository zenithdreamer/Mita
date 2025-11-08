#include "../include/crypto/crypto_service.h"
#include "../../shared/crypto/crypto_utils.h"
#include "../../shared/crypto/gcm_crypto.h"
#include <esp_log.h>

static const char *TAG = "CRYPTO_SERVICE";

CryptoService::CryptoService() : session_key_valid(false), iv_counter(0), session_salt(0)
{
    memset(session_key, 0, SESSION_KEY_SIZE);
    // Generate random session salt once
    session_salt = esp_random();
}

void CryptoService::generateNonce(uint8_t *nonce_out)
{
    mita::crypto::generateNonce(nonce_out);
}

bool CryptoService::computeHMAC(const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *hmac)
{
    return mita::crypto::computeHMAC(key, key_len, data, data_len, hmac);
}

// Derive device-specific PSK from master secret
// This matches the router's implementation for compatibility
// Device_PSK = HMAC-SHA256(master_secret, "DEVICE_PSK" || device_id)
bool CryptoService::deriveDevicePSK(const std::string &master_secret, const std::string &device_id, 
                                   uint8_t *device_psk_out)
{
    if (!device_psk_out)
    {
        return false;
    }

    bool result = mita::crypto::deriveDevicePSK(
        (const uint8_t*)master_secret.c_str(), master_secret.length(),
        (const uint8_t*)device_id.c_str(), device_id.length(),
        device_psk_out
    );
    
    if (result)
    {
        ESP_LOGI(TAG, "%s", "CryptoService: Device PSK derived successfully");
    }
    else
    {
        ESP_LOGI(TAG, "%s", "CryptoService: Failed to derive device PSK");
    }
    
    return result;
}

bool CryptoService::deriveSessionKey(const std::string &shared_secret, const uint8_t *nonce1, const uint8_t *nonce2)
{
    if (!mita::crypto::deriveSessionKey(
            (const uint8_t*)shared_secret.data(), shared_secret.length(),
            nonce1, nonce2, session_key))
    {
        return false;
    }

    const uint8_t enc_info[] = {'E', 'N', 'C'};
    if (!mita::crypto::deriveSubkey(session_key, SESSION_KEY_SIZE, enc_info, 3, encryption_key))
    {
        return false;
    }

    session_key_valid = true;
    
    iv_counter = 0;

    ESP_LOGI(TAG, "%s", "CryptoService: Session key derived successfully");
    return true;
}

bool CryptoService::rekeySession(const uint8_t *nonce3, const uint8_t *nonce4)
{
    if (!session_key_valid)
    {
        ESP_LOGI(TAG, "%s", "CryptoService: Cannot rekey - no valid session key");
        return false;
    }
    
    uint8_t new_session_key[SESSION_KEY_SIZE];
    if (!mita::crypto::rekeySession(session_key, nonce3, nonce4, new_session_key))
    {
        ESP_LOGI(TAG, "%s", "CryptoService: Failed to rekey session");
        return false;
    }
    
    memcpy(session_key, new_session_key, SESSION_KEY_SIZE);
    
    const uint8_t enc_info[] = {'E', 'N', 'C'};
    if (!mita::crypto::deriveSubkey(session_key, SESSION_KEY_SIZE, enc_info, 3, encryption_key))
    {
        return false;
    }
    
    iv_counter = 0;
    
    session_salt = esp_random();
    
    ESP_LOGI(TAG, "%s", "CryptoService: Session key rekeyed successfully");
    return true;
}

bool CryptoService::hasValidSessionKey() const
{
    return session_key_valid;
}

void CryptoService::clearSessionKey()
{
    memset(session_key, 0, SESSION_KEY_SIZE);
    session_key_valid = false;
    // Reset IV counter when clearing session
    iv_counter = 0;
}

void CryptoService::getSessionKey(uint8_t *key_out) const
{
    if (session_key_valid && key_out)
    {
        memcpy(key_out, session_key, SESSION_KEY_SIZE);
    }
}

// AES-GCM Authenticated Encryption
bool CryptoService::encryptGCM(const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *output, size_t &output_len)
{
    if (!session_key_valid || plaintext_len == 0)
    {
        return false;
    }

    return mita::crypto::encryptGCM(
        encryption_key, session_salt, iv_counter,
        plaintext, plaintext_len,
        aad, aad_len,
        output, output_len
    );
}

bool CryptoService::decryptGCM(const uint8_t *input, size_t input_len,
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *plaintext, size_t &plaintext_len)
{
    if (!session_key_valid || input_len < 28)
    {
        return false;
    }

    bool result = mita::crypto::decryptGCM(
        encryption_key,
        input, input_len,
        aad, aad_len,
        plaintext, plaintext_len
    );

    if (!result)
    {
        ESP_LOGI(TAG, "%s", "CryptoService: GCM authentication failed - data may be tampered");
    }

    return result;
}

uint8_t CryptoService::calculateSimpleChecksum(const uint8_t *data, size_t length)
{
    uint8_t checksum = 0;
    for (size_t i = 0; i < length; i++)
    {
        checksum ^= data[i];
    }
    return checksum;
}

bool CryptoService::verifySimpleChecksum(const uint8_t *data, size_t length, uint8_t expected)
{
    return calculateSimpleChecksum(data, length) == expected;
}