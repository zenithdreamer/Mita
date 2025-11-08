#include "crypto_utils.h"

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    #include <esp_random.h>
    #include <mbedtls/md.h>
#else
    #include <openssl/hmac.h>
    #include <openssl/rand.h>
    #include <openssl/crypto.h>
#endif

namespace mita {
namespace crypto {

bool computeHMAC(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* hmac_out)
{
    if (!key || !data || !hmac_out || key_len == 0 || data_len == 0)
    {
        return false;
    }

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    // ESP32 implementation using mbedtls
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 1) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_starts(&ctx, key, key_len) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&ctx, data, data_len) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_finish(&ctx, hmac_out) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
#else
    // Router implementation using OpenSSL
    unsigned int hmac_len;
    unsigned char* result = HMAC(EVP_sha256(), key, key_len,
                                 data, data_len, hmac_out, &hmac_len);

    return (result != nullptr && hmac_len == HMAC_SIZE);
#endif
}

bool deriveDevicePSK(const uint8_t* master_secret, size_t master_secret_len,
                    const uint8_t* device_id, size_t device_id_len,
                    uint8_t* device_psk_out)
{
    if (!master_secret || !device_id || !device_psk_out || 
        master_secret_len == 0 || device_id_len == 0)
    {
        return false;
    }

    // Build data: "DEVICE_PSK" || device_id
    const char* prefix = "DEVICE_PSK";
    const size_t prefix_len = 10; // strlen("DEVICE_PSK")
    const size_t data_len = prefix_len + device_id_len;
    
    uint8_t* data = new uint8_t[data_len];
    std::memcpy(data, prefix, prefix_len);
    std::memcpy(data + prefix_len, device_id, device_id_len);

    // Compute HMAC-SHA256(master_secret, "DEVICE_PSK" || device_id)
    bool result = computeHMAC(master_secret, master_secret_len, data, data_len, device_psk_out);

    delete[] data;
    return result;
}

bool deriveSessionKey(const uint8_t* psk, size_t psk_len,
                     const uint8_t* nonce1, const uint8_t* nonce2,
                     uint8_t* session_key_out)
{
    if (!psk || !nonce1 || !nonce2 || !session_key_out || psk_len == 0)
    {
        return false;
    }

    // SessionKey = HMAC-SHA256(PSK, Nonce1 || Nonce2)
    uint8_t nonce_data[NONCE_SIZE * 2];
    std::memcpy(nonce_data, nonce1, NONCE_SIZE);
    std::memcpy(nonce_data + NONCE_SIZE, nonce2, NONCE_SIZE);

    uint8_t hmac_output[HMAC_SIZE];
    if (!computeHMAC(psk, psk_len, nonce_data, NONCE_SIZE * 2, hmac_output))
    {
        return false;
    }

    // Use first SESSION_KEY_SIZE bytes as AES-128 key
    std::memcpy(session_key_out, hmac_output, SESSION_KEY_SIZE);
    return true;
}

bool rekeySession(const uint8_t* old_session_key,
                 const uint8_t* nonce3, const uint8_t* nonce4,
                 uint8_t* new_session_key_out)
{
    if (!old_session_key || !nonce3 || !nonce4 || !new_session_key_out)
    {
        return false;
    }

    // New_Session_Key = HMAC-SHA256(old_session_key, nonce3 || nonce4)
    uint8_t nonce_data[NONCE_SIZE * 2];
    std::memcpy(nonce_data, nonce3, NONCE_SIZE);
    std::memcpy(nonce_data + NONCE_SIZE, nonce4, NONCE_SIZE);

    uint8_t hmac_output[HMAC_SIZE];
    if (!computeHMAC(old_session_key, SESSION_KEY_SIZE, 
                     nonce_data, NONCE_SIZE * 2, hmac_output))
    {
        return false;
    }

    // Use first SESSION_KEY_SIZE bytes for new session key
    std::memcpy(new_session_key_out, hmac_output, SESSION_KEY_SIZE);
    return true;
}

bool deriveSubkey(const uint8_t* key, size_t key_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* subkey_out)
{
    if (!key || !info || !subkey_out || key_len == 0 || info_len == 0)
    {
        return false;
    }

    uint8_t hmac_output[HMAC_SIZE];
    if (!computeHMAC(key, key_len, info, info_len, hmac_output))
    {
        return false;
    }

    // Use first SESSION_KEY_SIZE bytes for subkey
    std::memcpy(subkey_out, hmac_output, SESSION_KEY_SIZE);
    return true;
}

void generateNonce(uint8_t* nonce_out)
{
    if (!nonce_out)
    {
        return;
    }

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    // ESP32 implementation using esp_random()
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        nonce_out[i] = esp_random() & 0xFF;
    }
#else
    // Router implementation using OpenSSL
    RAND_bytes(nonce_out, NONCE_SIZE);
#endif
}

int constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len)
{
    if (!a || !b)
    {
        return -1;
    }

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    // For ESP32, implement constant-time comparison manually
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }
    return diff;
#else
    // Router implementation using OpenSSL
    return CRYPTO_memcmp(a, b, len);
#endif
}

} // namespace crypto
} // namespace mita
