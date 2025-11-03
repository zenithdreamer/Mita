#include "../include/crypto/crypto_service.h"

CryptoService::CryptoService() : iv_counter(0), session_key_valid(false)
{
    memset(session_key, 0, SESSION_KEY_SIZE);
}

uint32_t CryptoService::generateNonce()
{
    return esp_random();
}

bool CryptoService::computeHMAC(const uint8_t *key, size_t key_len,
                                const uint8_t *data, size_t data_len,
                                uint8_t *hmac)
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

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

    if (mbedtls_md_hmac_finish(&ctx, hmac) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}

bool CryptoService::deriveSessionKey(const String &shared_secret, uint32_t nonce1, uint32_t nonce2)
{
    // SessionKey = HMAC_SHA256(PSK, Nonce1 || Nonce2)
    uint8_t nonce_data[8];
    nonce_data[0] = (nonce1 >> 24) & 0xFF;
    nonce_data[1] = (nonce1 >> 16) & 0xFF;
    nonce_data[2] = (nonce1 >> 8) & 0xFF;
    nonce_data[3] = nonce1 & 0xFF;
    nonce_data[4] = (nonce2 >> 24) & 0xFF;
    nonce_data[5] = (nonce2 >> 16) & 0xFF;
    nonce_data[6] = (nonce2 >> 8) & 0xFF;
    nonce_data[7] = nonce2 & 0xFF;

    uint8_t session_hmac[HMAC_SIZE];
    if (!computeHMAC((uint8_t *)shared_secret.c_str(), shared_secret.length(),
                     nonce_data, 8, session_hmac))
    {
        return false;
    }

    // Use first 16 bytes as AES-128 key
    memcpy(session_key, session_hmac, SESSION_KEY_SIZE);
    session_key_valid = true;
    iv_counter = 0;

    Serial.println("CryptoService: Session key derived successfully");
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
    iv_counter = 0;
}

void CryptoService::getSessionKey(uint8_t *key_out) const
{
    if (session_key_valid && key_out)
    {
        memcpy(key_out, session_key, SESSION_KEY_SIZE);
    }
}

bool CryptoService::encryptPayload(const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *ciphertext, size_t &ciphertext_len)
{
    if (!session_key_valid)
    {
        return false;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, session_key, 128) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Generate IV using counter (16 bytes)
    uint8_t iv[16];
    memset(iv, 0, 16);
    for (int i = 0; i < 8; i++)
    {
        iv[15 - i] = (iv_counter >> (i * 8)) & 0xFF;
    }
    iv_counter++;

    // Pad to AES block size using PKCS#7
    size_t padded_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (padded_len + 16 > MAX_PAYLOAD_SIZE)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    uint8_t *padded_data = (uint8_t *)malloc(padded_len);
    if (!padded_data)
    {
        mbedtls_aes_free(&aes);
        return false;
    }
    memcpy(padded_data, plaintext, plaintext_len);

    // PKCS#7 padding
    uint8_t pad_value = padded_len - plaintext_len;
    for (size_t i = plaintext_len; i < padded_len; i++)
    {
        padded_data[i] = pad_value;
    }

    // Copy IV to beginning of ciphertext
    memcpy(ciphertext, iv, 16);

    // Encrypt using CBC mode
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                              iv, padded_data, ciphertext + 16) != 0)
    {
        mbedtls_aes_free(&aes);
        free(padded_data);
        return false;
    }

    ciphertext_len = padded_len + 16;
    mbedtls_aes_free(&aes);
    free(padded_data);
    return true;
}

bool CryptoService::decryptPayload(const uint8_t *encrypted_data, unsigned int encrypted_length,
                                   uint8_t *decrypted_data, unsigned int &decrypted_length)
{
    if (!session_key_valid)
    {
        // No encryption during handshake
        memcpy(decrypted_data, encrypted_data, encrypted_length);
        decrypted_length = encrypted_length;
        return true;
    }

    if (encrypted_length < 16)
    {
        return false;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_dec(&aes, session_key, 128) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Extract IV from first 16 bytes
    uint8_t iv[16];
    memcpy(iv, encrypted_data, 16);

    const uint8_t *ciphertext = encrypted_data + 16;
    size_t ciphertext_len = encrypted_length - 16;

    if (ciphertext_len % AES_BLOCK_SIZE != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Decrypt using CBC mode
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len,
                              iv, ciphertext, decrypted_data) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Remove PKCS#7 padding
    uint8_t pad_value = decrypted_data[ciphertext_len - 1];
    if (pad_value > 0 && pad_value <= AES_BLOCK_SIZE)
    {
        decrypted_length = ciphertext_len - pad_value;
    }
    else
    {
        decrypted_length = ciphertext_len;
    }

    mbedtls_aes_free(&aes);
    return true;
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