#include "../include/crypto/crypto_service.h"

CryptoService::CryptoService() : session_key_valid(false)
{
    memset(session_key, 0, SESSION_KEY_SIZE);
}

void CryptoService::generateNonce(uint8_t *nonce_out)
{
    // Generate 16 random bytes (increased from 4 bytes)
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        nonce_out[i] = esp_random() & 0xFF;
    }
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

bool CryptoService::deriveSessionKey(const String &shared_secret, const uint8_t *nonce1, const uint8_t *nonce2)
{
    // SessionKey = HMAC_SHA256(PSK, Nonce1 || Nonce2)
    uint8_t nonce_data[NONCE_SIZE * 2];
    memcpy(nonce_data, nonce1, NONCE_SIZE);
    memcpy(nonce_data + NONCE_SIZE, nonce2, NONCE_SIZE);

    uint8_t session_hmac[HMAC_SIZE];
    if (!computeHMAC((uint8_t *)shared_secret.c_str(), shared_secret.length(),
                     nonce_data, NONCE_SIZE * 2, session_hmac))
    {
        return false;
    }

    // Use first 16 bytes as AES-128 key
    memcpy(session_key, session_hmac, SESSION_KEY_SIZE);
    session_key_valid = true;

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
}

void CryptoService::getSessionKey(uint8_t *key_out) const
{
    if (session_key_valid && key_out)
    {
        memcpy(key_out, session_key, SESSION_KEY_SIZE);
    }
}

// Key derivation helper (HKDF-like)
bool CryptoService::deriveSubkey(const uint8_t *key, size_t key_len, const char *info, uint8_t *output)
{
    uint8_t info_bytes[3];
    info_bytes[0] = info[0];
    info_bytes[1] = info[1];
    info_bytes[2] = info[2];

    uint8_t hmac[HMAC_SIZE];
    if (!computeHMAC(key, key_len, info_bytes, 3, hmac))
    {
        return false;
    }

    memcpy(output, hmac, SESSION_KEY_SIZE); // Use first 16 bytes
    return true;
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

    // Derive encryption key from session key
    uint8_t derived_enc_key[SESSION_KEY_SIZE];
    if (!deriveSubkey(session_key, SESSION_KEY_SIZE, "ENC", derived_enc_key))
    {
        return false;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    // Setup GCM with AES-128
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, derived_enc_key, 128) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    // Generate 12-byte IV (optimal for GCM)
    uint8_t iv[12];
    for (int i = 0; i < 12; i++)
    {
        iv[i] = esp_random() & 0xFF;
    }

    // Tag buffer (16 bytes)
    uint8_t tag[16];

    // Encrypt: output = ciphertext
    // We'll store: IV (12) || ciphertext || tag (16)
    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                  plaintext_len, iv, 12,
                                  aad, aad_len,
                                  plaintext, output + 12, // ciphertext starts after IV
                                  16, tag) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    mbedtls_gcm_free(&gcm);

    // Build output: IV || ciphertext || tag
    memcpy(output, iv, 12);
    memcpy(output + 12 + plaintext_len, tag, 16);
    output_len = 12 + plaintext_len + 16;

    return true;
}

bool CryptoService::decryptGCM(const uint8_t *input, size_t input_len,
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *plaintext, size_t &plaintext_len)
{
    if (!session_key_valid || input_len < 28) // 12 (IV) + 16 (tag) = min 28 bytes
    {
        return false;
    }

    // Derive encryption key from session key
    uint8_t derived_enc_key[SESSION_KEY_SIZE];
    if (!deriveSubkey(session_key, SESSION_KEY_SIZE, "ENC", derived_enc_key))
    {
        return false;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    // Setup GCM with AES-128
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, derived_enc_key, 128) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    // Extract IV (first 12 bytes)
    const uint8_t *iv = input;

    // Extract tag (last 16 bytes)
    const uint8_t *tag = input + input_len - 16;

    // Ciphertext is between IV and tag
    const uint8_t *ciphertext = input + 12;
    size_t ciphertext_len = input_len - 12 - 16;

    // Decrypt and verify tag
    if (mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, 12,
                                 aad, aad_len,
                                 tag, 16,
                                 ciphertext, plaintext) != 0)
    {
        mbedtls_gcm_free(&gcm);
        Serial.println("CryptoService: GCM authentication failed - data may be tampered");
        return false;
    }

    mbedtls_gcm_free(&gcm);
    plaintext_len = ciphertext_len;
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