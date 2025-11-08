#include "gcm_crypto.h"
#include "crypto_utils.h"

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    #include <mbedtls/gcm.h>
#else
    #include <openssl/evp.h>
#endif

namespace mita {
namespace crypto {

bool encryptGCM(const uint8_t* session_key,
               uint32_t session_salt,
               uint64_t& iv_counter,
               const uint8_t* plaintext, size_t plaintext_len,
               const uint8_t* aad, size_t aad_len,
               uint8_t* output, size_t& output_len)
{
    if (!session_key || !plaintext || !output || plaintext_len == 0)
    {
        return false;
    }

    uint8_t iv[12];
    std::memcpy(iv, &session_salt, 4);
    uint64_t current_counter = iv_counter++;
    std::memcpy(iv + 4, &current_counter, 8);

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 128) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    uint8_t tag[16];

    // Encrypt: output = IV || ciphertext || tag
    // Ciphertext starts at output + 12
    if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                  plaintext_len, iv, 12,
                                  aad, aad_len,
                                  plaintext, output + 12,
                                  16, tag) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    mbedtls_gcm_free(&gcm);

    // Build output: IV || ciphertext || tag
    std::memcpy(output, iv, 12);
    std::memcpy(output + 12 + plaintext_len, tag, 16);
    output_len = 12 + plaintext_len + 16;

    return true;

#else
    // Router implementation using OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    // Initialize encryption with AES-128-GCM
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Set IV length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Provide AAD if present
    int len;
    if (aad && aad_len > 0)
    {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Encrypt plaintext
    // Output format: IV || ciphertext || tag
    std::memcpy(output, iv, 12);
    if (EVP_EncryptUpdate(ctx, output + 12, &len, plaintext, static_cast<int>(plaintext_len)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, output + 12 + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    // Get tag (16 bytes)
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Append tag
    std::memcpy(output + 12 + ciphertext_len, tag, 16);
    output_len = 12 + ciphertext_len + 16;

    return true;
#endif
}

bool decryptGCM(const uint8_t* session_key,
               const uint8_t* input, size_t input_len,
               const uint8_t* aad, size_t aad_len,
               uint8_t* plaintext, size_t& plaintext_len)
{
    if (!session_key || !input || !plaintext || input_len < 28)
    {
        return false;
    }

    const uint8_t* iv = input;
    const uint8_t* tag = input + input_len - 16;
    const uint8_t* ciphertext = input + 12;
    size_t ciphertext_len = input_len - 12 - 16;

#if defined(ESP_PLATFORM) || defined(ARDUINO)
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 128) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    // Decrypt and verify tag
    if (mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, iv, 12,
                                 aad, aad_len,
                                 tag, 16,
                                 ciphertext, plaintext) != 0)
    {
        mbedtls_gcm_free(&gcm);
        return false; // Authentication failed
    }

    mbedtls_gcm_free(&gcm);
    plaintext_len = ciphertext_len;
    return true;

#else
    // Router implementation using OpenSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    // Initialize decryption with AES-128-GCM
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Set IV length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Provide AAD if present
    int len;
    if (aad && aad_len > 0)
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, static_cast<int>(ciphertext_len)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int decrypted_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false; // Authentication failed
    }
    decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext_len = decrypted_len;
    return true;
#endif
}

} // namespace crypto
} // namespace mita
