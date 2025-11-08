#ifndef MITA_GCM_CRYPTO_H
#define MITA_GCM_CRYPTO_H

#include "../protocol/protocol_types.h"
#include <cstdint>
#include <cstring>

namespace mita {
namespace crypto {

/**
 * @brief AES-GCM Authenticated Encryption
 * 
 * Platform-agnostic AES-128-GCM encryption with automatic IV generation
 * Format: IV (12 bytes) || ciphertext || tag (16 bytes)
 * 
 * Uses counter-based IV to prevent IV reuse:
 * IV = session_salt (4 bytes) || counter (8 bytes)
 * 
 * @param session_key Derived encryption key (must be SESSION_KEY_SIZE bytes)
 * @param session_salt Random salt generated once per session (4 bytes)
 * @param iv_counter Counter for IV generation (incremented after each call)
 * @param plaintext Plaintext data to encrypt
 * @param plaintext_len Length of plaintext
 * @param aad Additional authenticated data (can be nullptr if aad_len is 0)
 * @param aad_len Length of additional authenticated data
 * @param output Output buffer (must be at least plaintext_len + 28 bytes: 12 IV + plaintext + 16 tag)
 * @param output_len Output: actual length of encrypted data
 * @return true if successful, false otherwise
 */
bool encryptGCM(const uint8_t* session_key,
               uint32_t session_salt,
               uint64_t& iv_counter,
               const uint8_t* plaintext, size_t plaintext_len,
               const uint8_t* aad, size_t aad_len,
               uint8_t* output, size_t& output_len);

/**
 * @brief AES-GCM Authenticated Decryption
 * 
 * Platform-agnostic AES-128-GCM decryption with authentication verification
 * Input format: IV (12 bytes) || ciphertext || tag (16 bytes)
 * 
 * @param session_key Derived encryption key (must be SESSION_KEY_SIZE bytes)
 * @param input Encrypted data (IV || ciphertext || tag)
 * @param input_len Length of encrypted data (must be at least 28 bytes)
 * @param aad Additional authenticated data (must match encryption AAD)
 * @param aad_len Length of additional authenticated data
 * @param plaintext Output buffer for plaintext (must be at least input_len - 28 bytes)
 * @param plaintext_len Output: actual length of decrypted plaintext
 * @return true if successful and authenticated, false if authentication fails or error
 */
bool decryptGCM(const uint8_t* session_key,
               const uint8_t* input, size_t input_len,
               const uint8_t* aad, size_t aad_len,
               uint8_t* plaintext, size_t& plaintext_len);

} // namespace crypto
} // namespace mita

#endif // MITA_GCM_CRYPTO_H
