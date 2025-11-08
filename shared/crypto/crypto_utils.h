#ifndef MITA_CRYPTO_UTILS_H
#define MITA_CRYPTO_UTILS_H

#include "../protocol/protocol_types.h"
#include <cstdint>
#include <cstring>

namespace mita {
namespace crypto {

/**
 * @brief Compute HMAC-SHA256
 * 
 * Platform-agnostic HMAC computation that works with both mbedtls (ESP32) and OpenSSL (router)
 * 
 * @param key Key for HMAC
 * @param key_len Length of key in bytes
 * @param data Data to compute HMAC over
 * @param data_len Length of data in bytes
 * @param hmac_out Output buffer for HMAC (must be at least HMAC_SIZE bytes)
 * @return true if successful, false otherwise
 */
bool computeHMAC(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t* hmac_out);

/**
 * @brief Derive device-specific PSK from master secret
 * 
 * Device_PSK = HMAC-SHA256(master_secret, "DEVICE_PSK" || device_id)
 * This matches the implementation used by both router and client for compatibility
 * 
 * @param master_secret Master shared secret
 * @param master_secret_len Length of master secret
 * @param device_id Device identifier string
 * @param device_id_len Length of device_id
 * @param device_psk_out Output buffer for device PSK (must be at least HMAC_SIZE bytes)
 * @return true if successful, false otherwise
 */
bool deriveDevicePSK(const uint8_t* master_secret, size_t master_secret_len,
                    const uint8_t* device_id, size_t device_id_len,
                    uint8_t* device_psk_out);

/**
 * @brief Derive session key from PSK and nonces
 * 
 * SessionKey = HMAC-SHA256(PSK, Nonce1 || Nonce2)
 * Takes first SESSION_KEY_SIZE bytes for AES-128
 * 
 * @param psk Pre-shared key (device PSK)
 * @param psk_len Length of PSK
 * @param nonce1 First nonce (from HELLO/CHALLENGE)
 * @param nonce2 Second nonce (from CHALLENGE/AUTH)
 * @param session_key_out Output buffer for session key (must be at least SESSION_KEY_SIZE bytes)
 * @return true if successful, false otherwise
 */
bool deriveSessionKey(const uint8_t* psk, size_t psk_len,
                     const uint8_t* nonce1, const uint8_t* nonce2,
                     uint8_t* session_key_out);

/**
 * @brief Rekey session from old session key and new nonces
 * 
 * New_Session_Key = HMAC-SHA256(old_session_key, nonce3 || nonce4)
 * Used for forward secrecy during session rekeying
 * 
 * @param old_session_key Current session key
 * @param nonce3 First nonce for rekeying
 * @param nonce4 Second nonce for rekeying
 * @param new_session_key_out Output buffer for new session key (must be at least SESSION_KEY_SIZE bytes)
 * @return true if successful, false otherwise
 */
bool rekeySession(const uint8_t* old_session_key,
                 const uint8_t* nonce3, const uint8_t* nonce4,
                 uint8_t* new_session_key_out);

/**
 * @brief Derive subkey from key using info string (HKDF-like)
 * 
 * Subkey = HMAC-SHA256(key, info)[0:SESSION_KEY_SIZE]
 * Used to derive separate encryption and MAC keys from session key
 * 
 * @param key Input key
 * @param key_len Length of key
 * @param info Info string (e.g., "ENC", "MAC")
 * @param info_len Length of info string
 * @param subkey_out Output buffer for subkey (must be at least SESSION_KEY_SIZE bytes)
 * @return true if successful, false otherwise
 */
bool deriveSubkey(const uint8_t* key, size_t key_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* subkey_out);

/**
 * @brief Generate random nonce
 * 
 * Platform-agnostic random nonce generation
 * Uses esp_random() on ESP32, RAND_bytes on OpenSSL platforms
 * 
 * @param nonce_out Output buffer for nonce (must be NONCE_SIZE bytes)
 */
void generateNonce(uint8_t* nonce_out);

/**
 * @brief Constant-time memory comparison
 * 
 * Prevents timing attacks when comparing secrets
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len);

} // namespace crypto
} // namespace mita

#endif // MITA_CRYPTO_UTILS_H
