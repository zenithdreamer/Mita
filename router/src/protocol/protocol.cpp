#include "protocol/protocol.hpp"
#include <stdexcept>
#include <cstring>
#include <mutex>
#include <iomanip>
#include <sstream>
#include "core/logger.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "../../shared/crypto/crypto_utils.h"
#include "../../shared/crypto/gcm_crypto.h"

namespace mita
{
    namespace protocol
    {
        // Shared steady_clock reference point for all timestamp calculations
        // This ensures consistent relative time across handshake operations
        static const auto steady_clock_start = std::chrono::steady_clock::now();

        // ProtocolPacket implementation
        ProtocolPacket::ProtocolPacket(MessageType msg_type, uint16_t source_addr,
                                       uint16_t dest_addr, const std::vector<uint8_t> &payload,
                                       bool encrypted)
            : version_(PROTOCOL_VERSION), msg_type_(static_cast<uint8_t>(msg_type)), source_addr_(source_addr), dest_addr_(dest_addr), payload_(payload)
        {

            if (encrypted)
            {
                flags_ |= FLAG_ENCRYPTED;
            }

            if (payload_.size() > ProtocolPacket::PACKET_MAX_PAYLOAD_SIZE)
            {
                throw std::invalid_argument("Payload too large: " + std::to_string(payload_.size()) +
                                            " > " + std::to_string(ProtocolPacket::PACKET_MAX_PAYLOAD_SIZE));
            }
        }

        void ProtocolPacket::set_encrypted(bool encrypted)
        {
            if (encrypted)
            {
                flags_ |= FLAG_ENCRYPTED;
            }
            else
            {
                flags_ &= ~FLAG_ENCRYPTED;
            }
        }

        void ProtocolPacket::set_fragmented(bool fragmented)
        {
            if (fragmented)
            {
                priority_flags_ |= FLAG_FRAGMENTED;
            }
            else
            {
                priority_flags_ &= ~FLAG_FRAGMENTED;
            }
        }

        void ProtocolPacket::set_payload(const std::vector<uint8_t> &payload)
        {
            if (payload.size() > PACKET_MAX_PAYLOAD_SIZE)
            {
                throw std::invalid_argument("Payload too large");
            }
            payload_ = payload;
        }

        // NOTE: CRC-16 for basic transport-level integrity checking only
        // This is NOT cryptographically secure and should not be relied upon for security
        // Use AES-GCM authentication tags for cryptographic integrity protection
        
        // CRC-16-CCITT implementation
        uint16_t ProtocolPacket::compute_checksum() const
        {
            // Build data without checksum field for CRC calculation
            std::vector<uint8_t> data;
            data.reserve(PACKET_HEADER_SIZE - 2 + payload_.size());
            
            uint8_t version_flags = (version_ << 4) | (flags_ & 0x0F);
            
            // Bytes 0-6 (before checksum)
            data.push_back(version_flags);
            data.push_back(msg_type_);
            data.push_back((source_addr_ >> 8) & 0xFF);
            data.push_back(source_addr_ & 0xFF);
            data.push_back((dest_addr_ >> 8) & 0xFF);
            data.push_back(dest_addr_ & 0xFF);
            data.push_back(static_cast<uint8_t>(payload_.size()));
            
            // Skip bytes 7-8 (checksum field)
            
            // Bytes 9-18 (after checksum)
            data.push_back((sequence_number_ >> 8) & 0xFF);
            data.push_back(sequence_number_ & 0xFF);
            data.push_back(ttl_);
            data.push_back(priority_flags_);
            data.push_back((fragment_id_ >> 8) & 0xFF);
            data.push_back(fragment_id_ & 0xFF);
            data.push_back((timestamp_ >> 24) & 0xFF);
            data.push_back((timestamp_ >> 16) & 0xFF);
            data.push_back((timestamp_ >> 8) & 0xFF);
            data.push_back(timestamp_ & 0xFF);
            
            // Add payload bytes
            data.insert(data.end(), payload_.begin(), payload_.end());
            
            // Compute CRC-16-CCITT
            uint16_t crc = 0xFFFF;
            for (uint8_t byte : data)
            {
                crc ^= (uint16_t)byte << 8;
                for (uint8_t j = 0; j < 8; j++)
                {
                    if (crc & 0x8000)
                    {
                        crc = (crc << 1) ^ 0x1021;  // Polynomial
                    }
                    else
                    {
                        crc = crc << 1;
                    }
                }
            }
            
            return crc;
        }

        bool ProtocolPacket::verify_checksum(uint16_t received_checksum) const
        {
            return compute_checksum() == received_checksum;
        }

        std::vector<uint8_t> ProtocolPacket::to_bytes() const
        {
            std::vector<uint8_t> data(PACKET_HEADER_SIZE + payload_.size());

            uint8_t version_flags = (version_ << 4) | (flags_ & 0x0F);

            data[0] = version_flags;
            data[1] = msg_type_;
            data[2] = (source_addr_ >> 8) & 0xFF;
            data[3] = source_addr_ & 0xFF;
            data[4] = (dest_addr_ >> 8) & 0xFF;
            data[5] = dest_addr_ & 0xFF;
            data[6] = static_cast<uint8_t>(payload_.size());
            
            uint16_t crc = compute_checksum();
            data[7] = (crc >> 8) & 0xFF;  // CRC-16 high byte
            data[8] = crc & 0xFF;          // CRC-16 low byte
            
            data[9] = (sequence_number_ >> 8) & 0xFF;
            data[10] = sequence_number_ & 0xFF;
            data[11] = ttl_;
            data[12] = priority_flags_;
            data[13] = (fragment_id_ >> 8) & 0xFF;
            data[14] = fragment_id_ & 0xFF;
            data[15] = (timestamp_ >> 24) & 0xFF;  // 32-bit timestamp
            data[16] = (timestamp_ >> 16) & 0xFF;
            data[17] = (timestamp_ >> 8) & 0xFF;
            data[18] = timestamp_ & 0xFF;

            std::copy(payload_.begin(), payload_.end(), data.begin() + PACKET_HEADER_SIZE);

            return data;
        }

        std::unique_ptr<ProtocolPacket> ProtocolPacket::from_bytes(const std::vector<uint8_t> &data)
        {
            return from_bytes(data.data(), data.size());
        }

        std::unique_ptr<ProtocolPacket> ProtocolPacket::from_bytes(const uint8_t *data, size_t length)
        {
            if (length < PACKET_HEADER_SIZE)
            {
                throw std::invalid_argument("Insufficient data for header");
            }

            uint8_t version_flags = data[0];
            uint8_t version = (version_flags >> 4) & 0x0F;
            uint8_t flags = version_flags & 0x0F;
            uint8_t msg_type = data[1];
            uint16_t source_addr = (static_cast<uint16_t>(data[2]) << 8) | data[3];
            uint16_t dest_addr = (static_cast<uint16_t>(data[4]) << 8) | data[5];
            uint8_t payload_len = data[6];
            uint16_t received_checksum = (static_cast<uint16_t>(data[7]) << 8) | data[8];  // CRC-16

            uint16_t sequence_number = (static_cast<uint16_t>(data[9]) << 8) | data[10];
            uint8_t ttl = data[11];
            uint8_t priority_flags = data[12];
            uint16_t fragment_id = (static_cast<uint16_t>(data[13]) << 8) | data[14];
            uint32_t timestamp = ((uint32_t)data[15] << 24) | ((uint32_t)data[16] << 16) | 
                                ((uint32_t)data[17] << 8) | data[18];  // 32-bit timestamp

            if (version != PROTOCOL_VERSION)
            {
                throw std::invalid_argument("Unsupported protocol version: " + std::to_string(version));
            }

            if (length < PACKET_HEADER_SIZE + payload_len)
            {
                throw std::invalid_argument("Insufficient data for payload");
            }

            std::vector<uint8_t> payload(data + PACKET_HEADER_SIZE, data + PACKET_HEADER_SIZE + payload_len);
            bool encrypted = (flags & FLAG_ENCRYPTED) != 0;

            auto packet = std::make_unique<ProtocolPacket>(static_cast<MessageType>(msg_type),
                                                           source_addr, dest_addr, payload, encrypted);

            // Set extended header fields
            packet->sequence_number_ = sequence_number;
            packet->ttl_ = ttl;
            packet->priority_flags_ = priority_flags;
            packet->fragment_id_ = fragment_id;
            packet->timestamp_ = timestamp;

            // Verify checksum
            if (!packet->verify_checksum(received_checksum))
            {
                throw std::invalid_argument("Checksum verification failed");
            }

            // Store the verified checksum
            packet->checksum_ = received_checksum;

            return packet;
        }

        // PacketCrypto implementation using OpenSSL
        class PacketCrypto::Impl
        {
        public:
            explicit Impl(const std::vector<uint8_t> &session_key) : session_key_(session_key)
            {
                if (session_key_.size() != 16)
                {
                    throw std::invalid_argument("Session key must be 16 bytes for AES-128");
                }
            }

            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext)
            {
                if (plaintext.empty())
                {
                    return {};
                }

                // Generate random IV
                std::vector<uint8_t> iv(16);
                if (RAND_bytes(iv.data(), 16) != 1)
                {
                    throw std::runtime_error("Failed to generate IV");
                }

                // Create cipher context
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx)
                {
                    throw std::runtime_error("Failed to create cipher context");
                }

                // Initialize encryption
                if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, session_key_.data(), iv.data()) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to initialize encryption");
                }

                // Calculate output size with padding
                size_t max_output_size = plaintext.size() + 16;        // 16 bytes for padding
                std::vector<uint8_t> ciphertext(16 + max_output_size); // IV + encrypted data

                // Copy IV to the beginning
                std::copy(iv.begin(), iv.end(), ciphertext.begin());

                // Encrypt
                int len;
                if (EVP_EncryptUpdate(ctx, ciphertext.data() + 16, &len,
                                      plaintext.data(), static_cast<int>(plaintext.size())) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to encrypt data");
                }

                int ciphertext_len = len;

                // Finalize encryption
                if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + 16 + len, &len) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to finalize encryption");
                }

                ciphertext_len += len;
                EVP_CIPHER_CTX_free(ctx);

                // Resize to actual output size
                ciphertext.resize(16 + ciphertext_len);
                return ciphertext;
            }

            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext)
            {
                if (ciphertext.size() < 16)
                {
                    throw std::invalid_argument("Ciphertext too short - missing IV");
                }

                // Extract IV
                std::vector<uint8_t> iv(ciphertext.begin(), ciphertext.begin() + 16);

                // Create cipher context
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx)
                {
                    throw std::runtime_error("Failed to create cipher context");
                }

                // Initialize decryption
                if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, session_key_.data(), iv.data()) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to initialize decryption");
                }

                // Decrypt
                std::vector<uint8_t> plaintext(ciphertext.size());
                int len;
                if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                      ciphertext.data() + 16, static_cast<int>(ciphertext.size() - 16)) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to decrypt data");
                }

                int plaintext_len = len;

                // Finalize decryption
                if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
                {
                    EVP_CIPHER_CTX_free(ctx);
                    throw std::runtime_error("Failed to finalize decryption");
                }

                plaintext_len += len;
                EVP_CIPHER_CTX_free(ctx);

                // Resize to actual output size
                plaintext.resize(plaintext_len);
                return plaintext;
            }

            std::vector<uint8_t> compute_hmac(const std::vector<uint8_t> &data)
            {
                std::vector<uint8_t> hmac(HMAC_SIZE);
                if (!mita::crypto::computeHMAC(session_key_.data(), session_key_.size(),
                                               data.data(), data.size(), hmac.data()))
                {
                    throw std::runtime_error("Failed to compute HMAC");
                }
                return hmac;
            }

            bool verify_hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &hmac)
            {
                auto computed_hmac = compute_hmac(data);

                if (computed_hmac.size() != hmac.size())
                {
                    return false;
                }

                // Use constant-time comparison to prevent timing attacks
                return mita::crypto::constantTimeCompare(computed_hmac.data(), hmac.data(), hmac.size()) == 0;
            }

        private:
            std::vector<uint8_t> session_key_;
        };

        // Key derivation helper (HKDF-like)
        std::vector<uint8_t> PacketCrypto::derive_subkey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info)
        {
            std::vector<uint8_t> subkey(SESSION_KEY_SIZE);
            if (!mita::crypto::deriveSubkey(key.data(), key.size(), 
                                           info.data(), info.size(), subkey.data()))
            {
                throw std::runtime_error("Failed to derive subkey");
            }
            return subkey;
        }

        PacketCrypto::PacketCrypto(const std::vector<uint8_t> &session_key)
            : session_key_(session_key), iv_counter_(0), impl_(std::make_unique<Impl>(session_key))
        {
            // Derive separate keys for encryption and MAC to prevent key reuse
            std::vector<uint8_t> enc_info = {'E', 'N', 'C'};
            std::vector<uint8_t> mac_info = {'M', 'A', 'C'};
            
            encryption_key_ = derive_subkey(session_key, enc_info);
            mac_key_ = derive_subkey(session_key, mac_info);
            
            // Generate random session salt once per session
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&session_salt_), sizeof(session_salt_)) != 1)
            {
                throw std::runtime_error("Failed to generate session salt");
            }
        }

        PacketCrypto::~PacketCrypto() = default;

        std::vector<uint8_t> PacketCrypto::encrypt(const std::vector<uint8_t> &plaintext)
        {
            return impl_->encrypt(plaintext);
        }

        std::vector<uint8_t> PacketCrypto::decrypt(const std::vector<uint8_t> &ciphertext)
        {
            return impl_->decrypt(ciphertext);
        }

        std::vector<uint8_t> PacketCrypto::compute_hmac(const std::vector<uint8_t> &data)
        {
            return impl_->compute_hmac(data);
        }

        bool PacketCrypto::verify_hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &hmac)
        {
            return impl_->verify_hmac(data, hmac);
        }
        
        // Session key rotation for forward secrecy
        void PacketCrypto::rekey(const std::vector<uint8_t> &nonce3, const std::vector<uint8_t> &nonce4)
        {
            // Derive new session key using shared crypto utils
            std::vector<uint8_t> new_session_key(SESSION_KEY_SIZE);
            if (!mita::crypto::rekeySession(session_key_.data(), 
                                           nonce3.data(), nonce4.data(), 
                                           new_session_key.data()))
            {
                throw std::runtime_error("Failed to derive new session key during rekey");
            }
            
            // Update session key
            session_key_ = new_session_key;
            
            // Re-derive encryption and MAC keys from new session key
            encryption_key_ = derive_subkey(session_key_, std::vector<uint8_t>{'E', 'N', 'C'});
            mac_key_ = derive_subkey(session_key_, std::vector<uint8_t>{'M', 'A', 'C'});
            
            // Reset IV counter for new session
            iv_counter_ = 0;
            
            // Generate new session salt
            RAND_bytes(reinterpret_cast<unsigned char*>(&session_salt_), sizeof(session_salt_));
        }
        
        // Authenticated Encryption (Encrypt-then-MAC)
        std::vector<uint8_t> PacketCrypto::encrypt_authenticated(const std::vector<uint8_t> &plaintext)
        {
            // Step 1: Encrypt with AES-CBC
            auto ciphertext = impl_->encrypt(plaintext);  // Returns IV || encrypted_data
            
            // Step 2: Compute MAC over IV || ciphertext using separate MAC key
            unsigned int mac_len;
            std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);
            
            unsigned char *result = HMAC(
                EVP_sha256(),
                mac_key_.data(), mac_key_.size(),
                ciphertext.data(), ciphertext.size(),
                mac.data(), &mac_len
            );
            
            if (!result)
            {
                throw std::runtime_error("Failed to compute MAC for authenticated encryption");
            }
            
            mac.resize(32);  // SHA256 produces 32 bytes
            
            // Step 3: Return IV || ciphertext || MAC
            ciphertext.insert(ciphertext.end(), mac.begin(), mac.end());
            
            return ciphertext;
        }
        
        // Authenticated Decryption (Verify-then-Decrypt)
        std::vector<uint8_t> PacketCrypto::decrypt_authenticated(const std::vector<uint8_t> &data)
        {
            // Minimum size: 16 (IV) + 16 (min ciphertext with padding) + 32 (MAC) = 64 bytes
            if (data.size() < 64)
            {
                throw std::invalid_argument("Data too short for authenticated decryption");
            }
            
            // Step 1: Split MAC from encrypted data
            size_t mac_offset = data.size() - 32;
            std::vector<uint8_t> received_mac(data.begin() + mac_offset, data.end());
            std::vector<uint8_t> iv_ciphertext(data.begin(), data.begin() + mac_offset);
            
            // Step 2: Verify MAC BEFORE decryption (critical for security!)
            unsigned int mac_len;
            std::vector<uint8_t> computed_mac(EVP_MAX_MD_SIZE);
            
            unsigned char *result = HMAC(
                EVP_sha256(),
                mac_key_.data(), mac_key_.size(),
                iv_ciphertext.data(), iv_ciphertext.size(),
                computed_mac.data(), &mac_len
            );
            
            if (!result)
            {
                throw std::runtime_error("Failed to compute MAC for verification");
            }
            
            computed_mac.resize(32);
            
            // Constant-time comparison to prevent timing attacks
            if (CRYPTO_memcmp(computed_mac.data(), received_mac.data(), 32) != 0)
            {
                throw std::runtime_error("MAC verification failed - data may have been tampered with");
            }
            
            // Step 3: Only decrypt if MAC is valid
            return impl_->decrypt(iv_ciphertext);
        }

        // NEW: AES-GCM Authenticated Encryption Implementation
        std::vector<uint8_t> PacketCrypto::encrypt_gcm(const std::vector<uint8_t> &plaintext,
                                                        const std::vector<uint8_t> &additional_data)
        {
            if (plaintext.empty())
            {
                return {};
            }

            std::vector<uint8_t> output(plaintext.size() + 28);
            size_t output_len;
            
            uint64_t counter_value = iv_counter_.load();

            if (!mita::crypto::encryptGCM(
                    encryption_key_.data(), session_salt_, counter_value,
                    plaintext.data(), plaintext.size(),
                    additional_data.empty() ? nullptr : additional_data.data(),
                    additional_data.size(),
                    output.data(), output_len))
            {
                throw std::runtime_error("Failed to encrypt with GCM");
            }
            
            iv_counter_.store(counter_value);

            output.resize(output_len);
            return output;
        }

        std::vector<uint8_t> PacketCrypto::decrypt_gcm(const std::vector<uint8_t> &data,
                                                        const std::vector<uint8_t> &additional_data)
        {
            // Minimum size: 12 (IV) + 16 (tag) = 28 bytes
            if (data.size() < 28)
            {
                throw std::invalid_argument("Data too short for GCM decryption");
            }

            std::vector<uint8_t> plaintext(data.size() - 28); // Remove IV and tag
            size_t plaintext_len;

            if (!mita::crypto::decryptGCM(
                    encryption_key_.data(),
                    data.data(), data.size(),
                    additional_data.empty() ? nullptr : additional_data.data(),
                    additional_data.size(),
                    plaintext.data(), plaintext_len))
            {
                throw std::runtime_error("GCM authentication failed - data may have been tampered with");
            }

            plaintext.resize(plaintext_len);
            return plaintext;
        }

        // HandshakeManager implementation
        HandshakeManager::HandshakeManager(const std::string &router_id, const std::string &shared_secret)
            : router_id_(router_id), shared_secret_(shared_secret.begin(), shared_secret.end()) {}

        // Derive device-specific PSK from master secret
        // This provides per-device key isolation - compromise of one device doesn't expose master secret
        std::vector<uint8_t> derive_device_psk(const std::vector<uint8_t> &master_secret, 
                                              const std::string &device_id)
        {
            std::vector<uint8_t> device_psk(HMAC_SIZE);
            if (!mita::crypto::deriveDevicePSK(
                    master_secret.data(), master_secret.size(),
                    (const uint8_t*)device_id.c_str(), device_id.length(),
                    device_psk.data()))
            {
                throw std::runtime_error("Failed to derive device PSK");
            }
            
            return device_psk;
        }

        std::unique_ptr<ProtocolPacket> HandshakeManager::create_hello_packet(const std::string &device_id)
        {
            auto nonce1 = generate_nonce();

            // Store handshake state
            HandshakeState state;
            state.device_id = device_id;
            state.nonce1 = nonce1;
            state.timestamp = std::chrono::steady_clock::now();

            {
                std::lock_guard<std::mutex> lock(handshakes_mutex_);
                pending_handshakes_[device_id] = state;
            }

            // Create payload: router_id_len | router_id | device_id_len | device_id | nonce1
            std::vector<uint8_t> payload;
            payload.push_back(static_cast<uint8_t>(router_id_.size()));
            payload.insert(payload.end(), router_id_.begin(), router_id_.end());
            payload.push_back(static_cast<uint8_t>(device_id.size()));
            payload.insert(payload.end(), device_id.begin(), device_id.end());
            payload.insert(payload.end(), nonce1.begin(), nonce1.end());

            return std::make_unique<ProtocolPacket>(MessageType::HELLO, ROUTER_ADDRESS, 0, payload);
        }

        std::vector<uint8_t> HandshakeManager::generate_nonce()
        {
            std::vector<uint8_t> nonce(NONCE_SIZE);
            mita::crypto::generateNonce(nonce.data());
            return nonce;
        }

        std::vector<uint8_t> HandshakeManager::derive_session_key(const std::vector<uint8_t> &nonce1,
                                                                  const std::vector<uint8_t> &nonce2)
        {
            std::vector<uint8_t> session_key(SESSION_KEY_SIZE);
            if (!mita::crypto::deriveSessionKey(
                    shared_secret_.data(), shared_secret_.size(),
                    nonce1.data(), nonce2.data(),
                    session_key.data()))
            {
                throw std::runtime_error("Failed to derive session key");
            }

            return session_key;
        }
        
        // Helper to derive session key using device-specific PSK
        std::vector<uint8_t> HandshakeManager::derive_session_key_with_device_psk(
            const std::vector<uint8_t> &nonce1,
            const std::vector<uint8_t> &nonce2,
            const std::string &device_id)
        {
            // Derive device-specific PSK first
            std::vector<uint8_t> device_psk = derive_device_psk(shared_secret_, device_id);
            
            std::vector<uint8_t> session_key(SESSION_KEY_SIZE);
            if (!mita::crypto::deriveSessionKey(
                    device_psk.data(), device_psk.size(),
                    nonce1.data(), nonce2.data(),
                    session_key.data()))
            {
                throw std::runtime_error("Failed to derive session key with device PSK");
            }

            return session_key;
        }

        bool HandshakeManager::process_hello_packet(const ProtocolPacket &packet, std::string &device_id, std::vector<uint8_t> &nonce1)
        {
            // Extract device_id and nonce1 from payload
            // HELLO payload format: router_id_len | router_id | device_id_len | device_id | nonce1(16 bytes)
            const auto &payload = packet.get_payload();
            if (payload.size() < 2)
                return false;

            size_t offset = 0;
            uint8_t router_id_len = payload[offset++];
            if (offset + router_id_len >= payload.size())
                return false;

            std::string received_router_id(payload.begin() + offset, payload.begin() + offset + router_id_len);
            offset += router_id_len;

            if (offset >= payload.size())
                return false;
            uint8_t device_id_len = payload[offset++];
            if (offset + device_id_len > payload.size())
                return false;

            device_id = std::string(payload.begin() + offset, payload.begin() + offset + device_id_len);
            offset += device_id_len;
            
            // Extract nonce1 (16 bytes)
            if (offset + NONCE_SIZE > payload.size())
            {
                auto logger = core::get_logger("Protocol");
                if (logger)
                    logger->warning("HELLO packet missing nonce1", 
                                  core::LogContext().add("payload_size", payload.size()));
                return false;
            }
            
            nonce1.assign(payload.begin() + offset, payload.begin() + offset + NONCE_SIZE);
            
            return received_router_id == router_id_;
        }

        std::unique_ptr<PacketCrypto> HandshakeManager::get_session_crypto(const std::string &device_id)
        {
            std::lock_guard<std::mutex> lock(handshakes_mutex_);
            auto it = pending_handshakes_.find(device_id);
            if (it != pending_handshakes_.end() && !it->second.session_key.empty())
            {
                return std::make_unique<PacketCrypto>(it->second.session_key);
            }
            return nullptr;
        }

        void HandshakeManager::cleanup_expired_handshakes(std::chrono::seconds timeout)
        {
            auto cutoff = std::chrono::steady_clock::now() - timeout;
            std::lock_guard<std::mutex> lock(handshakes_mutex_);

            auto it = pending_handshakes_.begin();
            while (it != pending_handshakes_.end())
            {
                if (it->second.timestamp < cutoff)
                {
                    it = pending_handshakes_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }
        
        bool HandshakeManager::is_nonce_reused(const std::vector<uint8_t> &nonce)
        {
            std::lock_guard<std::mutex> lock(nonce_tracking_mutex_);
            auto now = std::chrono::steady_clock::now();
            
            // Remove expired nonces
            while (!recent_nonces_.empty())
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - recent_nonces_.front().timestamp);
                
                if (age > nonce_expiry_)
                {
                    recent_nonces_.pop_front();
                }
                else
                {
                    break;
                }
            }
            
            // Check if nonce exists in recent history
            for (const auto &record : recent_nonces_)
            {
                if (record.nonce == nonce)
                {
                    auto logger = core::get_logger("Protocol");
                    if (logger)
                    {
                        logger->warning("Nonce reuse detected - possible replay attack",
                                      core::LogContext()
                                          .add("nonce_size", nonce.size()));
                    }
                    return true;  // Nonce is being reused
                }
            }
            
            return false;  // Nonce is unique
        }

        void HandshakeManager::record_nonce(const std::vector<uint8_t> &nonce)
        {
            std::lock_guard<std::mutex> lock(nonce_tracking_mutex_);
            
            // Add to history
            recent_nonces_.push_back({nonce, std::chrono::steady_clock::now()});
            
            // Limit history size
            if (recent_nonces_.size() > max_nonce_history_)
            {
                recent_nonces_.pop_front();
            }
        }
        
        bool HandshakeManager::check_global_rate_limit()
        {
            std::lock_guard<std::mutex> lock(global_rate_limit_mutex_);
            auto now = std::chrono::steady_clock::now();
            
            // Remove attempts older than the window
            while (!global_handshake_attempts_.empty())
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - global_handshake_attempts_.front());
                
                if (age > global_window_)
                {
                    global_handshake_attempts_.pop_front();
                }
                else
                {
                    break;
                }
            }
            
            // Check if too many global attempts
            if (global_handshake_attempts_.size() >= global_max_attempts_)
            {
                auto logger = core::get_logger("Protocol");
                if (logger)
                {
                    logger->warning("GLOBAL rate limit exceeded - possible distributed DoS attack",
                                  core::LogContext()
                                      .add("global_attempts", global_handshake_attempts_.size())
                                      .add("window_seconds", global_window_.count()));
                }
                return false;  // Global rate limit exceeded
            }
            
            // Record this attempt
            global_handshake_attempts_.push_back(now);
            return true;  // Allowed
        }

        bool HandshakeManager::check_rate_limit(const std::string &source_id)
        {
            // Check global rate limit first
            if (!check_global_rate_limit())
            {
                return false;  // Global limit exceeded
            }

            std::lock_guard<std::mutex> lock(rate_limit_mutex_);
            auto now = std::chrono::steady_clock::now();
            
            auto &state = rate_limits_[source_id];
            
            // Remove attempts older than the window
            while (!state.attempts.empty())
            {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - state.attempts.front());
                
                if (age > state.window)
                {
                    state.attempts.pop_front();
                }
                else
                {
                    break;
                }
            }
            
            // Check if too many attempts
            if (state.attempts.size() >= state.max_attempts)
            {
                auto logger = core::get_logger("Protocol");
                if (logger)
                {
                    logger->warning("Rate limit exceeded for handshake",
                                  core::LogContext()
                                      .add("source_id", source_id)
                                      .add("attempts", state.attempts.size()));
                }
                return false;  // Rate limit exceeded
            }
            
            // Record this attempt
            state.attempts.push_back(now);
            return true;  // Allowed
        }

        std::unique_ptr<ProtocolPacket> HandshakeManager::create_challenge_packet(const std::string &device_id, const std::vector<uint8_t> &nonce1)
        {
            // Check if nonce is being reused
            if (is_nonce_reused(nonce1))
            {
                auto logger = core::get_logger("Protocol");
                if (logger)
                {
                    logger->warning("Rejecting HELLO with reused nonce - possible replay attack",
                                  core::LogContext().add("device_id", device_id));
                }
                return nullptr;  // Reject handshake with reused nonce
            }
            
            // Record nonce to prevent future reuse
            record_nonce(nonce1);
            
            auto nonce2 = generate_nonce();

            // Get current timestamp using shared steady_clock reference point
            // This ensures consistent timestamps between create_challenge and verify_auth
            auto now = std::chrono::steady_clock::now();
            uint64_t timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        now - steady_clock_start)
                                        .count();

            // Store / update handshake state with nonce1 and nonce2
            {
                std::lock_guard<std::mutex> lock(handshakes_mutex_);
                auto &state = pending_handshakes_[device_id];
                state.device_id = device_id;
                if (state.nonce1.empty())
                {
                    state.nonce1 = nonce1; // capture nonce1 supplied by device
                }
                state.nonce2 = nonce2;
                state.timestamp = std::chrono::steady_clock::now();
                state.creation_time_ms = timestamp_ms;  // Store for freshness validation
            }

            // Create payload: nonce2 (16 bytes) || timestamp (8 bytes)
            std::vector<uint8_t> payload = nonce2;
            
            // Append timestamp (big-endian, 8 bytes)
            for (int i = 7; i >= 0; i--)
            {
                payload.push_back((timestamp_ms >> (i * 8)) & 0xFF);
            }

            return std::make_unique<ProtocolPacket>(MessageType::CHALLENGE, ROUTER_ADDRESS, 0, payload);
        }

        bool HandshakeManager::verify_auth_packet(const std::string &device_id, const ProtocolPacket &packet)
        {
            auto logger = core::get_logger("Protocol");
            if (logger)
            {
                logger->debug("verify_auth_packet start", core::LogContext().add("device_id", device_id).add("msg_type", static_cast<int>(packet.get_message_type())));
            }

            if (packet.get_message_type() != MessageType::AUTH)
            {
                if (logger)
                    logger->debug("verify_auth_packet: wrong message type");
                return false;
            }

            std::lock_guard<std::mutex> lock(handshakes_mutex_);
            auto it = pending_handshakes_.find(device_id);
            if (it == pending_handshakes_.end())
            {
                if (logger)
                    logger->debug("verify_auth_packet: no pending handshake", core::LogContext().add("device_id", device_id));
                return false;
            }
            
            // Validate handshake freshness (10 second window - reduced from 30s)
            if (it->second.creation_time_ms > 0)
            {
                // Use shared steady_clock reference point (same as CHALLENGE creation)
                auto now = std::chrono::steady_clock::now();
                uint64_t current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - steady_clock_start).count();
                
                const uint64_t MAX_HANDSHAKE_AGE_MS = 10000;  // 10 seconds (reduced from 30)
                uint64_t handshake_age = current_time_ms - it->second.creation_time_ms;
                
                if (handshake_age > MAX_HANDSHAKE_AGE_MS)
                {
                    if (logger)
                        logger->warning("Handshake expired - possible replay attack",
                                      core::LogContext()
                                          .add("device_id", device_id)
                                          .add("age_ms", handshake_age));
                    
                    // Remove expired handshake
                    pending_handshakes_.erase(it);
                    return false;
                }
            }

            const auto &payload = packet.get_payload();
            if (logger)
                logger->debug("verify_auth_packet: received payload", core::LogContext().add("size", payload.size()));
            if (payload.size() < 32)
            { // 16 bytes HMAC + 16 bytes nonce1 (increased from 4 to 16)
                if (logger)
                    logger->debug("verify_auth_packet: payload too small", core::LogContext().add("size", payload.size()));
                return false;
            }

            // Extract received tag (first 16 bytes)
            std::vector<uint8_t> received_tag(payload.begin(), payload.begin() + 16);

            // Extract received nonce1 (next 16 bytes)
            std::vector<uint8_t> received_nonce1(payload.begin() + 16, payload.begin() + 32);

            // Verify nonce1 matches what was sent in HELLO
            const auto &expected_nonce1 = it->second.nonce1;
            if (expected_nonce1.size() != 16)
            {
                if (logger)
                    logger->debug("verify_auth_packet: stored nonce1 invalid size", core::LogContext().add("size", expected_nonce1.size()));
                return false;
            }

            if (received_nonce1 != expected_nonce1)
            {
                if (logger)
                    logger->debug("verify_auth_packet: nonce1 mismatch");
                return false;
            }

            // Construct data for HMAC: nonce2 (16 bytes) + device_id + router_id
            const auto &nonce2_vec = it->second.nonce2;
            if (nonce2_vec.size() != 16)
            {
                if (logger)
                    logger->debug("verify_auth_packet: nonce2 invalid size", core::LogContext().add("size", nonce2_vec.size()));
                return false;
            }
            std::vector<uint8_t> hmac_data;
            hmac_data.reserve(16 + device_id.size() + router_id_.size());
            hmac_data.insert(hmac_data.end(), nonce2_vec.begin(), nonce2_vec.end());  // Full 16 bytes
            hmac_data.insert(hmac_data.end(), device_id.begin(), device_id.end());
            hmac_data.insert(hmac_data.end(), router_id_.begin(), router_id_.end());

            // Derive device-specific PSK for this authentication
            std::vector<uint8_t> device_psk = derive_device_psk(shared_secret_, device_id);

            unsigned int hmac_len = 0;
            std::vector<uint8_t> expected_tag(EVP_MAX_MD_SIZE);
            unsigned char *result = HMAC(EVP_sha256(),
                                         device_psk.data(), static_cast<int>(device_psk.size()),
                                         hmac_data.data(), hmac_data.size(),
                                         expected_tag.data(), &hmac_len);
            if (!result)
            {
                return false;
            }
            expected_tag.resize(16); // Truncate to 16 bytes

            if (CRYPTO_memcmp(received_tag.data(), expected_tag.data(), 16) != 0)
            {
                auto to_hex = [](const std::vector<uint8_t> &v)
                {
                    std::string s;
                    for (uint8_t b : v)
                    {
                        char buf[3];
                        snprintf(buf, sizeof(buf), "%02X", b);
                        s += buf;
                    }
                    return s;
                };
                if (logger)
                    logger->debug("verify_auth_packet: HMAC mismatch", core::LogContext().add("expected", to_hex(expected_tag)).add("received", to_hex(received_tag)));
                return false;
            }

            // Successful verification -> derive and store session key if not already present
            if (it->second.session_key.empty())
            {
                // Use device-specific PSK for session key derivation
                it->second.session_key = derive_session_key_with_device_psk(
                    it->second.nonce1, 
                    it->second.nonce2,
                    device_id
                );
            }

            return true;
        }

        std::unique_ptr<ProtocolPacket> HandshakeManager::create_auth_ack_packet(const std::string &device_id, uint16_t assigned_address)
        {
            // Python implementation includes: 16-byte HMAC(nonce1) + 2-byte assigned address
            // HMAC is computed with shared_secret over nonce1 (big-endian 4 bytes)
            std::vector<uint8_t> payload;

            std::vector<uint8_t> nonce1_copy;
            {
                std::lock_guard<std::mutex> lock(handshakes_mutex_);
                auto it = pending_handshakes_.find(device_id);
                if (it != pending_handshakes_.end())
                {
                    nonce1_copy = it->second.nonce1; // should be 16 bytes
                }
            }

            if (nonce1_copy.size() == 16)
            {
                // Derive device-specific PSK
                std::vector<uint8_t> device_psk = derive_device_psk(shared_secret_, device_id);
                
                unsigned int hmac_len = 0;
                std::vector<uint8_t> tag(EVP_MAX_MD_SIZE);
                unsigned char *result = HMAC(EVP_sha256(),
                                             device_psk.data(), static_cast<int>(device_psk.size()),
                                             nonce1_copy.data(), 16,  // Full 16 bytes
                                             tag.data(), &hmac_len);
                if (result)
                {
                    tag.resize(16); // truncate to 16 bytes
                    payload.insert(payload.end(), tag.begin(), tag.end());
                }
            }
            else
            {
                // Fallback: no nonce captured or invalid size, leave out HMAC (client may reject)
            }

            // Append assigned address (big-endian)
            payload.push_back((assigned_address >> 8) & 0xFF);
            payload.push_back(assigned_address & 0xFF);

            auto logger = core::get_logger("Protocol");
            if (logger)
            {
                logger->debug("create_auth_ack_packet", core::LogContext().add("device_id", device_id).add("payload_size", payload.size()));
            }

            return std::make_unique<ProtocolPacket>(MessageType::AUTH_ACK, ROUTER_ADDRESS, assigned_address, payload);
        }

        void HandshakeManager::remove_handshake(const std::string &device_id)
        {
            std::lock_guard<std::mutex> lock(handshakes_mutex_);
            pending_handshakes_.erase(device_id);
        }

        // Utility functions
        namespace utils
        {
            uint64_t get_current_timestamp_ms()
            {
                auto now = std::chrono::steady_clock::now();
                return std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - steady_clock_start)
                           .count();
            }

            bool parse_hello_packet(const ProtocolPacket &packet, std::string &router_id,
                                    std::string &device_id, std::vector<uint8_t> &nonce1)
            {
                if (packet.get_message_type() != MessageType::HELLO)
                {
                    return false;
                }

                const auto &payload = packet.get_payload();
                if (payload.size() < 2)
                    return false;

                size_t offset = 0;
                uint8_t router_id_len = payload[offset++];
                if (offset + router_id_len >= payload.size())
                    return false;

                router_id = std::string(payload.begin() + offset, payload.begin() + offset + router_id_len);
                offset += router_id_len;

                if (offset >= payload.size())
                    return false;
                uint8_t device_id_len = payload[offset++];
                if (offset + device_id_len >= payload.size())
                    return false;

                device_id = std::string(payload.begin() + offset, payload.begin() + offset + device_id_len);
                offset += device_id_len;

                if (offset + NONCE_SIZE > payload.size())
                    return false;
                nonce1 = std::vector<uint8_t>(payload.begin() + offset, payload.begin() + offset + NONCE_SIZE);

                return true;
            }

            bool parse_auth_packet(const ProtocolPacket &packet, std::vector<uint8_t> &nonce2,
                                   std::vector<uint8_t> &auth_hmac)
            {
                if (packet.get_message_type() != MessageType::AUTH)
                {
                    return false;
                }

                const auto &payload = packet.get_payload();
                if (payload.size() < NONCE_SIZE + HMAC_SIZE)
                {
                    return false;
                }

                // Extract nonce2 (4 bytes)
                nonce2 = std::vector<uint8_t>(payload.begin(), payload.begin() + NONCE_SIZE);

                // Extract HMAC (32 bytes)
                auth_hmac = std::vector<uint8_t>(payload.begin() + NONCE_SIZE,
                                                 payload.begin() + NONCE_SIZE + HMAC_SIZE);

                return true;
            }

            bool validate_packet(const ProtocolPacket &packet)
            {
                // Basic validation
                return packet.get_payload().size() <= ProtocolPacket::PACKET_MAX_PAYLOAD_SIZE;
            }

            uint16_t calculate_checksum(const std::vector<uint8_t> &data)
            {
                uint32_t sum = 0;
                for (size_t i = 0; i < data.size(); i += 2)
                {
                    uint16_t word = data[i];
                    if (i + 1 < data.size())
                    {
                        word |= (static_cast<uint16_t>(data[i + 1]) << 8);
                    }
                    sum += word;
                }

                while (sum >> 16)
                {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }

                return static_cast<uint16_t>(~sum);
            }

        } // namespace utils

    } // namespace protocol
} // namespace mita