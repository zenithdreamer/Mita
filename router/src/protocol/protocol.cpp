#include "protocol/protocol.hpp"
#include <stdexcept>
#include <cstring>
#include <mutex>
#include "core/logger.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace mita
{
    namespace protocol
    {

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

        void ProtocolPacket::set_payload(const std::vector<uint8_t> &payload)
        {
            if (payload.size() > PACKET_MAX_PAYLOAD_SIZE)
            {
                throw std::invalid_argument("Payload too large");
            }
            payload_ = payload;
        }

        uint8_t ProtocolPacket::compute_checksum() const
        {
            uint32_t sum = 0;

            uint8_t version_flags = (version_ << 4) | (flags_ & 0x0F);
            sum += version_flags;
            sum += msg_type_;
            sum += (source_addr_ >> 8) & 0xFF;
            sum += source_addr_ & 0xFF;
            sum += (dest_addr_ >> 8) & 0xFF;
            sum += dest_addr_ & 0xFF;
            sum += static_cast<uint8_t>(payload_.size());

            // Add payload bytes
            for (uint8_t byte : payload_)
            {
                sum += byte;
            }

            // Return 8-bit checksum (sum of all bytes modulo 256, then one's complement)
            return static_cast<uint8_t>(~sum);
        }

        bool ProtocolPacket::verify_checksum(uint8_t received_checksum) const
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
            data[7] = compute_checksum();

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
            uint8_t received_checksum = data[7];

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
                unsigned int hmac_len;
                std::vector<uint8_t> hmac(EVP_MAX_MD_SIZE);

                unsigned char *result = HMAC(EVP_sha256(), session_key_.data(), session_key_.size(),
                                             data.data(), data.size(), hmac.data(), &hmac_len);

                if (!result)
                {
                    throw std::runtime_error("Failed to compute HMAC");
                }

                hmac.resize(hmac_len);
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
                return CRYPTO_memcmp(computed_hmac.data(), hmac.data(), hmac.size()) == 0;
            }

        private:
            std::vector<uint8_t> session_key_;
        };

        PacketCrypto::PacketCrypto(const std::vector<uint8_t> &session_key)
            : session_key_(session_key), impl_(std::make_unique<Impl>(session_key)) {}

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

        // HandshakeManager implementation
        HandshakeManager::HandshakeManager(const std::string &router_id, const std::string &shared_secret)
            : router_id_(router_id), shared_secret_(shared_secret.begin(), shared_secret.end()) {}

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
            RAND_bytes(nonce.data(), NONCE_SIZE);
            return nonce;
        }

        std::vector<uint8_t> HandshakeManager::derive_session_key(const std::vector<uint8_t> &nonce1,
                                                                  const std::vector<uint8_t> &nonce2)
        {
            // Key derivation using HMAC-SHA256 (matches Python implementation)
            std::vector<uint8_t> key_data;
            key_data.insert(key_data.end(), nonce1.begin(), nonce1.end());
            key_data.insert(key_data.end(), nonce2.begin(), nonce2.end());

            unsigned int hmac_len;
            std::vector<uint8_t> derived_key(EVP_MAX_MD_SIZE);

            unsigned char *result = HMAC(EVP_sha256(), shared_secret_.data(), shared_secret_.size(),
                                         key_data.data(), key_data.size(), derived_key.data(), &hmac_len);

            if (!result)
            {
                throw std::runtime_error("Failed to derive session key");
            }

            // Return first 16 bytes for AES-128
            derived_key.resize(SESSION_KEY_SIZE);
            return derived_key;
        }

        bool HandshakeManager::process_hello_packet(const ProtocolPacket &packet, std::string &device_id)
        {
            // Simplified implementation - extract device_id from payload
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

        std::unique_ptr<ProtocolPacket> HandshakeManager::create_challenge_packet(const std::string &device_id, const std::vector<uint8_t> &nonce1)
        {
            auto nonce2 = generate_nonce();

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
            }

            // Create payload: nonce2
            std::vector<uint8_t> payload = nonce2;

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

            const auto &payload = packet.get_payload();
            if (logger)
                logger->debug("verify_auth_packet: received payload", core::LogContext().add("size", payload.size()));
            if (payload.size() < 20)
            { // 16 bytes HMAC + 4 bytes nonce1
                if (logger)
                    logger->debug("verify_auth_packet: payload too small", core::LogContext().add("size", payload.size()));
                return false;
            }

            // Extract received tag (first 16 bytes)
            std::vector<uint8_t> received_tag(payload.begin(), payload.begin() + 16);

            // Extract received nonce1 (next 4 bytes big-endian)
            uint32_t received_nonce1 = 0;
            for (int i = 0; i < 4; i++)
            {
                received_nonce1 = (received_nonce1 << 8) | payload[16 + i];
            }

            // Expected nonce1 from stored state
            uint32_t expected_nonce1 = 0;
            const auto &nonce1_vec = it->second.nonce1;
            if (nonce1_vec.size() >= 4)
            {
                for (int i = 0; i < 4; i++)
                {
                    expected_nonce1 = (expected_nonce1 << 8) | nonce1_vec[i];
                }
            }

            if (received_nonce1 != expected_nonce1)
            {
                if (logger)
                    logger->debug("verify_auth_packet: nonce1 mismatch", core::LogContext().add("expected", expected_nonce1).add("received", received_nonce1));
                return false;
            }

            // Construct data for HMAC: nonce2 (4 bytes) + device_id + router_id
            const auto &nonce2_vec = it->second.nonce2;
            if (nonce2_vec.size() < 4)
            {
                if (logger)
                    logger->debug("verify_auth_packet: nonce2 missing or too small", core::LogContext().add("size", nonce2_vec.size()));
                return false;
            }
            std::vector<uint8_t> hmac_data;
            hmac_data.reserve(4 + device_id.size() + router_id_.size());
            hmac_data.insert(hmac_data.end(), nonce2_vec.begin(), nonce2_vec.begin() + 4);
            hmac_data.insert(hmac_data.end(), device_id.begin(), device_id.end());
            hmac_data.insert(hmac_data.end(), router_id_.begin(), router_id_.end());

            unsigned int hmac_len = 0;
            std::vector<uint8_t> expected_tag(EVP_MAX_MD_SIZE);
            unsigned char *result = HMAC(EVP_sha256(),
                                         shared_secret_.data(), static_cast<int>(shared_secret_.size()),
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
                it->second.session_key = derive_session_key(it->second.nonce1, it->second.nonce2);
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
                    nonce1_copy = it->second.nonce1; // should be 4 bytes
                }
            }

            if (nonce1_copy.size() >= 4)
            {
                unsigned int hmac_len = 0;
                std::vector<uint8_t> tag(EVP_MAX_MD_SIZE);
                unsigned char *result = HMAC(EVP_sha256(),
                                             shared_secret_.data(), static_cast<int>(shared_secret_.size()),
                                             nonce1_copy.data(), 4,
                                             tag.data(), &hmac_len);
                if (result)
                {
                    tag.resize(16); // truncate to 16 bytes like Python
                    payload.insert(payload.end(), tag.begin(), tag.end());
                }
            }
            else
            {
                // Fallback: no nonce captured, leave out HMAC (client may reject)
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