#ifndef MITA_ROUTER_PROTOCOL_HPP
#define MITA_ROUTER_PROTOCOL_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <deque>
#include <chrono>
#include <mutex>
#include "protocol/protocol_types.h"

namespace mita
{
    namespace protocol
    {
        // Use constants from shared header - no need to redefine

        /**
         * Enhanced protocol packet structure for router
         */
        class ProtocolPacket
        {
        public:
            // Use macros from shared header to avoid conflicts
            static constexpr size_t PACKET_HEADER_SIZE = HEADER_SIZE;
            static constexpr size_t PACKET_MAX_PAYLOAD_SIZE = MAX_PAYLOAD_SIZE;

            ProtocolPacket() = default;
            ProtocolPacket(MessageType msg_type, uint16_t source_addr = 0,
                           uint16_t dest_addr = 0, const std::vector<uint8_t> &payload = {},
                           bool encrypted = false);

            // Serialization
            std::vector<uint8_t> to_bytes() const;
            static std::unique_ptr<ProtocolPacket> from_bytes(const std::vector<uint8_t> &data);
            static std::unique_ptr<ProtocolPacket> from_bytes(const uint8_t *data, size_t length);

            // Getters
            uint8_t get_version() const { return version_; }
            uint8_t get_flags() const { return flags_; }
            MessageType get_message_type() const { return static_cast<MessageType>(msg_type_); }
            uint16_t get_source_addr() const { return source_addr_; }
            uint16_t get_dest_addr() const { return dest_addr_; }
            const std::vector<uint8_t> &get_payload() const { return payload_; }
            bool is_encrypted() const { return flags_ & FLAG_ENCRYPTED; }
            uint8_t get_checksum() const { return checksum_; }
            uint16_t get_sequence_number() const { return sequence_number_; }
            uint8_t get_ttl() const { return ttl_; }
            uint8_t get_priority() const { return priority_flags_ & PRIORITY_MASK; }
            uint8_t get_priority_flags() const { return priority_flags_; }
            uint16_t get_fragment_id() const { return fragment_id_; }
            uint16_t get_timestamp() const { return timestamp_; }
            bool is_fragmented() const { return priority_flags_ & FLAG_FRAGMENTED; }
            bool has_more_fragments() const { return priority_flags_ & FLAG_MORE_FRAGMENTS; }

            // Setters
            void set_encrypted(bool encrypted);
            void set_source_addr(uint16_t addr) { source_addr_ = addr; }
            void set_dest_addr(uint16_t addr) { dest_addr_ = addr; }
            void set_payload(const std::vector<uint8_t> &payload);
            void set_sequence_number(uint16_t seq) { sequence_number_ = seq; }
            void set_ttl(uint8_t ttl) { ttl_ = ttl; }
            void set_priority(uint8_t priority) { priority_flags_ = (priority_flags_ & ~PRIORITY_MASK) | (priority & PRIORITY_MASK); }
            void set_fragment_id(uint16_t frag_id) { fragment_id_ = frag_id; }
            void set_timestamp(uint16_t ts) { timestamp_ = ts; }
            void set_fragmented(bool fragmented);
            void decrement_ttl() { if (ttl_ > 0) ttl_--; }

        private:
            uint8_t version_ = PROTOCOL_VERSION;
            uint8_t flags_ = 0;
            uint8_t msg_type_ = 0;
            uint16_t source_addr_ = 0;
            uint16_t dest_addr_ = 0;
            uint8_t checksum_ = 0;
            uint16_t sequence_number_ = 0;
            uint8_t ttl_ = DEFAULT_TTL;
            uint8_t priority_flags_ = PRIORITY_NORMAL;
            uint16_t fragment_id_ = 0;
            uint16_t timestamp_ = 0;
            std::vector<uint8_t> payload_;

            uint8_t compute_checksum() const;
            bool verify_checksum(uint8_t received_checksum) const;
        };

        /**
         * Cryptographic functions for packet security
         */
        class PacketCrypto
        {
        public:
            PacketCrypto(const std::vector<uint8_t> &session_key);
            ~PacketCrypto();

            // Legacy: Encryption/Decryption (basic - DEPRECATED, kept for compatibility)
            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);
            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);

            // Legacy: Encrypt-then-MAC (DEPRECATED, use GCM instead)
            std::vector<uint8_t> encrypt_authenticated(const std::vector<uint8_t> &plaintext);
            std::vector<uint8_t> decrypt_authenticated(const std::vector<uint8_t> &data);

            // NEW: AES-GCM Authenticated Encryption (RECOMMENDED)
            // GCM provides both confidentiality and authenticity in one operation
            std::vector<uint8_t> encrypt_gcm(const std::vector<uint8_t> &plaintext, 
                                              const std::vector<uint8_t> &additional_data = {});
            std::vector<uint8_t> decrypt_gcm(const std::vector<uint8_t> &ciphertext,
                                              const std::vector<uint8_t> &additional_data = {});

            // HMAC verification (legacy, for control packets)
            std::vector<uint8_t> compute_hmac(const std::vector<uint8_t> &data);
            bool verify_hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &hmac);

        private:
            std::vector<uint8_t> session_key_;
            std::vector<uint8_t> encryption_key_;  // Derived key for AES
            std::vector<uint8_t> mac_key_;         // Derived key for HMAC (separate from encryption key)
            class Impl;
            std::unique_ptr<Impl> impl_;
            
            // Key derivation helper
            std::vector<uint8_t> derive_subkey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &info);
        };

        /**
         * Handshake manager for device authentication
         */
        class HandshakeManager
        {
        public:
            struct HandshakeState
            {
                std::string device_id;
                std::vector<uint8_t> nonce1;
                std::vector<uint8_t> nonce2;
                std::vector<uint8_t> session_key;
                std::chrono::steady_clock::time_point timestamp;
                uint64_t creation_time_ms = 0;  // Unix timestamp for freshness validation
                int attempts = 0;
            };
            
            // Rate limiting structure
            struct RateLimitState
            {
                std::deque<std::chrono::steady_clock::time_point> attempts;
                size_t max_attempts = 5;
                std::chrono::seconds window{60};
            };

            HandshakeManager(const std::string &router_id, const std::string &shared_secret);

            // Handshake packet creation
            std::unique_ptr<ProtocolPacket> create_hello_packet(const std::string &device_id);
            std::unique_ptr<ProtocolPacket> create_challenge_packet(const std::string &device_id,
                                                                    const std::vector<uint8_t> &nonce1);
            std::unique_ptr<ProtocolPacket> create_auth_ack_packet(const std::string &device_id,
                                                                   uint16_t assigned_address);

            // Handshake packet processing
            bool process_hello_packet(const ProtocolPacket &packet, std::string &device_id);
            bool verify_auth_packet(const std::string &device_id, const ProtocolPacket &packet);

            // Session management
            std::unique_ptr<PacketCrypto> get_session_crypto(const std::string &device_id);
            void cleanup_expired_handshakes(std::chrono::seconds timeout);
            void remove_handshake(const std::string &device_id);
            
            // Rate limiting (DoS protection)
            bool check_rate_limit(const std::string &source_id);

        private:
            std::string router_id_;
            std::vector<uint8_t> shared_secret_;
            std::map<std::string, HandshakeState> pending_handshakes_;
            mutable std::mutex handshakes_mutex_;
            
            // Rate limiting state
            std::map<std::string, RateLimitState> rate_limits_;
            mutable std::mutex rate_limit_mutex_;

            std::vector<uint8_t> derive_session_key(const std::vector<uint8_t> &nonce1,
                                                    const std::vector<uint8_t> &nonce2);
            std::vector<uint8_t> generate_nonce();
        };

        /**
         * Protocol utility functions
         */
        namespace utils
        {

            /**
             * Parse HELLO packet payload
             */
            bool parse_hello_packet(const ProtocolPacket &packet, std::string &router_id,
                                    std::string &device_id, std::vector<uint8_t> &nonce1);

            /**
             * Parse AUTH packet payload
             */
            bool parse_auth_packet(const ProtocolPacket &packet, std::vector<uint8_t> &nonce2,
                                   std::vector<uint8_t> &auth_hash);

            /**
             * Validate packet structure
             */
            bool validate_packet(const ProtocolPacket &packet);

            /**
             * Calculate packet checksum
             */
            uint16_t calculate_checksum(const std::vector<uint8_t> &data);

        } // namespace utils

    } // namespace protocol
} // namespace mita

#endif // MITA_ROUTER_PROTOCOL_HPP