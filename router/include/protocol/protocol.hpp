#ifndef MITA_ROUTER_PROTOCOL_HPP
#define MITA_ROUTER_PROTOCOL_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <map>
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

            // Setters
            void set_encrypted(bool encrypted);
            void set_source_addr(uint16_t addr) { source_addr_ = addr; }
            void set_dest_addr(uint16_t addr) { dest_addr_ = addr; }
            void set_payload(const std::vector<uint8_t> &payload);

        private:
            uint8_t version_ = PROTOCOL_VERSION;
            uint8_t flags_ = 0;
            uint8_t msg_type_ = 0;
            uint16_t source_addr_ = 0;
            uint16_t dest_addr_ = 0;
            std::vector<uint8_t> payload_;
        };

        /**
         * Cryptographic functions for packet security
         */
        class PacketCrypto
        {
        public:
            PacketCrypto(const std::vector<uint8_t> &session_key);
            ~PacketCrypto();

            // Encryption/Decryption
            std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext);
            std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext);

            // HMAC verification
            std::vector<uint8_t> compute_hmac(const std::vector<uint8_t> &data);
            bool verify_hmac(const std::vector<uint8_t> &data, const std::vector<uint8_t> &hmac);

        private:
            std::vector<uint8_t> session_key_;
            class Impl;
            std::unique_ptr<Impl> impl_;
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
                int attempts = 0;
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

        private:
            std::string router_id_;
            std::vector<uint8_t> shared_secret_;
            std::map<std::string, HandshakeState> pending_handshakes_;
            mutable std::mutex handshakes_mutex_;

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