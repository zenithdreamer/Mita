#ifndef MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP
#define MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <deque>
#include <chrono>
#include "protocol/protocol.hpp"
#include "protocol/protocol_types.h"
#include "core/transport_interface.hpp"

namespace mita
{
    namespace core
    {
        class Logger;
    }

    namespace services
    {
        /**
         * Captured packet information
         */
        struct CapturedPacket
        {
            std::string id;
            std::chrono::system_clock::time_point timestamp;
            std::string direction; // "inbound", "outbound", "forwarded"
            uint16_t source_addr;
            uint16_t dest_addr;
            std::string message_type;
            size_t payload_size;
            std::string transport; // "wifi" or "ble"
            bool encrypted;
            std::vector<uint8_t> raw_data;
            
            // Decoded information
            std::string decoded_header;
            std::string decoded_payload;
        };

        /**
         * Packet monitoring service for capturing and logging packets
         */
        class PacketMonitorService
        {
        public:
            PacketMonitorService(size_t max_packets = 1000);
            ~PacketMonitorService();

            // Capture packets
            void capture_packet(const protocol::ProtocolPacket &packet, 
                              const std::string &direction,
                              core::TransportType transport);

            // Get captured packets
            std::vector<CapturedPacket> get_packets(size_t limit = 100, size_t offset = 0) const;
            std::vector<CapturedPacket> get_recent_packets(size_t count = 50) const;
            CapturedPacket get_packet_by_id(const std::string &id) const;

            // Control
            void clear_packets();
            void set_max_packets(size_t max);
            size_t get_packet_count() const;

            // Enable/disable monitoring
            void enable() { enabled_ = true; }
            void disable() { enabled_ = false; }
            bool is_enabled() const { return enabled_; }

        private:
            std::string generate_packet_id();
            std::string message_type_to_string(MessageType type) const;
            std::string decode_header(const protocol::ProtocolPacket &packet) const;
            std::string decode_payload(const protocol::ProtocolPacket &packet) const;

            std::shared_ptr<core::Logger> logger_;
            mutable std::mutex packets_mutex_;
            std::deque<CapturedPacket> packets_;
            size_t max_packets_;
            std::atomic<bool> enabled_{true};
            std::atomic<uint64_t> packet_counter_{0};
        };

    } // namespace services
} // namespace mita

#endif // MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP
