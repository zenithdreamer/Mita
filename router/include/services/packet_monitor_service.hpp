#ifndef MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP
#define MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <deque>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <atomic>
#include "protocol/protocol.hpp"
#include "protocol/protocol_types.h"
#include "core/transport_interface.hpp"
#include "database/models.hpp"

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
            
            // Validation flags
            bool is_valid = true;          // false if packet failed validation
            std::string error_flags;        // e.g., "CHECKSUM_FAIL", "MALFORMED", "INVALID_VERSION"
            
            // Decoded information
            std::string decoded_header;
            std::string decoded_payload;
            std::string decrypted_payload; // Decrypted payload (if encrypted)
        };

        /**
         * Packet monitoring service for capturing and logging packets
         */
        class PacketMonitorService
        {
        public:
            PacketMonitorService(std::shared_ptr<mita::db::Storage> storage = nullptr);
            ~PacketMonitorService();

            // Start/stop the async writer thread
            void start();
            void stop();

            // Capture packets (returns packet_id for later updates)
            std::string capture_packet(const protocol::ProtocolPacket &packet,
                              const std::string &direction,
                              core::TransportType transport);
            
            // Capture invalid/rejected packets (for debugging)
            void capture_invalid_packet(const std::vector<uint8_t> &raw_data,
                                       const std::string &reason,
                                       const std::string &direction,
                                       core::TransportType transport);
            
            // Update existing packet with error information
            bool update_packet_error(const std::string &packet_id,
                                    const std::string &error_flags,
                                    bool is_valid = false);
            
            // Update existing packet with decrypted payload
            bool update_packet_decrypted(const std::string &packet_id,
                                        const std::string &decrypted_payload);

            // Get captured packets
            std::vector<CapturedPacket> get_packets(size_t limit = 100, size_t offset = 0) const;
            std::vector<CapturedPacket> get_recent_packets(size_t count = 50) const;
            CapturedPacket get_packet_by_id(const std::string &id) const;

            // Control
            void clear_packets();
            size_t get_packet_count() const;

            // Enable/disable monitoring
            void enable() { enabled_ = true; }
            void disable() { enabled_ = false; }
            bool is_enabled() const { return enabled_; }

            // Network metrics
            struct NetworkMetrics {
                uint64_t total_bytes_uploaded = 0;
                uint64_t total_bytes_downloaded = 0;
                uint64_t packets_per_second = 0;
                double upload_speed_mbps = 0.0;    // MB/s
                double download_speed_mbps = 0.0;  // MB/s
                std::chrono::steady_clock::time_point last_update;
            };

            NetworkMetrics get_network_metrics() const;

        private:
            std::string generate_packet_id();
            std::string message_type_to_string(MessageType type) const;
            std::string decode_header(const protocol::ProtocolPacket &packet) const;
            std::string decode_payload(const protocol::ProtocolPacket &packet) const;
            void save_packet_to_db(const CapturedPacket &packet);
            std::string bytes_to_hex(const std::vector<uint8_t> &data) const;
            std::vector<uint8_t> hex_to_bytes(const std::string &hex) const;

            // Synchronous update methods (called by async writer thread)
            bool update_packet_error_sync(const std::string &packet_id,
                                         const std::string &error_flags,
                                         bool is_valid = false);
            bool update_packet_decrypted_sync(const std::string &packet_id,
                                             const std::string &decrypted_payload);

            std::shared_ptr<core::Logger> logger_;
            std::shared_ptr<mita::db::Storage> storage_;
            mutable std::mutex db_mutex_;
            std::atomic<bool> enabled_{true};
            std::atomic<uint64_t> packet_counter_{0};

            // Network metrics tracking
            mutable std::mutex metrics_mutex_;
            std::atomic<uint64_t> total_bytes_uploaded_{0};
            std::atomic<uint64_t> total_bytes_downloaded_{0};
            std::chrono::steady_clock::time_point metrics_start_time_;
            std::chrono::steady_clock::time_point last_metrics_update_;
            
            // Rolling window for packets per second calculation (last 60 seconds)
            struct PacketTimestamp {
                std::chrono::steady_clock::time_point time;
                size_t bytes;
                bool is_upload;
            };
            mutable std::mutex window_mutex_;
            std::deque<PacketTimestamp> packet_window_;

            void update_metrics(size_t bytes, bool is_upload);
            void clean_packet_window();

            // Async database writer
            std::thread writer_thread_;
            std::atomic<bool> writer_running_{false};
            std::mutex queue_mutex_;
            std::condition_variable queue_cv_;
            std::deque<CapturedPacket> write_queue_;
            static constexpr size_t MAX_QUEUE_SIZE = 1000; // Prevent memory exhaustion

            // Update operations queue
            struct PacketUpdate {
                enum Type { DECRYPTED_PAYLOAD, ERROR_FLAG } type;
                std::string packet_id;
                std::string data;
                bool is_valid = false;
            };
            std::deque<PacketUpdate> update_queue_;

            void writer_thread_func();
            void enqueue_packet(const CapturedPacket &packet);
            void enqueue_update(const PacketUpdate &update);
        };

    } // namespace services
} // namespace mita

#endif // MITA_ROUTER_PACKET_MONITOR_SERVICE_HPP
