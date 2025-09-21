#ifndef MITA_ROUTER_STATISTICS_SERVICE_HPP
#define MITA_ROUTER_STATISTICS_SERVICE_HPP

#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <map>
#include <string>
#include <vector>
#include <memory>

namespace mita
{
    namespace core
    {
        class Logger;
    }

    namespace services
    {

        /**
         * Statistics data structure for returning values (non-atomic copies)
         */
        struct RouterStatisticsSnapshot
        {
            // Packet statistics
            uint64_t packets_routed = 0;
            uint64_t packets_dropped = 0;
            uint64_t packets_received = 0;
            uint64_t packets_sent = 0;
            uint64_t bytes_transferred = 0;

            // Connection statistics
            uint64_t handshakes_completed = 0;
            uint64_t handshakes_failed = 0;
            uint64_t connections_established = 0;
            uint64_t connections_dropped = 0;

            // Error statistics
            uint64_t errors = 0;
            uint64_t protocol_errors = 0;
            uint64_t transport_errors = 0;

            // Performance metrics
            uint64_t average_latency_ms = 0;
            uint64_t peak_concurrent_connections = 0;

            // Timing
            std::chrono::steady_clock::time_point start_time;

            // Convert to map for JSON serialization
            std::map<std::string, uint64_t> to_map() const;

            // Get uptime in seconds
            uint64_t get_uptime_seconds() const;

            // Reset all counters (except start_time)
            void reset();
        };

        /**
         * Statistics data structure (with atomic members for thread safety)
         */
        struct RouterStatistics
        {
            // Packet statistics
            std::atomic<uint64_t> packets_routed{0};
            std::atomic<uint64_t> packets_dropped{0};
            std::atomic<uint64_t> packets_received{0};
            std::atomic<uint64_t> packets_sent{0};
            std::atomic<uint64_t> bytes_transferred{0};

            // Connection statistics
            std::atomic<uint64_t> handshakes_completed{0};
            std::atomic<uint64_t> handshakes_failed{0};
            std::atomic<uint64_t> connections_established{0};
            std::atomic<uint64_t> connections_dropped{0};

            // Error statistics
            std::atomic<uint64_t> errors{0};
            std::atomic<uint64_t> protocol_errors{0};
            std::atomic<uint64_t> transport_errors{0};

            // Performance metrics
            std::atomic<uint64_t> average_latency_ms{0};
            std::atomic<uint64_t> peak_concurrent_connections{0};

            // Timestamp
            std::chrono::steady_clock::time_point start_time;

            RouterStatistics() : start_time(std::chrono::steady_clock::now()) {}

            // Convert to map for JSON serialization
            std::map<std::string, uint64_t> to_map() const;

            // Get uptime in seconds
            uint64_t get_uptime_seconds() const;

            // Reset all counters (except start_time)
            void reset();
        };

        /**
         * Per-transport statistics snapshot (non-atomic for returning)
         */
        struct TransportStatisticsSnapshot
        {
            uint64_t packets_received = 0;
            uint64_t packets_sent = 0;
            uint64_t bytes_transferred = 0;
            uint64_t connections_active = 0;
            uint64_t connections_total = 0;
            uint64_t errors = 0;

            std::map<std::string, uint64_t> to_map() const;
        };

        /**
         * Per-transport statistics (atomic for thread safety)
         */
        struct TransportStatistics
        {
            std::atomic<uint64_t> packets_received{0};
            std::atomic<uint64_t> packets_sent{0};
            std::atomic<uint64_t> bytes_transferred{0};
            std::atomic<uint64_t> connections_active{0};
            std::atomic<uint64_t> connections_total{0};
            std::atomic<uint64_t> errors{0};

            std::map<std::string, uint64_t> to_map() const;
        };

        /**
         * Statistics collection and reporting service
         */
        class StatisticsService
        {
        public:
            StatisticsService();
            ~StatisticsService() = default;

            // Service lifecycle
            void start();
            void stop();
            bool is_running() const { return running_; }

            // Packet statistics
            void record_packet_received(size_t bytes = 0);
            void record_packet_sent(size_t bytes = 0);
            void record_packet_routed(size_t bytes = 0);
            void record_packet_dropped();

            // Connection statistics
            void record_handshake_completed();
            void record_handshake_failed();
            void record_connection_established();
            void record_connection_dropped();

            // Error statistics
            void record_error();
            void record_protocol_error();
            void record_transport_error();

            // Performance metrics
            void record_latency(uint64_t latency_ms);
            void update_peak_connections(uint64_t current_connections);

            // Transport-specific statistics
            void record_transport_packet_received(const std::string &transport, size_t bytes = 0);
            void record_transport_packet_sent(const std::string &transport, size_t bytes = 0);
            void record_transport_error(const std::string &transport);
            void update_transport_connections(const std::string &transport, uint64_t active_count);

            // Data access
            RouterStatisticsSnapshot get_statistics() const;
            TransportStatisticsSnapshot get_transport_statistics(const std::string &transport) const;
            std::map<std::string, TransportStatisticsSnapshot> get_all_transport_statistics() const;

            // Periodic updates
            void update_periodic_stats();

            // Utility methods
            uint64_t get_uptime() const;
            void reset_statistics();

            // JSON export
            std::map<std::string, std::map<std::string, uint64_t>> export_json() const;

        private:
            void update_latency_average(uint64_t new_latency);

            mutable std::shared_mutex stats_mutex_;
            RouterStatistics stats_;

            mutable std::shared_mutex transport_stats_mutex_;
            std::map<std::string, TransportStatistics> transport_stats_;

            // Latency calculation
            mutable std::mutex latency_mutex_;
            std::vector<uint64_t> latency_samples_;
            static constexpr size_t MAX_LATENCY_SAMPLES = 1000;

            std::atomic<bool> running_{false};
            std::shared_ptr<core::Logger> logger_;
        };

    } // namespace services
} // namespace mita

#endif // MITA_ROUTER_STATISTICS_SERVICE_HPP