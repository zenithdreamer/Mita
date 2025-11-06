#include "services/statistics_service.hpp"
#include "core/logger.hpp"
#include <algorithm>

namespace mita
{
    namespace services
    {

        // RouterStatistics implementation
        std::map<std::string, uint64_t> RouterStatistics::to_map() const
        {
            return {
                {"packets_routed", packets_routed.load()},
                {"packets_dropped", packets_dropped.load()},
                {"packets_received", packets_received.load()},
                {"packets_sent", packets_sent.load()},
                {"bytes_transferred", bytes_transferred.load()},
                {"handshakes_completed", handshakes_completed.load()},
                {"handshakes_failed", handshakes_failed.load()},
                {"connections_established", connections_established.load()},
                {"connections_dropped", connections_dropped.load()},
                {"errors", errors.load()},
                {"protocol_errors", protocol_errors.load()},
                {"transport_errors", transport_errors.load()},
                {"sequence_gaps_detected", sequence_gaps_detected.load()},
                {"replay_attempts_blocked", replay_attempts_blocked.load()},
                {"stale_packets_dropped", stale_packets_dropped.load()},
                {"session_rekeys_completed", session_rekeys_completed.load()},
                {"average_latency_ms", average_latency_ms.load()},
                {"peak_concurrent_connections", peak_concurrent_connections.load()},
                {"uptime_seconds", get_uptime_seconds()}};
        }

        uint64_t RouterStatistics::get_uptime_seconds() const
        {
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
            return static_cast<uint64_t>(uptime.count());
        }

        void RouterStatistics::reset()
        {
            packets_routed = 0;
            packets_dropped = 0;
            packets_received = 0;
            packets_sent = 0;
            bytes_transferred = 0;
            handshakes_completed = 0;
            handshakes_failed = 0;
            connections_established = 0;
            connections_dropped = 0;
            errors = 0;
            protocol_errors = 0;
            transport_errors = 0;
            sequence_gaps_detected = 0;
            replay_attempts_blocked = 0;
            stale_packets_dropped = 0;
            session_rekeys_completed = 0;
            average_latency_ms = 0;
            peak_concurrent_connections = 0;
            start_time = std::chrono::steady_clock::now();
        }

        // TransportStatistics implementation
        std::map<std::string, uint64_t> TransportStatistics::to_map() const
        {
            return {
                {"packets_received", packets_received.load()},
                {"packets_sent", packets_sent.load()},
                {"bytes_transferred", bytes_transferred.load()},
                {"connections_active", connections_active.load()},
                {"connections_total", connections_total.load()},
                {"errors", errors.load()}};
        }

        // RouterStatisticsSnapshot implementation
        std::map<std::string, uint64_t> RouterStatisticsSnapshot::to_map() const
        {
            return {
                {"packets_routed", packets_routed},
                {"packets_dropped", packets_dropped},
                {"packets_received", packets_received},
                {"packets_sent", packets_sent},
                {"bytes_transferred", bytes_transferred},
                {"handshakes_completed", handshakes_completed},
                {"handshakes_failed", handshakes_failed},
                {"connections_established", connections_established},
                {"connections_dropped", connections_dropped},
                {"errors", errors},
                {"protocol_errors", protocol_errors},
                {"transport_errors", transport_errors},
                {"sequence_gaps_detected", sequence_gaps_detected},
                {"replay_attempts_blocked", replay_attempts_blocked},
                {"stale_packets_dropped", stale_packets_dropped},
                {"session_rekeys_completed", session_rekeys_completed},
                {"average_latency_ms", average_latency_ms},
                {"peak_concurrent_connections", peak_concurrent_connections},
                {"uptime_seconds", get_uptime_seconds()}};
        }

        uint64_t RouterStatisticsSnapshot::get_uptime_seconds() const
        {
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
            return static_cast<uint64_t>(uptime.count());
        }

        void RouterStatisticsSnapshot::reset()
        {
            packets_routed = 0;
            packets_dropped = 0;
            packets_received = 0;
            packets_sent = 0;
            bytes_transferred = 0;
            handshakes_completed = 0;
            handshakes_failed = 0;
            connections_established = 0;
            connections_dropped = 0;
            errors = 0;
            protocol_errors = 0;
            transport_errors = 0;
            sequence_gaps_detected = 0;
            replay_attempts_blocked = 0;
            stale_packets_dropped = 0;
            session_rekeys_completed = 0;
            average_latency_ms = 0;
            peak_concurrent_connections = 0;
            start_time = std::chrono::steady_clock::now();
        }

        // TransportStatisticsSnapshot implementation
        std::map<std::string, uint64_t> TransportStatisticsSnapshot::to_map() const
        {
            return {
                {"packets_received", packets_received},
                {"packets_sent", packets_sent},
                {"bytes_transferred", bytes_transferred},
                {"connections_active", connections_active},
                {"connections_total", connections_total},
                {"errors", errors}};
        }

        // StatisticsService implementation
        StatisticsService::StatisticsService()
            : logger_(core::get_logger("StatisticsService"))
        {

            stats_.start_time = std::chrono::steady_clock::now();
            logger_->info("Statistics service initialized");
        }

        void StatisticsService::start()
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            logger_->info("Statistics service started");
        }

        void StatisticsService::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            logger_->info("Statistics service stopped");
        }

        void StatisticsService::record_packet_received(size_t bytes)
        {
            stats_.packets_received++;
            if (bytes > 0)
            {
                stats_.bytes_transferred += bytes;
            }
        }

        void StatisticsService::record_packet_sent(size_t bytes)
        {
            stats_.packets_sent++;
            if (bytes > 0)
            {
                stats_.bytes_transferred += bytes;
            }
        }

        void StatisticsService::record_packet_routed(size_t bytes)
        {
            stats_.packets_routed++;
            if (bytes > 0)
            {
                stats_.bytes_transferred += bytes;
            }
        }

        void StatisticsService::record_packet_dropped()
        {
            stats_.packets_dropped++;
        }

        void StatisticsService::record_handshake_completed()
        {
            stats_.handshakes_completed++;
        }

        void StatisticsService::record_handshake_failed()
        {
            stats_.handshakes_failed++;
        }

        void StatisticsService::record_connection_established()
        {
            stats_.connections_established++;
        }

        void StatisticsService::record_connection_dropped()
        {
            stats_.connections_dropped++;
        }

        void StatisticsService::record_error()
        {
            stats_.errors++;
        }

        void StatisticsService::record_protocol_error()
        {
            stats_.protocol_errors++;
            stats_.errors++;
        }

        void StatisticsService::record_transport_error()
        {
            stats_.transport_errors++;
        }

        // Security metrics (Task 4,5,6)
        void StatisticsService::record_sequence_gap()
        {
            stats_.sequence_gaps_detected++;
        }

        void StatisticsService::record_replay_attempt()
        {
            stats_.replay_attempts_blocked++;
        }

        void StatisticsService::record_stale_packet()
        {
            stats_.stale_packets_dropped++;
        }

        void StatisticsService::record_session_rekey()
        {
            stats_.session_rekeys_completed++;
        }

        void StatisticsService::record_latency(uint64_t latency_ms)
        {
            std::lock_guard<std::mutex> lock(latency_mutex_);

            latency_samples_.push_back(latency_ms);

            // Keep only recent samples
            if (latency_samples_.size() > MAX_LATENCY_SAMPLES)
            {
                latency_samples_.erase(latency_samples_.begin());
            }

            update_latency_average(latency_ms);
        }

        void StatisticsService::update_peak_connections(uint64_t current_connections)
        {
            uint64_t current_peak = stats_.peak_concurrent_connections.load();
            while (current_connections > current_peak)
            {
                if (stats_.peak_concurrent_connections.compare_exchange_weak(current_peak, current_connections))
                {
                    break;
                }
            }
        }

        void StatisticsService::record_transport_packet_received(const std::string &transport, size_t bytes)
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            auto &transport_stats = transport_stats_[transport];
            transport_stats.packets_received++;
            if (bytes > 0)
            {
                transport_stats.bytes_transferred += bytes;
            }

            record_packet_received(bytes);
        }

        void StatisticsService::record_transport_packet_sent(const std::string &transport, size_t bytes)
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            auto &transport_stats = transport_stats_[transport];
            transport_stats.packets_sent++;
            if (bytes > 0)
            {
                transport_stats.bytes_transferred += bytes;
            }

            record_packet_sent(bytes);
        }

        void StatisticsService::record_transport_error(const std::string &transport)
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            auto &transport_stats = transport_stats_[transport];
            transport_stats.errors++;

            record_transport_error();
        }

        void StatisticsService::update_transport_connections(const std::string &transport, uint64_t active_count)
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            auto &transport_stats = transport_stats_[transport];

            uint64_t previous = transport_stats.connections_active.exchange(active_count);
            if (active_count > previous)
            {
                transport_stats.connections_total += (active_count - previous);
            }
        }

        RouterStatisticsSnapshot StatisticsService::get_statistics() const
        {
            RouterStatisticsSnapshot result;
            result.packets_routed = stats_.packets_routed.load();
            result.packets_dropped = stats_.packets_dropped.load();
            result.packets_received = stats_.packets_received.load();
            result.packets_sent = stats_.packets_sent.load();
            result.bytes_transferred = stats_.bytes_transferred.load();
            result.handshakes_completed = stats_.handshakes_completed.load();
            result.handshakes_failed = stats_.handshakes_failed.load();
            result.connections_established = stats_.connections_established.load();
            result.connections_dropped = stats_.connections_dropped.load();
            result.errors = stats_.errors.load();
            result.protocol_errors = stats_.protocol_errors.load();
            result.transport_errors = stats_.transport_errors.load();
            result.average_latency_ms = stats_.average_latency_ms.load();
            result.peak_concurrent_connections = stats_.peak_concurrent_connections.load();
            result.start_time = stats_.start_time;
            return result;
        }

        TransportStatisticsSnapshot StatisticsService::get_transport_statistics(const std::string &transport) const
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            auto it = transport_stats_.find(transport);
            if (it != transport_stats_.end())
            {
                TransportStatisticsSnapshot result;
                result.packets_sent = it->second.packets_sent.load();
                result.packets_received = it->second.packets_received.load();
                result.bytes_transferred = it->second.bytes_transferred.load();
                result.connections_total = it->second.connections_total.load();
                result.connections_active = it->second.connections_active.load();
                result.errors = it->second.errors.load();
                return result;
            }
            return TransportStatisticsSnapshot{};
        }

        std::map<std::string, TransportStatisticsSnapshot> StatisticsService::get_all_transport_statistics() const
        {
            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            std::map<std::string, TransportStatisticsSnapshot> result;
            for (const auto &[transport_name, stats] : transport_stats_)
            {
                TransportStatisticsSnapshot snapshot;
                snapshot.packets_sent = stats.packets_sent.load();
                snapshot.packets_received = stats.packets_received.load();
                snapshot.bytes_transferred = stats.bytes_transferred.load();
                snapshot.connections_total = stats.connections_total.load();
                snapshot.connections_active = stats.connections_active.load();
                snapshot.errors = stats.errors.load();
                result[transport_name] = snapshot;
            }
            return result;
        }

        void StatisticsService::update_periodic_stats()
        {
            // Calculate current connections across all transports
            uint64_t total_connections = 0;
            {
                std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
                for (const auto &[transport, stats] : transport_stats_)
                {
                    total_connections += stats.connections_active.load();
                }
            }

            update_peak_connections(total_connections);
        }

        uint64_t StatisticsService::get_uptime() const
        {
            return stats_.get_uptime_seconds();
        }

        void StatisticsService::reset_statistics()
        {
            std::unique_lock<std::shared_mutex> lock(transport_stats_mutex_);
            std::lock_guard<std::mutex> latency_lock(latency_mutex_);

            stats_.reset();
            transport_stats_.clear();
            latency_samples_.clear();

            logger_->info("Statistics reset");
        }

        std::map<std::string, std::map<std::string, uint64_t>> StatisticsService::export_json() const
        {
            std::map<std::string, std::map<std::string, uint64_t>> result;

            result["global"] = stats_.to_map();

            std::shared_lock<std::shared_mutex> lock(transport_stats_mutex_);
            for (const auto &[transport, stats] : transport_stats_)
            {
                result[transport] = stats.to_map();
            }

            return result;
        }

        void StatisticsService::update_latency_average(uint64_t new_latency)
        {
            if (latency_samples_.empty())
            {
                stats_.average_latency_ms = new_latency;
                return;
            }

            // Calculate rolling average
            uint64_t sum = 0;
            for (uint64_t sample : latency_samples_)
            {
                sum += sample;
            }

            stats_.average_latency_ms = sum / latency_samples_.size();
        }

    } // namespace services
} // namespace mita