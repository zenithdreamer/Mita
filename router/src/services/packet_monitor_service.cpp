#include "services/packet_monitor_service.hpp"
#include "core/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace mita
{
    namespace services
    {

        PacketMonitorService::PacketMonitorService(std::shared_ptr<mita::db::Storage> storage, size_t max_packets)
            : logger_(core::get_logger("PacketMonitor")),
              storage_(storage),
              max_packets_(max_packets),
              metrics_start_time_(std::chrono::steady_clock::now()),
              last_metrics_update_(std::chrono::steady_clock::now())
        {
            logger_->info("Packet Monitor Service initialized",
                         core::LogContext()
                            .add("max_packets", max_packets)
                            .add("database_enabled", storage_ != nullptr));
        }

        PacketMonitorService::~PacketMonitorService()
        {
            logger_->info("Packet Monitor Service shutting down");
        }

        void PacketMonitorService::capture_packet(const protocol::ProtocolPacket &packet,
                                                  const std::string &direction,
                                                  core::TransportType transport)
        {
            if (!enabled_)
            {
                return;
            }

            try
            {
                CapturedPacket captured;
                captured.id = generate_packet_id();
                captured.timestamp = std::chrono::system_clock::now();
                captured.direction = direction;

                // Safely extract packet info with bounds checking
                try {
                    captured.source_addr = packet.get_source_addr();
                    captured.dest_addr = packet.get_dest_addr();
                    captured.message_type = message_type_to_string(packet.get_message_type());
                    captured.payload_size = packet.get_payload().size();
                    captured.transport = (transport == core::TransportType::WIFI) ? "wifi" : "ble";
                    captured.encrypted = packet.is_encrypted();

                    // Copy raw data safely
                    captured.raw_data = packet.to_bytes();

                    // Decode header and payload with error handling
                    captured.decoded_header = decode_header(packet);
                    captured.decoded_payload = decode_payload(packet);
                } catch (const std::exception &decode_error) {
                    logger_->warning("Error decoding packet details",
                                   core::LogContext().add("error", decode_error.what()));
                    // Continue with partial data
                    captured.decoded_header = "Error decoding header";
                    captured.decoded_payload = "Error decoding payload";
                }

                // Update metrics based on direction
                bool is_upload = (direction == "outbound" || direction == "forwarded");
                update_metrics(captured.payload_size + 16, is_upload); // +16 for header overhead

                // Log before moving
                logger_->debug("Captured packet",
                             core::LogContext()
                                 .add("id", captured.id)
                                 .add("direction", direction)
                                 .add("type", captured.message_type));

                // Save to database if storage is available
                if (storage_) {
                    save_packet_to_db(captured);
                }

                {
                    std::lock_guard<std::mutex> lock(packets_mutex_);

                    // Add to front (most recent first)
                    packets_.push_front(std::move(captured)); // Use move semantics

                    // Remove oldest if exceeding limit
                    while (packets_.size() > max_packets_)
                    {
                        packets_.pop_back();
                    }
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Failed to capture packet",
                             core::LogContext().add("error", e.what()));
            }
        }

        std::vector<CapturedPacket> PacketMonitorService::get_packets(size_t limit, size_t offset) const
        {
            std::lock_guard<std::mutex> lock(packets_mutex_);

            std::vector<CapturedPacket> result;
            
            if (offset >= packets_.size())
            {
                return result;
            }

            size_t end = std::min(offset + limit, packets_.size());
            result.reserve(end - offset);

            for (size_t i = offset; i < end; ++i)
            {
                result.push_back(packets_[i]);
            }

            return result;
        }

        std::vector<CapturedPacket> PacketMonitorService::get_recent_packets(size_t count) const
        {
            return get_packets(count, 0);
        }

        CapturedPacket PacketMonitorService::get_packet_by_id(const std::string &id) const
        {
            std::lock_guard<std::mutex> lock(packets_mutex_);

            auto it = std::find_if(packets_.begin(), packets_.end(),
                                   [&id](const CapturedPacket &p) { return p.id == id; });

            if (it != packets_.end())
            {
                return *it;
            }

            throw std::runtime_error("Packet not found: " + id);
        }

        void PacketMonitorService::clear_packets()
        {
            std::lock_guard<std::mutex> lock(packets_mutex_);
            packets_.clear();
            logger_->info("Cleared all captured packets");
        }

        void PacketMonitorService::set_max_packets(size_t max)
        {
            std::lock_guard<std::mutex> lock(packets_mutex_);
            max_packets_ = max;

            // Trim if needed
            while (packets_.size() > max_packets_)
            {
                packets_.pop_back();
            }

            logger_->info("Updated max packets", core::LogContext().add("max_packets", max));
        }

        size_t PacketMonitorService::get_packet_count() const
        {
            std::lock_guard<std::mutex> lock(packets_mutex_);
            return packets_.size();
        }

        std::string PacketMonitorService::generate_packet_id()
        {
            auto counter = packet_counter_.fetch_add(1);
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
            
            std::ostringstream oss;
            oss << "pkt_" << ms << "_" << counter;
            return oss.str();
        }

        std::string PacketMonitorService::message_type_to_string(MessageType type) const
        {
            switch (type)
            {
            case MessageType::HELLO:
                return "HELLO";
            case MessageType::CHALLENGE:
                return "CHALLENGE";
            case MessageType::AUTH:
                return "AUTH";
            case MessageType::AUTH_ACK:
                return "AUTH_ACK";
            case MessageType::DATA:
                return "DATA";
            case MessageType::ACK:
                return "ACK";
            case MessageType::CONTROL:
                return "CONTROL";
            case MessageType::ERROR:
                return "ERROR";
            default:
                return "UNKNOWN";
            }
        }

        std::string PacketMonitorService::decode_header(const protocol::ProtocolPacket &packet) const
        {
            try {
                std::ostringstream oss;
                oss << "Version: " << static_cast<int>(packet.get_version()) << "\n";
                oss << "Flags: 0x" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(packet.get_flags()) << std::dec << "\n";
                oss << "Message Type: " << message_type_to_string(packet.get_message_type()) << "\n";
                oss << "Source Address: 0x" << std::hex << std::setw(4) << std::setfill('0')
                    << packet.get_source_addr() << std::dec << "\n";
                oss << "Dest Address: 0x" << std::hex << std::setw(4) << std::setfill('0')
                    << packet.get_dest_addr() << std::dec << "\n";
                oss << "Payload Length: " << packet.get_payload().size() << " bytes\n";
                oss << "Checksum: 0x" << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(packet.get_checksum()) << std::dec << "\n";
                oss << "Sequence Number: " << packet.get_sequence_number() << "\n";
                oss << "TTL: " << static_cast<int>(packet.get_ttl()) << "\n";
                oss << "Priority: " << static_cast<int>(packet.get_priority()) << "\n";
                oss << "Fragment ID: " << packet.get_fragment_id() << "\n";
                oss << "Timestamp: " << packet.get_timestamp() << "\n";
                oss << "Encrypted: " << (packet.is_encrypted() ? "Yes" : "No") << "\n";
                oss << "Fragmented: " << (packet.is_fragmented() ? "Yes" : "No");

                return oss.str();
            } catch (const std::exception &e) {
                return std::string("Error decoding header: ") + e.what();
            }
        }

        std::string PacketMonitorService::decode_payload(const protocol::ProtocolPacket &packet) const
        {
            try {
                const auto &payload = packet.get_payload();

                if (payload.empty())
                {
                    return "Empty payload";
                }

                std::ostringstream oss;

                // Limit payload decoding to prevent huge strings (max 1KB for display)
                size_t display_size = std::min(payload.size(), size_t(1024));

                // Hex dump
                oss << "Hex dump (" << payload.size() << " bytes";
                if (display_size < payload.size()) {
                    oss << ", showing first " << display_size;
                }
                oss << "):\n";

                for (size_t i = 0; i < display_size; ++i)
                {
                    if (i > 0 && i % 16 == 0)
                    {
                        oss << "\n";
                    }
                    else if (i > 0 && i % 8 == 0)
                    {
                        oss << "  ";
                    }
                    else if (i > 0)
                    {
                        oss << " ";
                    }
                    oss << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(payload[i]);
                }
                oss << std::dec << "\n\n";

                // ASCII representation
                oss << "ASCII (printable only):\n";
                for (size_t i = 0; i < display_size; ++i)
                {
                    char c = static_cast<char>(payload[i]);
                    if (c >= 32 && c <= 126)
                    {
                        oss << c;
                    }
                    else
                    {
                        oss << '.';
                    }
                }

                if (display_size < payload.size()) {
                    oss << "\n... (" << (payload.size() - display_size) << " more bytes)";
                }

                return oss.str();
            } catch (const std::exception &e) {
                return std::string("Error decoding payload: ") + e.what();
            }
        }

        void PacketMonitorService::update_metrics(size_t bytes, bool is_upload)
        {
            // Update total bytes
            if (is_upload) {
                total_bytes_uploaded_.fetch_add(bytes);
            } else {
                total_bytes_downloaded_.fetch_add(bytes);
            }

            // Add to rolling window for packets per second calculation
            std::lock_guard<std::mutex> lock(window_mutex_);
            packet_window_.push_back({std::chrono::steady_clock::now(), bytes, is_upload});
            
            // Clean old entries (older than 60 seconds)
            clean_packet_window();
            
            last_metrics_update_ = std::chrono::steady_clock::now();
        }

        void PacketMonitorService::clean_packet_window()
        {
            auto now = std::chrono::steady_clock::now();
            auto cutoff = now - std::chrono::seconds(60);
            
            while (!packet_window_.empty() && packet_window_.front().time < cutoff) {
                packet_window_.pop_front();
            }
        }

        PacketMonitorService::NetworkMetrics PacketMonitorService::get_network_metrics() const
        {
            NetworkMetrics metrics;
            
            // Get total bytes
            metrics.total_bytes_uploaded = total_bytes_uploaded_.load();
            metrics.total_bytes_downloaded = total_bytes_downloaded_.load();
            
            std::lock_guard<std::mutex> lock(window_mutex_);
            
            // Calculate packets per second and throughput from last 60 seconds
            auto now = std::chrono::steady_clock::now();
            auto window_start = now - std::chrono::seconds(60);
            
            uint64_t recent_packets = 0;
            uint64_t recent_upload_bytes = 0;
            uint64_t recent_download_bytes = 0;
            
            for (const auto& entry : packet_window_) {
                if (entry.time >= window_start) {
                    recent_packets++;
                    if (entry.is_upload) {
                        recent_upload_bytes += entry.bytes;
                    } else {
                        recent_download_bytes += entry.bytes;
                    }
                }
            }
            
            // Calculate rates
            auto window_duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - (packet_window_.empty() ? metrics_start_time_ : packet_window_.front().time)
            ).count();
            
            if (window_duration > 0) {
                metrics.packets_per_second = recent_packets / window_duration;
                // Convert bytes/sec to MB/s
                metrics.upload_speed_mbps = (recent_upload_bytes / static_cast<double>(window_duration)) / (1024.0 * 1024.0);
                metrics.download_speed_mbps = (recent_download_bytes / static_cast<double>(window_duration)) / (1024.0 * 1024.0);
            }
            
            metrics.last_update = last_metrics_update_;
            
            return metrics;
        }

        void PacketMonitorService::save_packet_to_db(const CapturedPacket &packet)
        {
            try {
                using namespace sqlite_orm;

                // Convert timestamp to milliseconds
                auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    packet.timestamp.time_since_epoch()
                ).count();

                // Create database packet record
                mita::db::MonitoredPacket db_packet;
                db_packet.packet_id = packet.id;
                db_packet.timestamp = timestamp_ms;
                db_packet.direction = packet.direction;
                db_packet.source_addr = packet.source_addr;
                db_packet.dest_addr = packet.dest_addr;
                db_packet.message_type = packet.message_type;
                db_packet.payload_size = packet.payload_size;
                db_packet.transport = packet.transport;
                db_packet.encrypted = packet.encrypted ? 1 : 0;
                db_packet.raw_data = bytes_to_hex(packet.raw_data);
                db_packet.decoded_header = packet.decoded_header;
                db_packet.decoded_payload = packet.decoded_payload;

                // Insert into database
                storage_->insert(db_packet);

                logger_->debug("Saved packet to database",
                             core::LogContext().add("packet_id", packet.id));
            } catch (const std::exception &e) {
                logger_->error("Failed to save packet to database",
                             core::LogContext()
                                .add("packet_id", packet.id)
                                .add("error", e.what()));
            }
        }

        std::string PacketMonitorService::bytes_to_hex(const std::vector<uint8_t> &data) const
        {
            std::ostringstream oss;
            for (size_t i = 0; i < data.size(); ++i) {
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(data[i]);
            }
            return oss.str();
        }

    } // namespace services
} // namespace mita
