#include "services/packet_monitor_service.hpp"
#include "core/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace mita
{
    namespace services
    {

        PacketMonitorService::PacketMonitorService(std::shared_ptr<mita::db::Storage> storage)
            : logger_(core::get_logger("PacketMonitor")),
              storage_(storage),
              metrics_start_time_(std::chrono::steady_clock::now()),
              last_metrics_update_(std::chrono::steady_clock::now())
        {
            logger_->info("Packet Monitor Service initialized",
                         core::LogContext()
                            .add("database_enabled", storage_ != nullptr));
        }

        PacketMonitorService::~PacketMonitorService()
        {
            logger_->info("Packet Monitor Service shutting down");
        }

        std::string PacketMonitorService::capture_packet(const protocol::ProtocolPacket &packet,
                                                  const std::string &direction,
                                                  core::TransportType transport)
        {
            if (!enabled_)
            {
                return "";
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
                    
                    // Debug: Check the actual message type value
                    auto msg_type = packet.get_message_type();
                    uint8_t msg_type_raw = static_cast<uint8_t>(msg_type);
                    logger_->debug("Capturing packet",
                                 core::LogContext()
                                     .add("msg_type_raw", static_cast<int>(msg_type_raw))
                                     .add("source", captured.source_addr)
                                     .add("dest", captured.dest_addr));
                    
                    captured.message_type = message_type_to_string(msg_type);
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

                // Log before saving
                logger_->debug("Captured packet",
                             core::LogContext()
                                 .add("id", captured.id)
                                 .add("direction", direction)
                                 .add("type", captured.message_type));

                // Save to database if storage is available
                if (storage_) {
                    save_packet_to_db(captured);
                } else {
                    logger_->warning("Storage not available, packet not saved",
                                   core::LogContext().add("packet_id", captured.id));
                }
                
                return captured.id;
            }
            catch (const std::exception &e)
            {
                logger_->error("Failed to capture packet",
                             core::LogContext().add("error", e.what()));
                return "";
            }
        }

        void PacketMonitorService::capture_invalid_packet(const std::vector<uint8_t> &raw_data,
                                                          const std::string &reason,
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
                captured.transport = (transport == core::TransportType::WIFI) ? "wifi" : "ble";
                captured.raw_data = raw_data;
                
                // Mark as invalid
                captured.is_valid = false;
                captured.message_type = "INVALID";
                captured.source_addr = 0xFFFF;
                captured.dest_addr = 0xFFFF;
                captured.payload_size = raw_data.size();
                captured.encrypted = false;
                
                // Determine error flags from reason
                if (reason.find("GCM_AUTH_FAIL") != std::string::npos || 
                    reason.find("GCM authentication failed") != std::string::npos)
                {
                    captured.error_flags = "GCM_AUTH_FAIL";
                    captured.encrypted = true;  // Was encrypted but failed auth
                }
                else if (reason.find("Checksum") != std::string::npos || reason.find("checksum") != std::string::npos)
                {
                    captured.error_flags = "CHECKSUM_FAIL";
                }
                else if (reason.find("version") != std::string::npos)
                {
                    captured.error_flags = "INVALID_VERSION";
                }
                else if (reason.find("parse") != std::string::npos || reason.find("Insufficient") != std::string::npos)
                {
                    captured.error_flags = "MALFORMED";
                }
                else
                {
                    captured.error_flags = "INVALID";
                }
                
                // Store rejection reason in decoded fields
                captured.decoded_header = "REJECTED: " + reason;
                
                // Show hex dump of raw data
                std::string hex_dump;
                for (size_t i = 0; i < std::min(raw_data.size(), size_t(64)); i++)
                {
                    char buf[4];
                    snprintf(buf, sizeof(buf), "%02X ", raw_data[i]);
                    hex_dump += buf;
                    if ((i + 1) % 16 == 0) hex_dump += "\n";
                }
                captured.decoded_payload = "Raw data (first 64 bytes):\n" + hex_dump;

                logger_->warning("Invalid packet captured",
                               core::LogContext()
                                   .add("id", captured.id)
                                   .add("reason", reason)
                                   .add("size", raw_data.size())
                                   .add("transport", captured.transport));

                // Save to database if storage is available
                if (storage_)
                {
                    save_packet_to_db(captured);
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Failed to capture invalid packet",
                             core::LogContext().add("error", e.what()));
            }
        }

        std::vector<CapturedPacket> PacketMonitorService::get_packets(size_t limit, size_t offset) const
        {
            std::vector<CapturedPacket> result;

            if (!storage_) {
                logger_->warning("Storage not available, cannot retrieve packets");
                return result;
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;

                // Query all packets ordered by timestamp DESC (most recent first)
                auto all_rows = storage_->get_all<mita::db::MonitoredPacket>(
                    order_by(&mita::db::MonitoredPacket::timestamp).desc()
                );

                // Apply manual pagination
                size_t start_idx = std::min(offset, all_rows.size());
                size_t end_idx = std::min(offset + limit, all_rows.size());

                if (start_idx < end_idx) {
                    result.reserve(end_idx - start_idx);

                    for (size_t i = start_idx; i < end_idx; ++i) {
                        const auto &row = all_rows[i];
                        CapturedPacket p;
                        p.id = row.packet_id;
                        p.timestamp = std::chrono::system_clock::time_point(std::chrono::milliseconds(row.timestamp));
                        p.direction = row.direction;
                        p.source_addr = static_cast<uint16_t>(row.source_addr);
                        p.dest_addr = static_cast<uint16_t>(row.dest_addr);
                        p.message_type = row.message_type;
                        p.payload_size = static_cast<size_t>(row.payload_size);
                        p.transport = row.transport;
                        p.encrypted = row.encrypted != 0;
                        p.raw_data = hex_to_bytes(row.raw_data);
                        p.decoded_header = row.decoded_header;
                        p.decoded_payload = row.decoded_payload;
                        p.decrypted_payload = row.decrypted_payload;
                        p.is_valid = row.is_valid != 0;
                        p.error_flags = row.error_flags;
                        result.push_back(std::move(p));
                    }
                }
            } catch (const std::exception &e) {
                logger_->error("Failed to retrieve packets from database",
                             core::LogContext().add("error", e.what()));
            }

            return result;
        }

        std::vector<CapturedPacket> PacketMonitorService::get_recent_packets(size_t count) const
        {
            return get_packets(count, 0);
        }

        CapturedPacket PacketMonitorService::get_packet_by_id(const std::string &id) const
        {
            if (!storage_) {
                throw std::runtime_error("Storage not available");
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;

                // Query packet by packet_id
                auto rows = storage_->get_all<mita::db::MonitoredPacket>(
                    where(c(&mita::db::MonitoredPacket::packet_id) == id)
                );

                if (rows.empty()) {
                    throw std::runtime_error("Packet not found: " + id);
                }

                const auto &row = rows[0];
                CapturedPacket p;
                p.id = row.packet_id;
                p.timestamp = std::chrono::system_clock::time_point(std::chrono::milliseconds(row.timestamp));
                p.direction = row.direction;
                p.source_addr = static_cast<uint16_t>(row.source_addr);
                p.dest_addr = static_cast<uint16_t>(row.dest_addr);
                p.message_type = row.message_type;
                p.payload_size = static_cast<size_t>(row.payload_size);
                p.transport = row.transport;
                p.encrypted = row.encrypted != 0;
                p.raw_data = hex_to_bytes(row.raw_data);
                p.decoded_header = row.decoded_header;
                p.decoded_payload = row.decoded_payload;

                return p;
            } catch (const std::exception &e) {
                logger_->error("Failed to retrieve packet from database",
                             core::LogContext()
                                .add("packet_id", id)
                                .add("error", e.what()));
                throw;
            }
        }

        void PacketMonitorService::clear_packets()
        {
            if (!storage_) {
                logger_->warning("Storage not available, cannot clear packets");
                return;
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;
                storage_->remove_all<mita::db::MonitoredPacket>();
                logger_->info("Cleared all captured packets from database");
            } catch (const std::exception &e) {
                logger_->error("Failed to clear packets from database",
                             core::LogContext().add("error", e.what()));
                throw;
            }
        }

        size_t PacketMonitorService::get_packet_count() const
        {
            if (!storage_) {
                logger_->warning("Storage not available, cannot count packets");
                return 0;
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;
                return storage_->count<mita::db::MonitoredPacket>();
            } catch (const std::exception &e) {
                logger_->error("Failed to count packets from database",
                             core::LogContext().add("error", e.what()));
                return 0;
            }
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
            case MessageType::HEARTBEAT:
                return "HEARTBEAT";
            case MessageType::DISCONNECT:
                return "DISCONNECT";
            case MessageType::DISCONNECT_ACK:
                return "DISCONNECT_ACK";
            case MessageType::SESSION_RESUME:
                return "SESSION_RESUME";
            case MessageType::SESSION_RESUME_ACK:
                return "SESSION_RESUME_ACK";
            case MessageType::SESSION_REKEY_REQ:
                return "SESSION_REKEY_REQ";
            case MessageType::SESSION_REKEY_ACK:
                return "SESSION_REKEY_ACK";
            case MessageType::PING:
                return "PING";
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

        bool PacketMonitorService::update_packet_error(const std::string &packet_id,
                                                       const std::string &error_flags,
                                                       bool is_valid)
        {
            if (!storage_ || packet_id.empty()) {
                return false;
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;

                // Update the packet record with error information
                storage_->update_all(
                    set(c(&mita::db::MonitoredPacket::error_flags) = error_flags,
                        c(&mita::db::MonitoredPacket::is_valid) = is_valid ? 1 : 0),
                    where(c(&mita::db::MonitoredPacket::packet_id) = packet_id)
                );

                logger_->debug("Updated packet with error information",
                             core::LogContext()
                                .add("packet_id", packet_id)
                                .add("error_flags", error_flags));
                return true;
            } catch (const std::exception &e) {
                logger_->error("Failed to update packet error",
                             core::LogContext()
                                .add("packet_id", packet_id)
                                .add("error", e.what()));
                return false;
            }
        }

        bool PacketMonitorService::update_packet_decrypted(const std::string &packet_id,
                                                           const std::string &decrypted_payload)
        {
            if (!storage_ || packet_id.empty()) {
                return false;
            }

            try {
                std::lock_guard<std::mutex> lock(db_mutex_);
                using namespace sqlite_orm;

                // Update the packet record with decrypted payload
                storage_->update_all(
                    set(c(&mita::db::MonitoredPacket::decrypted_payload) = decrypted_payload),
                    where(c(&mita::db::MonitoredPacket::packet_id) = packet_id)
                );

                logger_->debug("Updated packet with decrypted payload",
                             core::LogContext()
                                .add("packet_id", packet_id)
                                .add("decrypted_size", decrypted_payload.size()));
                return true;
            } catch (const std::exception &e) {
                logger_->error("Failed to update packet with decrypted payload",
                             core::LogContext()
                                .add("packet_id", packet_id)
                                .add("error", e.what()));
                return false;
            }
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
                db_packet.decrypted_payload = packet.decrypted_payload;
                db_packet.is_valid = packet.is_valid ? 1 : 0;
                db_packet.error_flags = packet.error_flags;

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

        std::vector<uint8_t> PacketMonitorService::hex_to_bytes(const std::string &hex) const
        {
            std::vector<uint8_t> bytes;
            if (hex.empty()) return bytes;
            size_t len = hex.length();
            bytes.reserve(len / 2);
            for (size_t i = 0; i + 1 < len; i += 2) {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
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
