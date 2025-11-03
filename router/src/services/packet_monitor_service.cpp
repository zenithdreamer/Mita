#include "services/packet_monitor_service.hpp"
#include "core/logger.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace mita
{
    namespace services
    {

        PacketMonitorService::PacketMonitorService(size_t max_packets)
            : logger_(core::get_logger("PacketMonitor")), max_packets_(max_packets)
        {
            logger_->info("Packet Monitor Service initialized", 
                         core::LogContext().add("max_packets", max_packets));
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
                captured.source_addr = packet.get_source_addr();
                captured.dest_addr = packet.get_dest_addr();
                captured.message_type = message_type_to_string(packet.get_message_type());
                captured.payload_size = packet.get_payload().size();
                captured.transport = (transport == core::TransportType::WIFI) ? "wifi" : "ble";
                captured.encrypted = packet.is_encrypted();
                captured.raw_data = packet.to_bytes();
                captured.decoded_header = decode_header(packet);
                captured.decoded_payload = decode_payload(packet);

                std::lock_guard<std::mutex> lock(packets_mutex_);
                
                // Add to front (most recent first)
                packets_.push_front(captured);

                // Remove oldest if exceeding limit
                while (packets_.size() > max_packets_)
                {
                    packets_.pop_back();
                }

                logger_->debug("Captured packet",
                             core::LogContext()
                                 .add("id", captured.id)
                                 .add("direction", direction)
                                 .add("type", captured.message_type));
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
        }

        std::string PacketMonitorService::decode_payload(const protocol::ProtocolPacket &packet) const
        {
            const auto &payload = packet.get_payload();

            if (payload.empty())
            {
                return "Empty payload";
            }

            std::ostringstream oss;

            // Hex dump
            oss << "Hex dump (" << payload.size() << " bytes):\n";
            for (size_t i = 0; i < payload.size(); ++i)
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
            for (size_t i = 0; i < payload.size(); ++i)
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

            return oss.str();
        }

    } // namespace services
} // namespace mita
