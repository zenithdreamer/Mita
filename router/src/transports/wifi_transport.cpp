#include "transports/wifi_transport.hpp"
#include "transports/wifi_client_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "config/mita_config.h"
#include "transport/transport_constants.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <vector>
#include <ifaddrs.h>
#include <net/if.h>

namespace mita
{
    namespace transports
    {

        // WiFiTransport implementation
        WiFiTransport::WiFiTransport(const core::RouterConfig &config,
                                     services::RoutingService &routing_service,
                                     services::DeviceManagementService &device_management,
                                     services::StatisticsService &statistics_service,
                                     std::shared_ptr<services::PacketMonitorService> packet_monitor)
            : BaseTransport(config, routing_service, device_management, statistics_service),
              raw_socket_(-1),
              logger_(core::get_logger("WiFiTransport")),
              packet_monitor_(packet_monitor)
        {
            // Get WiFi AP IP from config
            wifi_ap_ip_ = config_.wifi.server_host;
            
            logger_->info("WiFi transport initialized",
                          core::LogContext()
                              .add("protocol", MITA_IP_PROTOCOL)
                              .add("ap_ip", wifi_ap_ip_));
        }

        WiFiTransport::~WiFiTransport()
        {
            stop();
        }

        bool WiFiTransport::start()
        {
            if (running_.exchange(true))
            {
                return true; // Already running
            }

            try
            {
                // Create raw socket for custom IP protocol
                raw_socket_ = socket(AF_INET, SOCK_RAW, MITA_IP_PROTOCOL);
                if (raw_socket_ < 0)
                {
                    logger_->error("Failed to create raw socket",
                                   core::LogContext().add("error", strerror(errno)).add("protocol", MITA_IP_PROTOCOL));
                    return false;
                }

                // Set socket to non-blocking
                int flags = fcntl(raw_socket_, F_GETFL, 0);
                fcntl(raw_socket_, F_SETFL, flags | O_NONBLOCK);

                // Enable IP header inclusion for sending
                int one = 1;
                if (setsockopt(raw_socket_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
                {
                    logger_->warning("Failed to set IP_HDRINCL",
                                     core::LogContext().add("error", strerror(errno)));
                }

                // Get local IP address
                struct ifaddrs *ifaddr, *ifa;
                if (getifaddrs(&ifaddr) == -1)
                {
                    logger_->warning("Failed to get network interfaces",
                                     core::LogContext().add("error", strerror(errno)));
                    local_ip_ = "0.0.0.0"; // Fallback
                }
                else
                {
                    // Find first non-loopback IPv4 address
                    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
                    {
                        if (ifa->ifa_addr == nullptr)
                            continue;

                        if (ifa->ifa_addr->sa_family == AF_INET)
                        {
                            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                            char ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);

                            // Skip loopback
                            if (strcmp(ip_str, "127.0.0.1") != 0)
                            {
                                local_ip_ = ip_str;
                                break;
                            }
                        }
                    }
                    freeifaddrs(ifaddr);

                    if (local_ip_.empty())
                    {
                        local_ip_ = "0.0.0.0"; // Fallback
                    }
                }

                logger_->info("Using local IP for raw packets",
                              core::LogContext().add("local_ip", local_ip_));

                // Start receive thread
                receive_thread_ = std::make_unique<std::thread>(&WiFiTransport::receive_packets, this);

                // Register message handler
                device_management_.register_message_handler("wifi", [this](const std::string &device_id, const protocol::ProtocolPacket &packet)
                                                            { send_packet(device_id, packet); });

                logger_->info("WiFi transport started",
                              core::LogContext().add("protocol", MITA_IP_PROTOCOL));
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception starting WiFi transport",
                               core::LogContext().add("error", e.what()));
                running_ = false;
                return false;
            }
        }

        void WiFiTransport::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            // Close raw socket to stop receiving
            if (raw_socket_ >= 0)
            {
                close(raw_socket_);
                raw_socket_ = -1;
            }

            // Wait for receive thread
            if (receive_thread_ && receive_thread_->joinable())
            {
                receive_thread_->join();
            }

            // Stop all client handlers
            {
                std::lock_guard<std::recursive_mutex> lock(clients_mutex_);
                for (auto &[device_id, handler] : client_handlers_)
                {
                    handler->stop();
                }
                client_handlers_.clear();
                ip_to_device_.clear();
            }

            logger_->info("WiFi transport stopped");
        }

        bool WiFiTransport::send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
        {
            logger_->debug("WiFiTransport::send_packet called",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("msg_type", static_cast<int>(packet.get_message_type()))
                               .add("dest", packet.get_dest_addr())
                               .add("src", packet.get_source_addr()));

            std::lock_guard<std::recursive_mutex> lock(clients_mutex_);

            auto *handler = find_client_handler(device_id);
            if (!handler)
            {
                logger_->warning("Cannot send packet - device not found",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("available_handlers", client_handlers_.size()));

                // Log all available device IDs
                for (const auto &[id, h] : client_handlers_)
                {
                    logger_->debug("Available client handler",
                                   core::LogContext().add("device_id", id));
                }
                return false;
            }

            logger_->debug("WiFiTransport::send_packet - found handler, sending",
                           core::LogContext().add("device_id", device_id));

            bool result = handler->send_packet(packet);
            logger_->debug("WiFiTransport::send_packet result",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("result", result));
            return result;
        }

        int WiFiTransport::broadcast_packet(const protocol::ProtocolPacket &packet)
        {
            std::lock_guard<std::recursive_mutex> lock(clients_mutex_);

            int sent_count = 0;
            for (auto &[device_id, handler] : client_handlers_)
            {
                if (handler->is_authenticated() && handler->send_packet(packet))
                {
                    sent_count++;
                }
            }

            return sent_count;
        }

        std::string WiFiTransport::get_connection_info() const
        {
            return "WiFi Raw IP - Protocol " + std::to_string(MITA_IP_PROTOCOL);
        }

        void WiFiTransport::receive_packets()
        {
            logger_->info("WiFi transport receiving packets");

            auto last_cleanup = std::chrono::steady_clock::now();
            const auto cleanup_interval = std::chrono::seconds(5);

            const size_t max_packet_size = 65535;
            uint8_t *buffer = new uint8_t[max_packet_size];

            while (running_)
            {
                auto now = std::chrono::steady_clock::now();
                if (now - last_cleanup >= cleanup_interval)
                {
                    cleanup_disconnected_clients();
                    last_cleanup = now;
                }

                struct sockaddr_in src_addr;
                socklen_t addr_len = sizeof(src_addr);

                ssize_t received = recvfrom(raw_socket_, buffer, max_packet_size, 0,
                                            (struct sockaddr *)&src_addr, &addr_len);

                if (received > 0)
                {
                    // Extract IP header
                    struct ip *ip_hdr = (struct ip *)buffer;
                    uint8_t ihl = ip_hdr->ip_hl * 4; // Header length in bytes

                    // Verify it's our protocol
                    if (ip_hdr->ip_p == MITA_IP_PROTOCOL && received > ihl)
                    {
                        // Extract source IP
                        char source_ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(ip_hdr->ip_src), source_ip_str, INET_ADDRSTRLEN);
                        std::string source_ip(source_ip_str);

                        // Extract payload (skip IP header)
                        const uint8_t *payload = buffer + ihl;
                        size_t payload_len = received - ihl;

                        handle_packet_from_ip(source_ip, payload, payload_len);
                    }
                }
                else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    if (running_)
                    {
                        logger_->error("recvfrom error",
                                       core::LogContext().add("error", strerror(errno)));
                    }
                }

                // Small delay to avoid busy waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            delete[] buffer;
            logger_->debug("WiFi transport stopped receiving");
        }

        void WiFiTransport::handle_packet_from_ip(const std::string &source_ip, const uint8_t *data, size_t length)
        {
            // Deserialize the packet
            auto packet_ptr = protocol::ProtocolPacket::from_bytes(data, length);
            if (!packet_ptr)
            {
                logger_->warning("Failed to deserialize packet",
                                 core::LogContext().add("source_ip", source_ip));
                return;
            }

            protocol::ProtocolPacket &packet = *packet_ptr;

            // Check if this is a HELLO packet (new connection)
            if (packet.get_message_type() == MessageType::HELLO)
            {
                std::string router_id, device_id;
                std::vector<uint8_t> nonce1;
                if (!protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce1))
                {
                    logger_->warning("Failed to parse HELLO packet",
                                     core::LogContext().add("source_ip", source_ip));
                    return;
                }
                std::lock_guard<std::recursive_mutex> lock(clients_mutex_);

                // Check if we already have a handler for this device
                auto it = client_handlers_.find(device_id);
                if (it == client_handlers_.end())
                {
                    // New device - check connection limit
                    if (client_handlers_.size() >= static_cast<size_t>(config_.wifi.max_connections))
                    {
                        logger_->warning("Connection limit reached, rejecting client",
                                         core::LogContext().add("device_id", device_id).add("source_ip", source_ip));
                        return;
                    }

                    // Create new handler
                    try
                    {
                        auto handler = std::make_unique<WiFiClientHandler>(
                            source_ip, config_,
                            routing_service_, device_management_, statistics_service_, packet_monitor_);

                        // Set send callback
                        handler->set_send_callback([this](const std::string &ip, const uint8_t *data, size_t len)
                                                   { return send_raw_packet(ip, data, len); });

                        client_handlers_[device_id] = std::move(handler);
                        ip_to_device_[source_ip] = device_id;

                        client_handlers_[device_id]->start(packet);

                        logger_->info("New WiFi client connected",
                                      core::LogContext().add("device_id", device_id).add("source_ip", source_ip));
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Exception creating client handler",
                                       core::LogContext().add("device_id", device_id).add("error", e.what()));
                        statistics_service_.record_transport_error("wifi");
                    }
                }
                else
                {
                    // Existing device - update IP if changed
                    ip_to_device_[source_ip] = device_id;
                    it->second->handle_packet(packet);
                }
            }
            else
            {
                // Regular packet - find handler by IP
                std::lock_guard<std::recursive_mutex> lock(clients_mutex_);

                auto handler = find_client_by_ip(source_ip);
                if (handler)
                {
                    handler->handle_packet(packet);
                }
                else
                {
                    logger_->warning("Received packet from unknown source",
                                     core::LogContext().add("source_ip", source_ip));
                }
            }
        }

        bool WiFiTransport::send_raw_packet(const std::string &dest_ip, const uint8_t *data, size_t length)
        {
            if (raw_socket_ < 0)
            {
                return false;
            }

            // Calculate total packet size (IP header + data)
            const size_t ip_header_len = 20;
            size_t total_len = ip_header_len + length;
            uint8_t *packet = new uint8_t[total_len];

            // Build IP header
            memset(packet, 0, ip_header_len);

            // Version (4) and IHL (5 = 20 bytes)
            packet[0] = 0x45;

            // Type of Service
            packet[1] = 0;

            // Total Length
            packet[2] = (total_len >> 8) & 0xFF;
            packet[3] = total_len & 0xFF;

            // Identification
            static uint16_t ip_id = 0;
            ip_id++;
            packet[4] = (ip_id >> 8) & 0xFF;
            packet[5] = ip_id & 0xFF;

            // Flags and Fragment Offset
            packet[6] = 0x40; // Don't fragment
            packet[7] = 0;

            // TTL
            packet[8] = 64;

            // Protocol
            packet[9] = MITA_IP_PROTOCOL;

            // Header Checksum (will be calculated)
            packet[10] = 0;
            packet[11] = 0;

            // Determine source IP based on destination subnet
            // If destination is on WiFi AP subnet (192.168.50.x), use WiFi AP IP as source
            std::string src_ip;
            if (dest_ip.substr(0, 11) == "192.168.50.")
            {
                src_ip = wifi_ap_ip_;  // Use WiFi AP interface IP
            }
            else
            {
                src_ip = local_ip_;  // Use main network interface IP
            }

            // Source IP
            struct in_addr src_addr;
            inet_pton(AF_INET, src_ip.c_str(), &src_addr);
            memcpy(packet + 12, &src_addr, 4);

            // Destination IP
            struct in_addr dest_addr;
            inet_pton(AF_INET, dest_ip.c_str(), &dest_addr);
            memcpy(packet + 16, &dest_addr, 4);

            // Calculate IP header checksum
            uint32_t sum = 0;
            for (size_t i = 0; i < ip_header_len; i += 2)
            {
                uint16_t word = (packet[i] << 8) | packet[i + 1];
                sum += word;
            }
            while (sum >> 16)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            uint16_t checksum = ~sum;
            packet[10] = (checksum >> 8) & 0xFF;
            packet[11] = checksum & 0xFF;

            // Copy payload
            memcpy(packet + ip_header_len, data, length);

            // Send packet
            struct sockaddr_in dest_sockaddr;
            memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));
            dest_sockaddr.sin_family = AF_INET;
            dest_sockaddr.sin_addr = dest_addr;

            ssize_t sent = sendto(raw_socket_, packet, total_len, 0,
                                  (struct sockaddr *)&dest_sockaddr, sizeof(dest_sockaddr));

            delete[] packet;

            if (sent < 0)
            {
                logger_->error("sendto failed",
                               core::LogContext().add("error", strerror(errno)).add("dest_ip", dest_ip));
                return false;
            }

            logger_->debug("Raw packet sent successfully",
                           core::LogContext()
                               .add("dest_ip", dest_ip)
                               .add("src_ip", src_ip)
                               .add("payload_size", length)
                               .add("total_size", total_len)
                               .add("sent_bytes", sent));

            return sent == (ssize_t)total_len;
        }

        void WiFiTransport::cleanup_disconnected_clients()
        {
            {
                std::lock_guard<std::recursive_mutex> lock(clients_mutex_);
                for (auto& pair : client_handlers_)
                {
                    if (pair.second)
                    {
                        pair.second->check_heartbeat_timeout();
                    }
                }
            }

            std::vector<std::unique_ptr<WiFiClientHandler>> handlers_to_cleanup;

            {
                std::lock_guard<std::recursive_mutex> lock(clients_mutex_);

                int cleaned = 0;
                auto it = client_handlers_.begin();
                while (it != client_handlers_.end())
                {
                    if (it->second && it->second->check_for_disconnected())
                    {
                        std::string device_id = it->first;
                        std::string client_ip = it->second->get_client_ip();

                        logger_->info("Removing disconnected client",
                                      core::LogContext().add("device_id", device_id).add("ip", client_ip));

                        if (!device_id.empty())
                        {
                            device_management_.remove_device(device_id);
                        }

                        // Remove IP mapping
                        ip_to_device_.erase(client_ip);

                        handlers_to_cleanup.push_back(std::move(it->second));
                        it = client_handlers_.erase(it);
                        cleaned++;
                    }
                    else
                    {
                        ++it;
                    }
                }

                if (cleaned > 0)
                {
                    logger_->info("Cleaned up disconnected clients",
                                  core::LogContext().add("cleaned_count", cleaned).add("remaining", client_handlers_.size()));
                }
            }

            handlers_to_cleanup.clear();
        }

        std::vector<WiFiClientHandler*> WiFiTransport::get_all_client_handlers() const
        {
            std::lock_guard<std::recursive_mutex> lock(clients_mutex_);
            std::vector<WiFiClientHandler*> handlers;

            for (const auto& device : client_handlers_)
            {
                if (device.second)
                {
                    handlers.push_back(device.second.get());
                }
            }

            return handlers;
        }

        WiFiClientHandler *WiFiTransport::find_client_handler(const std::string &device_id)
        {
            auto it = client_handlers_.find(device_id);
            if (it != client_handlers_.end())
            {
                return it->second.get();
            }
            return nullptr;
        }

        WiFiClientHandler *WiFiTransport::find_client_by_ip(const std::string &ip_address)
        {
            auto it = ip_to_device_.find(ip_address);
            if (it != ip_to_device_.end())
            {
                return find_client_handler(it->second);
            }
            return nullptr;
        }

    } // namespace transports
} // namespace mita