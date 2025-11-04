#include "transports/wifi_client_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>

namespace mita
{
    namespace transports
    {

        // WiFiClientHandler implementation
        WiFiClientHandler::WiFiClientHandler(int client_socket, const sockaddr_in &client_addr,
                                             const core::RouterConfig &config,
                                             services::RoutingService &routing_service,
                                             services::DeviceManagementService &device_management,
                                             services::StatisticsService &statistics_service,
                                             std::shared_ptr<services::PacketMonitorService> packet_monitor)
            : client_socket_(client_socket), client_addr_(client_addr), config_(config), routing_service_(routing_service), device_management_(device_management), statistics_service_(statistics_service), packet_monitor_(packet_monitor), assigned_address_(0), authenticated_(false), running_(false), logger_(core::get_logger("WiFiClientHandler"))
        {

            // Convert client address to string
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr_.sin_addr, addr_str, INET_ADDRSTRLEN);
            client_address_str_ = std::string(addr_str) + ":" + std::to_string(ntohs(client_addr_.sin_port));

            // Initialize handshake manager
            handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                config_.router_id, config_.shared_secret);

            logger_->info("WiFi client handler created",
                          core::LogContext().add("client_address", client_address_str_));
        }

        WiFiClientHandler::~WiFiClientHandler()
        {
            stop();
        }

        void WiFiClientHandler::start(std::optional<protocol::ProtocolPacket> initial_hello)
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            // Store the initial HELLO if provided
            pending_hello_ = std::move(initial_hello);

            handler_thread_ = std::make_unique<std::thread>(&WiFiClientHandler::handle_client, this);
            logger_->debug("WiFi client handler started",
                           core::LogContext().add("client_address", client_address_str_).add("has_hello", pending_hello_.has_value()));
        }

        void WiFiClientHandler::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            if (handler_thread_ && handler_thread_->joinable())
            {
                handler_thread_->join();
            }

            cleanup();
            logger_->debug("WiFi client handler stopped",
                           core::LogContext().add("client_address", client_address_str_));
        }

        void WiFiClientHandler::reconnect(int new_socket, const sockaddr_in &new_addr,
                                           const protocol::ProtocolPacket &hello_packet)
        {
            logger_->info("Reconnecting client handler",
                          core::LogContext().add("device_id", device_id_).add("old_address", client_address_str_));

            // Stop the handler thread if it's running
            bool was_running = running_.exchange(false);
            if (was_running && handler_thread_ && handler_thread_->joinable())
            {
                handler_thread_->join();
                handler_thread_.reset();
            }

            // Close old socket
            cleanup();

            // Update to new socket and address
            client_socket_ = new_socket;
            client_addr_ = new_addr;

            // Update address string
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr_.sin_addr, addr_str, INET_ADDRSTRLEN);
            client_address_str_ = std::string(addr_str) + ":" + std::to_string(ntohs(client_addr_.sin_port));

            // Reset authentication state
            authenticated_ = false;
            session_crypto_.reset();

            // Reinitialize handshake manager
            handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                config_.router_id, config_.shared_secret);

            logger_->info("Client handler reconnected",
                          core::LogContext().add("device_id", device_id_).add("new_address", client_address_str_));

            // Start with the HELLO packet we already received
            start(hello_packet);
        }

        bool WiFiClientHandler::send_packet(const protocol::ProtocolPacket &packet)
        {
            if (!running_ || client_socket_ < 0)
            {
                return false;
            }

            try
            {
                // Capture outbound packet for monitoring (handshake or data)
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "outbound", core::TransportType::WIFI);
                }

                auto packet_data = packet.to_bytes();

                // Send packet data directly (no size prefix)
                ssize_t sent = send(client_socket_, packet_data.data(), packet_data.size(), MSG_NOSIGNAL);
                if (sent != static_cast<ssize_t>(packet_data.size()))
                {
                    logger_->error("Failed to send packet data",
                                   core::LogContext().add("client_address", client_address_str_).add("expected", packet_data.size()).add("sent", sent).add("error", strerror(errno)));
                    return false;
                }

                statistics_service_.record_transport_packet_sent("wifi", packet_data.size());
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception sending packet",
                               core::LogContext().add("client_address", client_address_str_).add("error", e.what()));
                statistics_service_.record_transport_error("wifi");
                return false;
            }
        }

        void WiFiClientHandler::handle_client()
        {
            logger_->info("Handling WiFi client connection",
                          core::LogContext().add("client_address", client_address_str_));

            try
            {
                // Set socket timeout
                struct timeval timeout;
                timeout.tv_sec = config_.security.handshake_timeout;
                timeout.tv_usec = 0;
                setsockopt(client_socket_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                // Process pending HELLO first if we have one
                if (pending_hello_)
                {
                    logger_->debug("Processing pending HELLO packet",
                                   core::LogContext().add("client_address", client_address_str_));
                    handle_handshake_packet(*pending_hello_);
                    pending_hello_.reset(); // Clear it
                }

                while (running_)
                {
                    protocol::ProtocolPacket packet;
                    if (receive_packet(packet, 5000))
                    { // 5 second timeout
                        // While not authenticated, treat all incoming packets as potential handshake packets
                        // (HELLO followed by AUTH).
                        if (!authenticated_)
                        {
                            handle_handshake_packet(packet);
                        }
                        else
                        {
                            handle_data_packet(packet);
                        }
                    }
                    else
                    {
                        // Timeout or error - check if we should continue
                        if (!running_)
                        {
                            break;
                        }

                        if (!authenticated_)
                        {
                            logger_->warning("Client handshake timeout",
                                             core::LogContext().add("client_address", client_address_str_));
                            break;
                        }
                    }
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception handling client",
                               core::LogContext().add("client_address", client_address_str_).add("error", e.what()));
                statistics_service_.record_transport_error("wifi");
            }

            // Clean up device registration comment because now it broke when do fast reconnect
            // if (!device_id_.empty())
            // {
            //     device_management_.remove_device(device_id_);
            // }

            cleanup();
        }

        bool WiFiClientHandler::receive_packet_from_socket(int socket,
                                                           protocol::ProtocolPacket &packet,
                                                           int timeout_ms,
                                                           std::shared_ptr<core::Logger> logger)
        {
            if (socket < 0)
            {
                return false;
            }

            try
            {
                // Use select for timeout
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(socket, &read_fds);

                struct timeval timeout;
                timeout.tv_sec = timeout_ms / 1000;
                timeout.tv_usec = (timeout_ms % 1000) * 1000;

                int select_result = select(socket + 1, &read_fds, nullptr, nullptr, &timeout);
                if (select_result <= 0)
                {
                    return false; // Timeout or error
                }

                // Read header first (16 bytes)
                const size_t header_size = 16; // HEADER_SIZE from protocol
                std::vector<uint8_t> header_data(header_size);
                ssize_t received = recv(socket, header_data.data(), header_size, MSG_WAITALL);
                if (received != static_cast<ssize_t>(header_size))
                {
                    return false;
                }

                // Extract payload length from header (byte 6)
                uint8_t payload_length = header_data[6];

                // payload_length is uint8_t (0-255) so it's always <= 256, no validation needed

                // Read payload if present
                std::vector<uint8_t> packet_data = header_data;
                if (payload_length > 0)
                {
                    std::vector<uint8_t> payload_data(payload_length);
                    received = recv(socket, payload_data.data(), payload_length, MSG_WAITALL);
                    if (received != static_cast<ssize_t>(payload_length))
                    {
                        if (logger)
                        {
                            logger->error("fail to receive packet",
                                         core::LogContext().add("expected", payload_length).add("received", received));
                        }
                        return false;
                    }
                    packet_data.insert(packet_data.end(), payload_data.begin(), payload_data.end());
                }

                // Parse packet
                auto parsed_packet = protocol::ProtocolPacket::from_bytes(packet_data);
                if (!parsed_packet)
                {
                    if (logger)
                    {
                        logger->error("failed to parse packet");
                    }
                    return false;
                }

                packet = *parsed_packet;
                return true;
            }
            catch (const std::exception &e)
            {
                if (logger)
                {
                    logger->error("Exception receiving packet",
                                 core::LogContext().add("error", e.what()));
                }
                return false;
            }
        }

        bool WiFiClientHandler::receive_packet(protocol::ProtocolPacket &packet, int timeout_ms)
        {
            if (client_socket_ < 0)
            {
                return false;
            }

            bool success = receive_packet_from_socket(client_socket_, packet, timeout_ms, logger_);

            if (success)
            {
                // Capture incoming packet for monitoring (handshake or data)
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "inbound", core::TransportType::WIFI);
                }

                size_t packet_size = 16 + packet.get_payload().size();
                statistics_service_.record_transport_packet_received("wifi", packet_size);
            }
            else
            {
                statistics_service_.record_transport_error("wifi");
            }

            return success;
        }

        void WiFiClientHandler::handle_handshake_packet(const protocol::ProtocolPacket &packet)
        {
            try
            {
                if (packet.get_message_type() == MessageType::HELLO)
                {
                    std::string router_id, device_id;
                    std::vector<uint8_t> nonce1;

                    if (protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce1))
                    {
                        if (router_id == config_.router_id)
                        {
                            device_id_ = device_id;

                            // Register device in device management
                            if (device_management_.register_device(device_id_, core::TransportType::WIFI))
                            {
                                // Get assigned address from routing service
                                assigned_address_ = routing_service_.get_device_address(device_id_);

                                if (assigned_address_ == 0)
                                {
                                    logger_->error("Device registered but no address assigned",
                                                   core::LogContext().add("device_id", device_id_));
                                    device_management_.remove_device(device_id_);
                                    return;
                                }

                                // Create challenge packet
                                auto challenge_packet = handshake_manager_->create_challenge_packet(device_id_, nonce1);
                                if (challenge_packet && send_packet(*challenge_packet))
                                {
                                    logger_->info("Sent challenge to device",
                                                  core::LogContext().add("device_id", device_id_).add("assigned_address", assigned_address_));
                                }
                                else
                                {
                                    logger_->error("Failed to send challenge packet",
                                                   core::LogContext().add("device_id", device_id_));
                                    device_management_.remove_device(device_id_);
                                }
                            }
                            else
                            {
                                logger_->error("Failed to register device",
                                               core::LogContext().add("device_id", device_id_));
                            }
                        }
                        else
                        {
                            logger_->warning("Invalid router ID in HELLO packet",
                                             core::LogContext().add("expected", config_.router_id).add("received", router_id));
                        }
                    }
                    else
                    {
                        logger_->error("Failed to parse HELLO packet",
                                       core::LogContext().add("client_address", client_address_str_));
                    }
                }
                else if (packet.get_message_type() == MessageType::AUTH)
                {
                    if (device_id_.empty())
                    {
                        logger_->warning("Received AUTH without HELLO",
                                         core::LogContext().add("client_address", client_address_str_));
                        return;
                    }

                    // Verify authentication packet
                    if (handshake_manager_->verify_auth_packet(device_id_, packet))
                    {
                        // Authentication successful
                        logger_->info("Device authentication successful",
                                      core::LogContext().add("device_id", device_id_));

                        // Create AUTH_ACK packet before completing handshake
                        auto auth_ack_packet = handshake_manager_->create_auth_ack_packet(device_id_, assigned_address_);

                        if (auth_ack_packet && send_packet(*auth_ack_packet))
                        {
                            // Mark as authenticated
                            authenticated_ = true;

                            // Obtain session crypto for this device if available
                            session_crypto_ = handshake_manager_->get_session_crypto(device_id_);
                            // Remove handshake state as it's no longer needed
                            handshake_manager_->remove_handshake(device_id_);

                            // Inform device management so state moves from HANDSHAKING -> AUTHENTICATED
                            if (session_crypto_)
                            {
                                device_management_.authenticate_device(device_id_, std::shared_ptr<protocol::PacketCrypto>(session_crypto_.release()));
                            }
                            else
                            {
                                // Even without crypto (should not happen), attempt to authenticate
                                device_management_.authenticate_device(device_id_, nullptr);
                            }

                            logger_->info("Device authenticated and AUTH_ACK sent",
                                          core::LogContext().add("device_id", device_id_).add("assigned_address", assigned_address_));
                        }
                        else
                        {
                            logger_->error("Failed to send AUTH_ACK packet",
                                           core::LogContext().add("device_id", device_id_));
                            device_management_.remove_device(device_id_);
                        }
                    }
                    else
                    {
                        // Authentication failed
                        logger_->warning("Authentication verification failed",
                                         core::LogContext().add("device_id", device_id_));
                        device_management_.remove_device(device_id_);
                        running_ = false;
                    }
                }
            } // end try block
            catch (const std::exception &e)
            {
                logger_->error("Exception handling handshake packet",
                               core::LogContext().add("client_address", client_address_str_).add("error", e.what()));
                statistics_service_.record_protocol_error();
            }
        }

        void WiFiClientHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
        {
            if (device_id_.empty())
            {
                return;
            }

            // Forward to device management service
            device_management_.handle_packet(device_id_, packet, core::TransportType::WIFI);
        }

        void WiFiClientHandler::cleanup()
        {
            if (client_socket_ >= 0)
            {
                close(client_socket_);
                client_socket_ = -1;
            }
        }

    } // namespace transports
} // namespace mita
