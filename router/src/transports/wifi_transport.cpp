#include "transports/wifi_transport.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"

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
                                             services::StatisticsService &statistics_service)
            : client_socket_(client_socket), client_addr_(client_addr), config_(config), routing_service_(routing_service), device_management_(device_management), statistics_service_(statistics_service), assigned_address_(0), authenticated_(false), running_(false), logger_(core::get_logger("WiFiClientHandler"))
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

        void WiFiClientHandler::start()
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            handler_thread_ = std::make_unique<std::thread>(&WiFiClientHandler::handle_client, this);
            logger_->debug("WiFi client handler started",
                           core::LogContext().add("client_address", client_address_str_));
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

        bool WiFiClientHandler::send_packet(const protocol::ProtocolPacket &packet)
        {
            if (!running_ || client_socket_ < 0)
            {
                return false;
            }

            try
            {
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

            // Clean up device registration
            if (!device_id_.empty())
            {
                device_management_.remove_device(device_id_);
            }

            cleanup();
        }

        bool WiFiClientHandler::receive_packet(protocol::ProtocolPacket &packet, int timeout_ms)
        {
            if (client_socket_ < 0)
            {
                return false;
            }

            try
            {
                // Use select for timeout
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(client_socket_, &read_fds);

                struct timeval timeout;
                timeout.tv_sec = timeout_ms / 1000;
                timeout.tv_usec = (timeout_ms % 1000) * 1000;

                int select_result = select(client_socket_ + 1, &read_fds, nullptr, nullptr, &timeout);
                if (select_result <= 0)
                {
                    return false; // Timeout or error
                }

                // Read header first (8 bytes)
                const size_t header_size = 8; // HEADER_SIZE from protocol
                std::vector<uint8_t> header_data(header_size);
                ssize_t received = recv(client_socket_, header_data.data(), header_size, MSG_WAITALL);
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
                    received = recv(client_socket_, payload_data.data(), payload_length, MSG_WAITALL);
                    if (received != static_cast<ssize_t>(payload_length))
                    {
                        logger_->error("Failed to receive complete payload",
                                       core::LogContext().add("client_address", client_address_str_).add("expected", payload_length).add("received", received));
                        return false;
                    }
                    packet_data.insert(packet_data.end(), payload_data.begin(), payload_data.end());
                }

                // Parse packet
                auto parsed_packet = protocol::ProtocolPacket::from_bytes(packet_data);
                if (!parsed_packet)
                {
                    logger_->error("Failed to parse packet",
                                   core::LogContext().add("client_address", client_address_str_));
                    return false;
                }

                packet = *parsed_packet;
                statistics_service_.record_transport_packet_received("wifi", packet_data.size());
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception receiving packet",
                               core::LogContext().add("client_address", client_address_str_).add("error", e.what()));
                statistics_service_.record_transport_error("wifi");
                return false;
            }
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

        // WiFiTransport implementation
        WiFiTransport::WiFiTransport(const core::RouterConfig &config,
                                     services::RoutingService &routing_service,
                                     services::DeviceManagementService &device_management,
                                     services::StatisticsService &statistics_service)
            : BaseTransport(config, routing_service, device_management, statistics_service), server_socket_(-1), logger_(core::get_logger("WiFiTransport"))
        {

            memset(&server_addr_, 0, sizeof(server_addr_));
            server_addr_.sin_family = AF_INET;
            server_addr_.sin_port = htons(config_.wifi.server_port);
            inet_pton(AF_INET, config_.wifi.server_host.c_str(), &server_addr_.sin_addr);

            logger_->info("WiFi transport initialized",
                          core::LogContext().add("host", config_.wifi.server_host).add("port", config_.wifi.server_port));
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
                // Create server socket
                server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
                if (server_socket_ < 0)
                {
                    logger_->error("Failed to create server socket",
                                   core::LogContext().add("error", strerror(errno)));
                    return false;
                }

                // Set socket options
                int opt = 1;
                if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
                {
                    logger_->warning("Failed to set SO_REUSEADDR",
                                     core::LogContext().add("error", strerror(errno)));
                }

                // Bind socket
                if (bind(server_socket_, reinterpret_cast<struct sockaddr *>(&server_addr_),
                         sizeof(server_addr_)) < 0)
                {
                    logger_->error("Failed to bind server socket",
                                   core::LogContext().add("host", config_.wifi.server_host).add("port", config_.wifi.server_port).add("error", strerror(errno)));
                    close(server_socket_);
                    server_socket_ = -1;
                    running_ = false;
                    return false;
                }

                // Listen for connections
                if (listen(server_socket_, config_.wifi.max_connections) < 0)
                {
                    logger_->error("Failed to listen on server socket",
                                   core::LogContext().add("error", strerror(errno)));
                    close(server_socket_);
                    server_socket_ = -1;
                    running_ = false;
                    return false;
                }

                // Start accept thread
                accept_thread_ = std::make_unique<std::thread>(&WiFiTransport::accept_connections, this);

                // Register message handler
                device_management_.register_message_handler("wifi", [this](const std::string &device_id, const protocol::ProtocolPacket &packet)
                                                            { send_packet(device_id, packet); });

                logger_->info("WiFi transport started",
                              core::LogContext().add("host", config_.wifi.server_host).add("port", config_.wifi.server_port));
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

            // Close server socket to stop accepting connections
            if (server_socket_ >= 0)
            {
                close(server_socket_);
                server_socket_ = -1;
            }

            // Wait for accept thread
            if (accept_thread_ && accept_thread_->joinable())
            {
                accept_thread_->join();
            }

            // Stop all client handlers
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                for (auto &[device_id, handler] : client_handlers_)
                {
                    handler->stop();
                }
                client_handlers_.clear();
            }

            logger_->info("WiFi transport stopped");
        }

        bool WiFiTransport::send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);

            auto *handler = find_client_handler(device_id);
            if (!handler)
            {
                logger_->warning("Cannot send packet - device not found",
                                 core::LogContext().add("device_id", device_id));
                return false;
            }

            return handler->send_packet(packet);
        }

        int WiFiTransport::broadcast_packet(const protocol::ProtocolPacket &packet)
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);

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
            return "WiFi TCP Server " + config_.wifi.server_host + ":" +
                   std::to_string(config_.wifi.server_port);
        }

        void WiFiTransport::accept_connections()
        {
            logger_->info("WiFi transport accepting connections");

            // Set socket to non-blocking for better shutdown behavior
            int flags = fcntl(server_socket_, F_GETFL, 0);
            fcntl(server_socket_, F_SETFL, flags | O_NONBLOCK);

            while (running_)
            {
                sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);

                int client_socket = accept(server_socket_,
                                           reinterpret_cast<struct sockaddr *>(&client_addr),
                                           &client_addr_len);

                if (client_socket == -1)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        // No connection available, sleep briefly and continue
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        continue;
                    }
                    else if (running_)
                    {
                        logger_->error("Failed to accept client connection",
                                       core::LogContext().add("error", strerror(errno)));
                    }
                    continue;
                }

                if (!running_)
                {
                    close(client_socket);
                    break;
                }

                handle_new_client(client_socket, client_addr);
            }

            logger_->debug("WiFi transport stopped accepting connections");
        }

        void WiFiTransport::handle_new_client(int client_socket, const sockaddr_in &client_addr)
        {
            // Check connection limit
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                if (client_handlers_.size() >= static_cast<size_t>(config_.wifi.max_connections))
                {
                    logger_->warning("Connection limit reached, rejecting client");
                    close(client_socket);
                    return;
                }
            }

            try
            {
                // Create client handler
                auto handler = std::make_unique<WiFiClientHandler>(
                    client_socket, client_addr, config_,
                    routing_service_, device_management_, statistics_service_);

                // Store temporarily with socket address as key
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
                std::string temp_key = std::string(addr_str) + ":" + std::to_string(ntohs(client_addr.sin_port));

                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    client_handlers_[temp_key] = std::move(handler);
                    client_handlers_[temp_key]->start();
                }

                logger_->info("New WiFi client connected",
                              core::LogContext().add("client_address", temp_key));

                // Periodically clean up disconnected clients
                cleanup_disconnected_clients();
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception handling new client",
                               core::LogContext().add("error", e.what()));
                close(client_socket);
                statistics_service_.record_transport_error("wifi");
            }
        }

        void WiFiTransport::cleanup_disconnected_clients()
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);

            auto it = client_handlers_.begin();
            while (it != client_handlers_.end())
            {
                if (!it->second->is_authenticated() && !it->second->get_device_id().empty())
                {
                    // Handler has device ID but is not authenticated - might be disconnected
                    // TODO: This is a simplified check, need more sophisticated detection
                }
                ++it;
            }
        }

        WiFiClientHandler *WiFiTransport::find_client_handler(const std::string &device_id)
        {
            for (auto &[key, handler] : client_handlers_)
            {
                if (handler->get_device_id() == device_id)
                {
                    return handler.get();
                }
            }
            return nullptr;
        }

    } // namespace transports
} // namespace mita