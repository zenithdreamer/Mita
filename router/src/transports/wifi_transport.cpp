#include "transports/wifi_transport.hpp"
#include "transports/wifi_client_handler.hpp"
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
#include <vector>

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
            : BaseTransport(config, routing_service, device_management, statistics_service), server_socket_(-1), logger_(core::get_logger("WiFiTransport")), packet_monitor_(packet_monitor)
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

            auto last_cleanup = std::chrono::steady_clock::now();
            const auto cleanup_interval = std::chrono::seconds(5);

            while (running_)
            {

                auto now = std::chrono::steady_clock::now();
                if (now - last_cleanup >= cleanup_interval)
                {
                    cleanup_disconnected_clients();
                    last_cleanup = now;
                }

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
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
            // Periodically clean up disconnected clients
            cleanup_disconnected_clients();

            //read hello packet to get device_id
            protocol::ProtocolPacket hello_packet;
            if (!WiFiClientHandler::receive_packet_from_socket(client_socket, hello_packet, 5000,logger_))
            {
                logger_->warning("Failed to receive HELLO packet, closing connection");
                close(client_socket);
                return;
            }

            std::string router_id, device_id;
            std::vector<uint8_t> nonce1;
            if (!protocol::utils::parse_hello_packet(hello_packet, router_id, device_id, nonce1))
            {
                logger_->warning("Failed to parse HELLO packet, closing connection");
                close(client_socket);
                return;
            }


            {
                std::lock_guard<std::mutex> lock(clients_mutex_);

                auto it = client_handlers_.find(device_id);
                if (it != client_handlers_.end())
                {
                    // Handler exists - this is a reconnection
                    logger_->debug("Device reconnecting, reusing handler",
                                  core::LogContext().add("device_id", device_id));

                    it->second->reconnect(client_socket, client_addr, hello_packet);
                    return;
                }

                // Check connection limit
                if (client_handlers_.size() >= static_cast<size_t>(config_.wifi.max_connections))
                {
                    logger_->warning("Connection limit reached, rejecting client",
                                     core::LogContext().add("device_id", device_id));
                    close(client_socket);
                    return;
                }
            }

            // Create new handler for this device
            try
            {
                auto handler = std::make_unique<WiFiClientHandler>(
                    client_socket, client_addr, config_,
                    routing_service_, device_management_, statistics_service_, packet_monitor_);

                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    client_handlers_[device_id] = std::move(handler);
                    client_handlers_[device_id]->start(hello_packet);
                }

                logger_->info("New WiFi client connected",
                              core::LogContext().add("device_id", device_id));
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception handling new client",
                               core::LogContext().add("device_id", device_id).add("error", e.what()));
                close(client_socket);
                statistics_service_.record_transport_error("wifi");
            }
        }
        void WiFiTransport::cleanup_disconnected_clients()
        {

            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
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
                std::lock_guard<std::mutex> lock(clients_mutex_);

                int cleaned = 0;
                auto it = client_handlers_.begin();
                while (it != client_handlers_.end())
                {
                    if (it->second && it->second->check_for_disconnected())
                    {
                        std::string device_id = it->first;

                        logger_->info("Removing disconnected client",
                                       core::LogContext().add("device_id", device_id));

                        if (!device_id.empty())
                        {
                            device_management_.remove_device(device_id);
                        }


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
                    logger_->info("Clean up disconnected client",
                                   core::LogContext().add("cleaned_count", cleaned).add("remaining", client_handlers_.size()));
                }
            }

            handlers_to_cleanup.clear();
        }

        std::vector<WiFiClientHandler*> WiFiTransport::get_all_client_handlers() const
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
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

        //map key is now device_id
        WiFiClientHandler *WiFiTransport::find_client_handler(const std::string &device_id)
        {
            
            auto it = client_handlers_.find(device_id);
            if (it != client_handlers_.end())
            {
                return it->second.get();
            }
            return nullptr;
        }

    } // namespace transports
} // namespace mita