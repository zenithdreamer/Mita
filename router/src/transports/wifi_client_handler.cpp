#include "transports/wifi_client_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "config/mita_config.h"

#include <arpa/inet.h>
#include <cstring>

namespace mita
{
    namespace transports
    {

        // WiFiClientHandler implementation
        WiFiClientHandler::WiFiClientHandler(const std::string &client_ip,
                                             const core::RouterConfig &config,
                                             services::RoutingService &routing_service,
                                             services::DeviceManagementService &device_management,
                                             services::StatisticsService &statistics_service,
                                             std::shared_ptr<services::PacketMonitorService> packet_monitor)
            : client_ip_(client_ip), config_(config), routing_service_(routing_service),
              device_management_(device_management), statistics_service_(statistics_service),
              packet_monitor_(packet_monitor), assigned_address_(0), authenticated_(false),
              running_(false), last_heartbeat_(std::chrono::steady_clock::now()),
              disconnect_time_(std::chrono::steady_clock::time_point::max()),
              logger_(core::get_logger("WiFiClientHandler"))
        {
            // Initialize handshake manager
            handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                config_.router_id, config_.shared_secret);

            logger_->info("WiFi client handler created",
                          core::LogContext().add("client_ip", client_ip_));
        }

        WiFiClientHandler::~WiFiClientHandler()
        {
            stop();
        }

        void WiFiClientHandler::set_send_callback(std::function<bool(const std::string &, const uint8_t *, size_t)> callback)
        {
            send_raw_packet_ = callback;
        }

        void WiFiClientHandler::start(const protocol::ProtocolPacket &initial_hello)
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            // Process the initial HELLO packet immediately
            handle_packet(initial_hello);

            logger_->debug("WiFi client handler started",
                           core::LogContext().add("client_ip", client_ip_));
        }

        void WiFiClientHandler::stop()
        {
            running_ = false;
            cleanup();
            logger_->debug("WiFi client handler stopped",
                           core::LogContext().add("client_ip", client_ip_));
        }

        void WiFiClientHandler::handle_packet(const protocol::ProtocolPacket &packet)
        {
            if (!running_)
            {
                return;
            }

            // Capture inbound packet for monitoring
            if (packet_monitor_)
            {
                packet_monitor_->capture_packet(packet, "inbound", core::TransportType::WIFI);
            }

            // Update heartbeat for any received packet
            update_heartbeat();

            // Handle based on message type
            switch (packet.get_message_type())
            {
            case MessageType::HELLO:
            case MessageType::CHALLENGE:
            case MessageType::AUTH:
            case MessageType::AUTH_ACK:
                handle_handshake_packet(packet);
                break;

            case MessageType::HEARTBEAT:
                handle_heartbeat_packet(packet);
                break;

            default:
                if (authenticated_)
                {
                    handle_data_packet(packet);
                }
                else
                {
                    logger_->warning("Received non-handshake packet before authentication",
                                     core::LogContext().add("client_ip", client_ip_).add("msg_type", static_cast<int>(packet.get_message_type())));
                }
                break;
            }
        }

        bool WiFiClientHandler::send_packet(const protocol::ProtocolPacket &packet)
        {
            logger_->debug("WiFiClientHandler::send_packet called",
                           core::LogContext()
                               .add("client_ip", client_ip_)
                               .add("device_id", device_id_)
                               .add("msg_type", static_cast<int>(packet.get_message_type()))
                               .add("running", running_)
                               .add("has_send_func", send_raw_packet_ != nullptr));

            if (!running_ || !send_raw_packet_)
            {
                logger_->warning("Cannot send packet - handler not ready",
                                 core::LogContext()
                                     .add("client_ip", client_ip_)
                                     .add("running", running_)
                                     .add("has_send_func", send_raw_packet_ != nullptr));
                return false;
            }

            try
            {
                // Capture outbound packet for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "outbound", core::TransportType::WIFI);
                }

                auto packet_data = packet.to_bytes();

                logger_->debug("About to call send_raw_packet_",
                               core::LogContext()
                                   .add("client_ip", client_ip_)
                                   .add("packet_size", packet_data.size()));

                // Send via raw IP
                bool result = send_raw_packet_(client_ip_, packet_data.data(), packet_data.size());

                logger_->debug("send_raw_packet_ returned",
                               core::LogContext()
                                   .add("client_ip", client_ip_)
                                   .add("result", result));

                return result;
            }
            catch (const std::exception &e)
            {
                logger_->error("Exception sending packet",
                               core::LogContext().add("client_ip", client_ip_).add("error", e.what()));
                return false;
            }
        }

        void WiFiClientHandler::handle_handshake_packet(const protocol::ProtocolPacket &packet)
        {
            try
            {
                // Capture inbound handshake packets (HELLO, AUTH)
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "inbound", core::TransportType::WIFI);
                }
                
                if (packet.get_message_type() == MessageType::HELLO)
                {
                    std::string router_id, device_id;
                    std::vector<uint8_t> nonce1;

                    if (protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce1))
                    {
                        if (router_id == config_.router_id)
                        {
                            // Check rate limit to prevent DoS attacks
                            if (!handshake_manager_->check_rate_limit(device_id))
                            {
                                logger_->warning("Rate limit exceeded for handshake - dropping HELLO",
                                                core::LogContext().add("device_id", device_id));
                                return;
                            }
                            
                            device_id_ = device_id;

                            // Store device_id and send CHALLENGE without registering yet
                            // Registration happens after AUTH verification for security
                            logger_->info("Received HELLO from device",
                                          core::LogContext().add("device_id", device_id_));

                            // Create challenge packet
                            auto challenge_packet = handshake_manager_->create_challenge_packet(device_id_, nonce1);
                            if (!challenge_packet)
                            {
                                logger_->warning("Rejected HELLO - nonce reuse or security check failed",
                                               core::LogContext().add("device_id", device_id_));
                                running_ = false;  // Close connection
                                return;
                            }
                            
                            if (send_packet(*challenge_packet))
                            {
                                logger_->info("Sent CHALLENGE to device",
                                              core::LogContext().add("device_id", device_id_));
                            }
                            else
                            {
                                logger_->error("Failed to send CHALLENGE packet",
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
                                       core::LogContext().add("client_ip", client_ip_));
                    }
                }
                else if (packet.get_message_type() == MessageType::AUTH)
                {
                    if (device_id_.empty())
                    {
                        logger_->warning("Received AUTH without HELLO",
                                         core::LogContext().add("client_ip", client_ip_));
                        return;
                    }

                    // Verify authentication packet
                    if (handshake_manager_->verify_auth_packet(device_id_, packet))
                    {
                        // Authentication successful - NOW register the device
                        logger_->info("Device authentication successful",
                                      core::LogContext().add("device_id", device_id_));

                        // Register device in device management (only after auth verification)
                        if (!device_management_.register_device(device_id_, core::TransportType::WIFI))
                        {
                            logger_->error("Failed to register device after authentication",
                                           core::LogContext().add("device_id", device_id_));
                            running_ = false;
                            return;
                        }

                        // Get assigned address from routing service
                        assigned_address_ = routing_service_.get_device_address(device_id_);

                        if (assigned_address_ == 0)
                        {
                            logger_->error("Device registered but no address assigned",
                                           core::LogContext().add("device_id", device_id_));
                            device_management_.remove_device(device_id_);
                            running_ = false;
                            return;
                        }

                        // Create AUTH_ACK packet with assigned address
                        auto auth_ack_packet = handshake_manager_->create_auth_ack_packet(device_id_, assigned_address_);

                        if (auth_ack_packet && send_packet(*auth_ack_packet))
                        {
                            // Mark as authenticated
                            authenticated_ = true;

                            update_heartbeat();

                            // Obtain session crypto for this device if available
                            session_crypto_ = handshake_manager_->get_session_crypto(device_id_);
                            // Remove handshake state as it's no longer needed
                            handshake_manager_->remove_handshake(device_id_);

                            // Set transport fingerprint before authentication
                            device_management_.set_transport_fingerprint(device_id_, client_ip_);

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
                                          core::LogContext()
                                              .add("device_id", device_id_)
                                              .add("assigned_address", assigned_address_)
                                              .add("fingerprint", client_ip_));
                        }
                        else
                        {
                            logger_->error("Failed to send AUTH_ACK packet",
                                           core::LogContext().add("device_id", device_id_));
                            device_management_.remove_device(device_id_);
                            running_ = false;
                        }
                    }
                    else
                    {
                        // Authentication failed - clear handshake state to allow retry
                        logger_->warning("Authentication verification failed, clearing handshake state",
                                         core::LogContext().add("device_id", device_id_));
                        handshake_manager_->remove_handshake(device_id_);
                        running_ = false;
                    }
                }
            } // end try block
            catch (const std::exception &e)
            {
                logger_->error("Exception handling handshake packet",
                               core::LogContext().add("client_ip", client_ip_).add("error", e.what()));
                statistics_service_.record_protocol_error();
            }
        }

        void WiFiClientHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
        {
            if (device_id_.empty())
            {
                return;
            }

            // Forward to device management service with current fingerprint for validation
            device_management_.handle_packet(device_id_, packet, core::TransportType::WIFI, client_ip_);
        }

        void WiFiClientHandler::cleanup()
        {
            // Cleanup is handled by the transport
        }

        void WiFiClientHandler::handle_heartbeat_packet(const protocol::ProtocolPacket &packet)
        {
            update_heartbeat();

            logger_->debug("Heartbeat received",
                           core::LogContext().add("device_id", device_id_).add("client_ip", client_ip_));
        }

        void WiFiClientHandler::update_heartbeat()
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex_);
            last_heartbeat_ = std::chrono::steady_clock::now();
            
            if (!running_)
            {
                logger_->info("Client reconnected via heartbeat",
                              core::LogContext()
                                  .add("device_id", device_id_)
                                  .add("ip", client_ip_));
                running_ = true;
                disconnect_time_ = std::chrono::steady_clock::time_point::max();
            }
        }

        bool WiFiClientHandler::check_heartbeat_timeout()
        {
            if (!authenticated_)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(heartbeat_mutex_);
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_heartbeat_).count();

            if (elapsed > MITA_HEARTBEAT_TIMEOUT_MS && running_)
            {
                logger_->warning("Heartbeat timeout - client appears disconnected",
                                core::LogContext()
                                    .add("device_id", device_id_)
                                    .add("elapsed_ms", elapsed)
                                    .add("timeout_ms", MITA_HEARTBEAT_TIMEOUT_MS));
                running_ = false;
                disconnect_time_ = now;
                return true;
            }

            return false;
        }

        std::chrono::steady_clock::time_point WiFiClientHandler::get_disconnect_time() const
        {
            std::lock_guard<std::mutex> lock(heartbeat_mutex_);
            return disconnect_time_;
        }

        bool WiFiClientHandler::check_for_disconnected() const
        {
            if (running_)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(heartbeat_mutex_);
            auto now = std::chrono::steady_clock::now();
            auto disconnected_duration = std::chrono::duration_cast<std::chrono::seconds>(now - disconnect_time_).count();

            return disconnected_duration >= 30;
        }

    } // namespace transports
} // namespace mita
