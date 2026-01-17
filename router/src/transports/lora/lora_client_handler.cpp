#include "transports/lora/lora_client_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "protocol/protocol.hpp"
#include "config/mita_config.h"

#include <cstring>

namespace mita
{
    namespace transports
    {
        namespace lora
        {

            LoRaClientHandler::LoRaClientHandler(uint8_t lora_address,
                                                 const core::RouterConfig &config,
                                                 services::RoutingService &routing_service,
                                                 services::DeviceManagementService &device_management,
                                                 services::StatisticsService &statistics_service,
                                                 SendPacketCallback send_callback,
                                                 std::shared_ptr<services::PacketMonitorService> packet_monitor)
                : lora_address_(lora_address),
                  authenticated_(false),
                  running_(false),
                  last_heartbeat_time_(std::chrono::steady_clock::now()),
                  disconnect_time_(std::chrono::steady_clock::time_point::max()),
                  config_(config),
                  routing_service_(routing_service),
                  device_management_(device_management),
                  statistics_service_(statistics_service),
                  packet_monitor_(packet_monitor),
                  logger_(core::get_logger("LoRaClientHandler")),
                  send_callback_(send_callback),
                  handshake_manager_(std::make_unique<protocol::HandshakeManager>(config.router_id, config.shared_secret))
            {
                logger_->info("LoRa client handler created",
                              core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
            }

            LoRaClientHandler::~LoRaClientHandler()
            {
                stop();
            }

            void LoRaClientHandler::start(const protocol::ProtocolPacket &initial_hello)
            {
                if (running_.exchange(true))
                {
                    return; 
                }


                handle_packet(initial_hello);

                logger_->debug("LoRa client handler started",
                               core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
            }

            void LoRaClientHandler::stop()
            {
                running_ = false;
                logger_->debug("LoRa client handler stopped",
                               core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
            }

            void LoRaClientHandler::handle_packet(const protocol::ProtocolPacket &packet)
            {

                if (packet.get_message_type() == MessageType::HELLO)
                {

                    logger_->info("Received HELLO - allowing reconnection",
                                  core::LogContext()
                                      .add("lora_addr", static_cast<int>(lora_address_))
                                      .add("was_running", running_));


                    if (!running_)
                    {
                        running_ = true;
                        disconnect_time_ = std::chrono::steady_clock::time_point::max();
                    }

                    last_heartbeat_time_ = std::chrono::steady_clock::now();
                    handle_handshake_packet(packet);
                    return;
                }

                if (!running_)
                {
                    return;
                }


                last_heartbeat_time_ = std::chrono::steady_clock::now();

                // Handle based on message type
                switch (packet.get_message_type())
                {
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
                                         core::LogContext()
                                             .add("lora_addr", static_cast<int>(lora_address_))
                                             .add("msg_type", static_cast<int>(packet.get_message_type())));
                    }
                    break;
                }
            }

            void LoRaClientHandler::handle_handshake_packet(const protocol::ProtocolPacket &packet)
            {
                try
                {

                    if (packet_monitor_)
                    {
                        packet_monitor_->capture_packet(packet, "inbound", core::TransportType::LORA);
                    }

                    if (packet.get_message_type() == MessageType::HELLO)
                    {
                        std::string router_id, device_id;
                        std::vector<uint8_t> nonce1;

                        if (protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce1))
                        {
                            if (router_id == config_.router_id)
                            {
                                device_id_ = device_id;

                                logger_->info("Received HELLO from LoRa device",
                                              core::LogContext()
                                                  .add("device_id", device_id_)
                                                  .add("lora_addr", static_cast<int>(lora_address_)));

                                // Create and send CHALLENGE packet
                                auto challenge_packet = handshake_manager_->create_challenge_packet(device_id_, nonce1);
                                if (!challenge_packet)
                                {
                                    logger_->warning("Rejected HELLO - nonce reuse or security check failed",
                                                   core::LogContext().add("device_id", device_id_));
                                    running_ = false;
                                    return;
                                }

                                if (packet_monitor_)
                                {
                                    packet_monitor_->capture_packet(*challenge_packet, "outbound", core::TransportType::LORA);
                                }

                                if (send_packet(*challenge_packet))
                                {
                                    logger_->info("Sent CHALLENGE to LoRa device",
                                                  core::LogContext()
                                                      .add("device_id", device_id_)
                                                      .add("lora_addr", static_cast<int>(lora_address_)));
                                }
                                else
                                {
                                    logger_->error("Failed to send CHALLENGE packet",
                                                   core::LogContext()
                                                       .add("device_id", device_id_)
                                                       .add("lora_addr", static_cast<int>(lora_address_)));
                                }
                            }
                            else
                            {
                                logger_->warning("Invalid router ID in HELLO packet",
                                                 core::LogContext()
                                                     .add("expected", config_.router_id)
                                                     .add("received", router_id));
                            }
                        }
                        else
                        {
                            logger_->error("Failed to parse HELLO packet",
                                           core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
                        }
                    }
                    else if (packet.get_message_type() == MessageType::AUTH)
                    {
                        if (device_id_.empty())
                        {
                            logger_->warning("Received AUTH without HELLO",
                                             core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
                            return;
                        }

                        if (handshake_manager_->verify_auth_packet(device_id_, packet))
                        {
                            if (!device_management_.register_device(device_id_, core::TransportType::LORA))
                            {
                                logger_->error("Failed to register LoRa device",
                                               core::LogContext().add("device_id", device_id_));
                                running_ = false;
                                return;
                            }

                            // Capture outbound AUTH_ACK for packet monitoring
                            if (packet_monitor_)
                            {
                                packet_monitor_->capture_packet(packet, "outbound", core::TransportType::LORA);
                            }

                            // Send AUTH_ACK
                            if (send_packet(packet))
                            {
                                authenticated_ = true;
                                last_heartbeat_time_ = std::chrono::steady_clock::now();

                                device_management_.set_transport_fingerprint(
                                    device_id_,
                                    "lora_" + std::to_string(lora_address_));

                                //authenticate device
                                device_management_.authenticate_device(device_id_, nullptr);

                                logger_->info("LoRa device authenticated - sent AUTH_ACK",
                                              core::LogContext()
                                                  .add("device_id", device_id_)
                                                  .add("lora_addr", static_cast<int>(lora_address_)));
                            }
                            else
                            {
                                logger_->error("Failed to send AUTH_ACK packet",
                                               core::LogContext().add("device_id", device_id_));
                            }
                        }
                        else
                        {
                            logger_->warning("AUTH verification failed",
                                             core::LogContext()
                                                 .add("device_id", device_id_)
                                                 .add("lora_addr", static_cast<int>(lora_address_)));
                            running_ = false;
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception handling handshake packet",
                                   core::LogContext()
                                       .add("lora_addr", static_cast<int>(lora_address_))
                                       .add("error", e.what()));
                    statistics_service_.record_protocol_error();
                }
            }

            void LoRaClientHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
            {
                if (device_id_.empty())
                {
                    return;
                }

                std::string fingerprint = "lora_" + std::to_string(lora_address_);
                device_management_.handle_packet(device_id_, packet, core::TransportType::LORA, fingerprint);
            }

            void LoRaClientHandler::handle_heartbeat_packet(const protocol::ProtocolPacket &packet)
            {

                last_heartbeat_time_ = std::chrono::steady_clock::now();

                if (!device_id_.empty())
                {
                    std::string fingerprint = "lora_" + std::to_string(lora_address_);
                    device_management_.handle_packet(device_id_, packet, core::TransportType::LORA, fingerprint);
                }

                logger_->debug("Heartbeat received",
                               core::LogContext()
                                   .add("device_id", device_id_)
                                   .add("lora_addr", static_cast<int>(lora_address_)));
            }

            bool LoRaClientHandler::send_packet(const protocol::ProtocolPacket &packet)
            {
                if (!send_callback_)
                {
                    logger_->error("No send callback configured",
                                   core::LogContext().add("lora_addr", static_cast<int>(lora_address_)));
                    return false;   
                }

                return send_callback_(lora_address_, packet);
            }

            bool LoRaClientHandler::check_heartbeat_timeout()
            {
                if (!authenticated_)
                {
                    return false;
                }

                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   now - last_heartbeat_time_)
                                   .count();

                if (elapsed > MITA_HEARTBEAT_TIMEOUT_MS && running_)
                {
                    logger_->warning("Heartbeat timeout - LoRa client appears disconnected",
                                     core::LogContext()
                                         .add("device_id", device_id_)
                                         .add("lora_addr", static_cast<int>(lora_address_))
                                         .add("elapsed_ms", elapsed)
                                         .add("timeout_ms", MITA_HEARTBEAT_TIMEOUT_MS));
                    running_ = false;
                    disconnect_time_ = now;
                    return true;
                }

                return false;
            }

            std::chrono::steady_clock::time_point LoRaClientHandler::get_disconnect_time() const
            {
                return disconnect_time_;
            }

            bool LoRaClientHandler::check_for_disconnected() const
            {
                if (running_)
                {
                    return false;
                }

                auto now = std::chrono::steady_clock::now();
                auto disconnected_duration = std::chrono::duration_cast<std::chrono::seconds>(
                                                 now - disconnect_time_)
                                                 .count();

                return disconnected_duration >= 30;
            }

        } // namespace lora
    }     // namespace transports
} // namespace mita
