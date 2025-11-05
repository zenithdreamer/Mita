#include "transports/ble/ble_device_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/packet_monitor_service.hpp"
#include "config/mita_config.h"

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            BLEDeviceHandler::BLEDeviceHandler(
                IBLEBackend *backend,
                const std::string &device_address,
                const core::RouterConfig &config,
                services::RoutingService &routing_service,
                services::DeviceManagementService &device_management,
                services::StatisticsService &statistics_service,
                std::shared_ptr<services::PacketMonitorService> packet_monitor)
                : config_(config),
                  routing_service_(routing_service),
                  device_management_(device_management),
                  statistics_service_(statistics_service),
                  backend_(backend),
                  device_address_(device_address),
                  assigned_address_(0),
                  connected_(false),
                  authenticated_(false),
                  last_heartbeat_(std::chrono::steady_clock::now()),
                  disconnect_time_(std::chrono::steady_clock::time_point::max()),
                  logger_(core::get_logger("BLEDeviceHandler")),
                  packet_monitor_(packet_monitor)
            {
                // Initialize handshake manager
                handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                    config_.router_id, config_.shared_secret);

                logger_->debug("Device handler created",
                              core::LogContext{}.add("address", device_address_));
            }

            BLEDeviceHandler::~BLEDeviceHandler()
            {
                disconnect();
            }

            bool BLEDeviceHandler::connect()
            {
                logger_->info("Device handler connecting",
                             core::LogContext{}.add("address", device_address_));

                connected_ = true;
                                update_heartbeat();

                return true;
            }

            bool BLEDeviceHandler::reconnect()
            {
                logger_->info("Device handler reconnecting",
                             core::LogContext{}
                                 .add("address", device_address_)
                                 .add("device_id", device_id_)
                                 .add("was_connected", connected_.load()));


                connected_ = true;
                update_heartbeat();

                // authen again
                authenticated_ = false;
                session_crypto_.reset();

                handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                    config_.router_id, config_.shared_secret);

                logger_->info("Device handler reconnected - waiting for handshake",
                             core::LogContext{}
                                 .add("address", device_address_)
                                 .add("device_id", device_id_));


                return true;
            }

            void BLEDeviceHandler::disconnect()
            {
                if (!connected_)
                {
                    return;
                }

                logger_->info("Device handler disconnecting",
                             core::LogContext{}.add("address", device_address_));

                connected_ = false;
                authenticated_ = false;


                if (!device_id_.empty())
                {
                    device_management_.notify_device_disconnected(device_id_);
                }
            }

            bool BLEDeviceHandler::send_packet(const protocol::ProtocolPacket &packet)
            {
                if (!connected_)
                {
                    logger_->warning("Cannot send packet - device not connected",
                                    core::LogContext{}.add("address", device_address_));
                    return false;
                }

                try
                {
                    auto outgoing_packet = packet;

                    //encrpte
                    if (packet.is_encrypted() && session_crypto_)
                    {
                        std::lock_guard<std::mutex> lock(crypto_mutex_);
                        auto payload = packet.get_payload();
                        auto encrypted = session_crypto_->encrypt(payload);
                        outgoing_packet.set_payload(encrypted);
                        outgoing_packet.set_encrypted(true);
                    }

                    // Serialize packet to bytes
                    auto packet_data = outgoing_packet.to_bytes();

                    logger_->debug("Sending BLE packet",
                                  core::LogContext{}
                                      .add("device_address", device_address_)
                                      .add("packet_type", static_cast<int>(packet.get_message_type()))
                                      .add("data_size", packet_data.size())
                                      .add("encrypted", outgoing_packet.is_encrypted()));

                    //use backend to send
                    bool success = backend_->write_characteristic(
                        device_address_,
                        config_.ble.service_uuid,
                        config_.ble.characteristic_uuid,
                        packet_data);

                    if (success)
                    {
                        logger_->debug("BLE packet sent successfully",
                                      core::LogContext{}.add("device_address", device_address_));
                        
                        // Capture outbound packet
                        if (packet_monitor_)
                        {
                            packet_monitor_->capture_packet(outgoing_packet, "outbound", core::TransportType::BLE);
                        }
                    }
                    else
                    {
                        logger_->warning("Failed to send BLE packet",
                                        core::LogContext{}.add("device_address", device_address_));
                    }

                    return success;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error sending BLE packet",
                                  core::LogContext{}.add("error", e.what()));
                    return false;
                }
            }

            void BLEDeviceHandler::process_notification(const std::vector<uint8_t> &data)
            {
                try
                {
                    logger_->debug("Processing notification",
                                  core::LogContext{}
                                      .add("address", device_address_)
                                      .add("size", data.size()));


                    auto parsed_packet = protocol::ProtocolPacket::from_bytes(data);
                    if (!parsed_packet)
                    {
                        logger_->warning("Failed to parse BLE notification as protocol packet",
                                        core::LogContext{}
                                            .add("device_id", device_id_)
                                            .add("data_size", data.size()));
                        return;
                    }

                    logger_->debug("Parsed protocol packet",
                                  core::LogContext{}
                                      .add("device_id", device_id_)
                                      .add("packet_type", static_cast<int>(parsed_packet->get_message_type()))
                                      .add("source_addr", parsed_packet->get_source_addr())
                                      .add("dest_addr", parsed_packet->get_dest_addr())
                                      .add("encrypted", parsed_packet->is_encrypted()));

                    // Capture inbound packet
                    if (packet_monitor_)
                    {
                        packet_monitor_->capture_packet(*parsed_packet, "inbound", core::TransportType::BLE);
                    }


                    if (parsed_packet->get_message_type() == MessageType::HELLO ||
                        parsed_packet->get_message_type() == MessageType::CHALLENGE ||
                        parsed_packet->get_message_type() == MessageType::AUTH ||
                        parsed_packet->get_message_type() == MessageType::AUTH_ACK)
                    {
                        handle_handshake_packet(*parsed_packet);
                    }
                    else if (parsed_packet->get_message_type() == MessageType::DATA)
                    {
                        handle_data_packet(*parsed_packet);
                    }
                    else
                    {
                        logger_->warning("Unknown packet type received",
                                        core::LogContext{}
                                            .add("device_id", device_id_)
                                            .add("packet_type", static_cast<int>(parsed_packet->get_message_type())));
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error handling BLE notification",
                                  core::LogContext{}
                                      .add("device_id", device_id_)
                                      .add("error", e.what()));
                }
            }

            void BLEDeviceHandler::handle_handshake_packet(const protocol::ProtocolPacket &packet)
            {
                try
                {
                    logger_->debug("Handling handshake packet",
                                  core::LogContext{}
                                      .add("address", device_address_)
                                      .add("type", static_cast<int>(packet.get_message_type())));

                    if (packet.get_message_type() == MessageType::HELLO)
                    {
                        // Parse HELLO packet
                        std::string router_id, device_id;
                        std::vector<uint8_t> nonce;
                        if (protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce))
                        {

                            if (router_id != config_.router_id)
                            {
                                logger_->warning("Wrong router ID from device",
                                                core::LogContext{}.add("router_id", router_id));
                                return;
                            }

                            device_id_ = device_id;
                            logger_->info("Received HELLO from BLE device",
                                         core::LogContext{}.add("device_id", device_id_));

                            // Store device_id and send CHALLENGE without registering yet
                            // Registration happens after AUTH verification for security

                            // Create and send CHALLENGE
                            auto challenge_packet = handshake_manager_->create_challenge_packet(device_id_, nonce);
                            send_packet(*challenge_packet);

                            logger_->info("Sent CHALLENGE to BLE device",
                                         core::LogContext{}.add("device_id", device_id_));
                        }
                    }
                    else if (packet.get_message_type() == MessageType::AUTH)
                    {
                        logger_->info("Received AUTH from BLE device",
                                     core::LogContext{}.add("device_id", device_id_));

                        if (device_id_.empty())
                        {
                            logger_->warning("Received AUTH without HELLO");
                            return;
                        }

                        // Verify authentication - only register after successful verification
                        if (handshake_manager_->verify_auth_packet(device_id_, packet))
                        {
                            // Authentication successful - NOW register the device
                            if (!device_management_.register_device(device_id_, core::TransportType::BLE))
                            {
                                logger_->warning("Failed to register BLE device after authentication",
                                                core::LogContext{}.add("device_id", device_id_));
                                return;
                            }

                            // Assign address
                            assigned_address_ = routing_service_.add_device(
                                device_id_, core::TransportType::BLE, this);

                            if (assigned_address_ == 0)
                            {
                                logger_->error("Failed to assign address to BLE device",
                                              core::LogContext{}.add("device_id", device_id_));
                                device_management_.remove_device(device_id_);
                                return;
                            }

                            // Create AUTH_ACK before completing handshake
                            auto auth_ack_packet = handshake_manager_->create_auth_ack_packet(
                                device_id_, assigned_address_);

                            // Complete handshake and get session crypto
                            session_crypto_ = handshake_manager_->get_session_crypto(device_id_);
                            
                            // Remove handshake state as it's no longer needed
                            handshake_manager_->remove_handshake(device_id_);

                            // Authenticate device in management service
                            if (session_crypto_)
                            {
                                device_management_.authenticate_device(device_id_, session_crypto_);
                            }
                            else
                            {
                                device_management_.authenticate_device(device_id_, nullptr);
                            }

                            // send auth ack
                            send_packet(*auth_ack_packet);


                            authenticated_ = true;

                            device_management_.notify_device_connected(device_id_);

                            logger_->info("BLE device authenticated",
                                         core::LogContext{}
                                             .add("device_id", device_id_)
                                             .add("address", "0x" + std::to_string(assigned_address_)));
                        }
                        else
                        {

                            logger_->warning("Authentication failed for BLE device",
                                            core::LogContext{}.add("device_id", device_id_));
                            statistics_service_.record_handshake_failed();
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error handling handshake packet",
                                  core::LogContext{}.add("error", e.what()));
                    statistics_service_.record_handshake_failed();
                }
            }


            void BLEDeviceHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
            {
                try
                {
                    logger_->debug("Handling data packet",
                                  core::LogContext{}
                                      .add("address", device_address_)
                                      .add("size", packet.get_payload().size()));

                    auto data_packet = packet;

                    // decrypt if need
                    if (data_packet.is_encrypted())
                    {
                        if (session_crypto_)
                        {
                            std::lock_guard<std::mutex> lock(crypto_mutex_);
                            auto payload = data_packet.get_payload();
                            auto decrypted = session_crypto_->decrypt(payload);
                            data_packet.set_payload(decrypted);
                            data_packet.set_encrypted(false); // set as decrypted
                        }
                        else
                        {
                            logger_->warning("Received encrypted packet but no session crypto available",
                                            core::LogContext{}.add("device_id", device_id_));
                            statistics_service_.record_packet_dropped();
                            return;
                        }
                    }

                    // forward to device management for processing
                    device_management_.handle_packet(device_id_, data_packet, core::TransportType::BLE);
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error handling data packet",
                                  core::LogContext{}.add("error", e.what()));
                    statistics_service_.record_packet_dropped();
                }
            }

            void BLEDeviceHandler::handle_heartbeat_packet(const protocol::ProtocolPacket &packet)
            {
                update_heartbeat();

                logger_->debug("BLE heartbeat received",
                              core::LogContext{}.add("device_id", device_id_).add("address", device_address_));
            }

            void BLEDeviceHandler::update_heartbeat()
            {
                std::lock_guard<std::mutex> lock(heartbeat_mutex_);
                last_heartbeat_ = std::chrono::steady_clock::now();

                if (!connected_)
                {
                    logger_->info("Device reconnected via heartbeat",
                                 core::LogContext{}.add("device_id", device_id_).add("address", device_address_));
                    connected_ = true;
                    disconnect_time_ = std::chrono::steady_clock::time_point::max();
                }
            }

            void BLEDeviceHandler::check_heartbeat_timeout()
            {
                if (!authenticated_)
                {
                    return;
                }

                std::lock_guard<std::mutex> lock(heartbeat_mutex_);
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_heartbeat_).count();

                // heartbeat time out 30 sec
                if (elapsed > MITA_HEARTBEAT_TIMEOUT_MS && connected_)
                {
                    logger_->warning("BLE heartbeat timeout - marking device as disconnected",
                                    core::LogContext{}
                                        .add("device_id", device_id_)
                                        .add("address", device_address_)
                                        .add("elapsed_ms", elapsed)
                                        .add("timeout_ms", MITA_HEARTBEAT_TIMEOUT_MS));

                    connected_ = false;
                    disconnect_time_ = now;
                }
            }

            std::chrono::steady_clock::time_point BLEDeviceHandler::get_disconnect_time() const
            {
                std::lock_guard<std::mutex> lock(heartbeat_mutex_);
                return disconnect_time_;
            }

            bool BLEDeviceHandler::check_for_disconnected() const
            {
                if (connected_)
                {
                    return false;
                }

                std::lock_guard<std::mutex> lock(heartbeat_mutex_);
                auto now = std::chrono::steady_clock::now();
                auto disconnected_duration = std::chrono::duration_cast<std::chrono::seconds>(now - disconnect_time_).count();

                // delete if disconnected for more than 30 seconds
                return disconnected_duration >= 30;
            }


        } // namespace ble
    }     // namespace transports
} // namespace mita
