#include "transports/ble/ble_transport.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "protocol/protocol.hpp"
#include <cstring>
#include <climits>
#include <thread>
#include <chrono>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            // ========== CoCClientHandler Implementation ==========

            CoCClientHandler::CoCClientHandler(
                int client_fd,
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
                  client_fd_(client_fd),
                  device_address_(device_address),
                  assigned_address_(0),
                  connected_(true),
                  authenticated_(false),
                  packet_monitor_(packet_monitor),
                  logger_(core::get_logger("CoCClientHandler"))
            {
                // Initialize handshake manager
                handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                    config_.router_id,
                    config_.shared_secret);

                logger_->info("Client handler created",
                              core::LogContext()
                                  .add("client_fd", client_fd)
                                  .add("device_addr", device_address));
            }

            CoCClientHandler::~CoCClientHandler()
            {
                disconnect();
            }

            void CoCClientHandler::disconnect()
            {
                if (connected_)
                {
                    connected_ = false;
                    logger_->info("Client disconnected",
                                  core::LogContext()
                                      .add("device_id", device_id_)
                                      .add("device_addr", device_address_));
                }
            }

            bool CoCClientHandler::send_packet(const protocol::ProtocolPacket &packet)
            {
                if (!connected_)
                {
                    logger_->warning("Cannot send packet - not connected");
                    return false;
                }

                try
                {
                    // Capture outbound packet for monitoring
                    if (packet_monitor_)
                    {
                        packet_monitor_->capture_packet(packet, "outbound", core::TransportType::BLE);
                    }

                    std::vector<uint8_t> serialized = packet.to_bytes();

                    // Send via L2CAP CoC socket
                    ssize_t sent = send(client_fd_, serialized.data(), serialized.size(), 0);
                    if (sent < 0)
                    {
                        logger_->error("Failed to send packet",
                                       core::LogContext()
                                           .add("error", std::string(strerror(errno))));
                        return false;
                    }

                    logger_->debug("Sent packet",
                                   core::LogContext()
                                       .add("bytes", static_cast<int>(sent))
                                       .add("type", static_cast<int>(packet.get_message_type())));
                    return true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception sending packet",
                                   core::LogContext().add("error", e.what()));
                    return false;
                }
            }

            void CoCClientHandler::handle_received_data(const uint8_t *data, size_t length)
            {
                // Add to receive buffer
                receive_buffer_.insert(receive_buffer_.end(), data, data + length);

                // Try to parse packets from buffer
                while (receive_buffer_.size() >= protocol::ProtocolPacket::PACKET_HEADER_SIZE)
                {
                    auto packet = protocol::ProtocolPacket::from_bytes(receive_buffer_.data(), receive_buffer_.size());

                    if (packet)
                    {
                        size_t packet_size = protocol::ProtocolPacket::PACKET_HEADER_SIZE + packet->get_payload().size();

                        // Remove consumed bytes
                        receive_buffer_.erase(receive_buffer_.begin(),
                                              receive_buffer_.begin() + packet_size);

                        // Handle the packet
                        handle_packet(*packet);
                    }
                    else
                    {
                        // Not enough data or invalid packet
                        break;
                    }
                }

                // Prevent buffer from growing too large
                if (receive_buffer_.size() > 4096)
                {
                    logger_->warning("Receive buffer too large, clearing",
                                     core::LogContext().add("size", receive_buffer_.size()));
                    receive_buffer_.clear();
                }
            }

            void CoCClientHandler::handle_packet(const protocol::ProtocolPacket &packet)
            {
                // Capture inbound packet for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "inbound", core::TransportType::BLE);
                }

                if (packet.get_message_type() == MessageType::HELLO ||
                    packet.get_message_type() == MessageType::AUTH)
                {
                    handle_handshake_packet(packet);
                }
                else if (authenticated_)
                {
                    handle_data_packet(packet);
                }
                else
                {
                    logger_->warning("Received packet before authentication - sending ERROR response",
                                     core::LogContext()
                                         .add("type", static_cast<int>(packet.get_message_type())));
                    
                    // Send ERROR packet to notify client to re-authenticate
                    // Error code 0x0B = "Not authenticated" (client should reconnect)
                    std::vector<uint8_t> error_payload = {0x0B, 0x00, 0x00}; // error_code, seq_high, seq_low
                    protocol::ProtocolPacket error_packet(
                        MessageType::ERROR,
                        ROUTER_ADDRESS,
                        packet.get_source_addr(),
                        error_payload);
                    send_packet(error_packet);
                }
            }

            void CoCClientHandler::handle_handshake_packet(const protocol::ProtocolPacket &packet)
            {
                try
                {
                    // Process handshake based on message type
                    if (packet.get_message_type() == MessageType::HELLO)
                    {
                        std::string device_id;
                        std::vector<uint8_t> nonce1;
                        
                        if (handshake_manager_->process_hello_packet(packet, device_id, nonce1))
                        {
                            device_id_ = device_id;

                            auto challenge = handshake_manager_->create_challenge_packet(device_id, nonce1);
                            if (challenge)
                            {
                                send_packet(*challenge);
                            }
                            else
                            {
                                logger_->warning("Failed to create challenge packet",
                                               core::LogContext().add("device_id", device_id));
                            }
                        }
                    }
                    else if (packet.get_message_type() == MessageType::AUTH)
                    {
                        if (handshake_manager_->verify_auth_packet(device_id_, packet))
                        {
                            // Handshake complete
                            session_crypto_ = handshake_manager_->get_session_crypto(device_id_);

                            logger_->info("Client authenticated successfully",
                                          core::LogContext()
                                              .add("device_id", device_id_));

                            // Register device
                            if (!device_management_.register_device(device_id_, core::TransportType::BLE))
                            {
                                logger_->error("Failed to register device after authentication",
                                               core::LogContext().add("device_id", device_id_));
                                return;
                            }

                            // Get assigned address from routing service
                            uint16_t assigned_address = routing_service_.get_device_address(device_id_);

                            if (assigned_address == 0)
                            {
                                logger_->error("Device registered but no address assigned",
                                               core::LogContext().add("device_id", device_id_));
                                device_management_.remove_device(device_id_);
                                return;
                            }
                            
                            // Authenticate device with session crypto
                            device_management_.authenticate_device(device_id_, session_crypto_);

                            // Send AUTH_ACK with correct assigned address
                            auto ack = handshake_manager_->create_auth_ack_packet(device_id_, assigned_address);
                            if (ack && send_packet(*ack))
                            {
                                authenticated_ = true;
                                
                                // Remove handshake state as it's no longer needed
                                handshake_manager_->remove_handshake(device_id_);
                                
                                logger_->info("AUTH_ACK sent successfully",
                                              core::LogContext()
                                                  .add("device_id", device_id_)
                                                  .add("assigned_address", assigned_address));
                            }
                            else
                            {
                                logger_->error("Failed to send AUTH_ACK",
                                               core::LogContext().add("device_id", device_id_));
                            }
                        }
                        else
                        {
                            logger_->warning("AUTH verification failed, clearing handshake state",
                                           core::LogContext().add("device_id", device_id_));
                            
                            // Clear failed handshake to allow retry
                            handshake_manager_->remove_handshake(device_id_);
                            
                            // Optionally send error response (client will timeout and retry)
                            // For now, client timeout mechanism handles this
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error processing handshake",
                                   core::LogContext().add("error", e.what()));
                }
            }

            void CoCClientHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
            {
                try
                {
                    // Decrypt if encrypted
                    protocol::ProtocolPacket decrypted_packet = packet;
                    if (packet.is_encrypted())
                    {
                        if (!session_crypto_)
                        {
                            logger_->error("Received encrypted packet but no session crypto");
                            return;
                        }

                        // Build AAD to match ESP32's encryption
                        // AAD format: source_addr (2 bytes) || dest_addr (2 bytes) || sequence_number (2 bytes)
                        std::vector<uint8_t> aad(6);
                        uint16_t source = packet.get_source_addr();
                        uint16_t dest = packet.get_dest_addr();
                        uint16_t seq = packet.get_sequence_number();
                        
                        aad[0] = (source >> 8) & 0xFF;
                        aad[1] = source & 0xFF;
                        aad[2] = (dest >> 8) & 0xFF;
                        aad[3] = dest & 0xFF;
                        aad[4] = (seq >> 8) & 0xFF;
                        aad[5] = seq & 0xFF;

                        // Format AAD as hex string for logging
                        char aad_hex[32];
                        snprintf(aad_hex, sizeof(aad_hex), "%02X%02X%02X%02X%02X%02X",
                                 aad[0], aad[1], aad[2], aad[3], aad[4], aad[5]);

                        logger_->debug("Decrypting with AAD",
                                       core::LogContext()
                                           .add("source", source)
                                           .add("dest", dest)
                                           .add("seq", seq)
                                           .add("aad_hex", std::string(aad_hex)));

                        std::vector<uint8_t> decrypted_data = session_crypto_->decrypt_gcm(packet.get_payload(), aad);
                        if (decrypted_data.empty())
                        {
                            logger_->error("Failed to decrypt packet");
                            return;
                        }
                        decrypted_packet.set_payload(decrypted_data);
                        // Mark packet as no longer encrypted after decryption
                        decrypted_packet.set_encrypted(false);
                    }

                    // Update statistics
                    statistics_service_.record_packet_received(decrypted_packet.get_payload().size());

                    // Forward to device management service for processing (including ACK generation)
                    device_management_.handle_packet(device_id_, decrypted_packet, core::TransportType::BLE, device_address_);

                    logger_->debug("Processed data packet",
                                   core::LogContext()
                                       .add("device_id", device_id_)
                                       .add("payload_size", decrypted_packet.get_payload().size()));
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error processing data packet",
                                   core::LogContext().add("error", e.what()));
                }
            }

            // ========== BLETransport Implementation ==========

            BLETransport::BLETransport(
                const core::RouterConfig &config,
                services::RoutingService &routing_service,
                services::DeviceManagementService &device_management,
                services::StatisticsService &statistics_service,
                std::shared_ptr<services::PacketMonitorService> packet_monitor)
                : BaseTransport(config, routing_service, device_management, statistics_service),
                  packet_monitor_(packet_monitor),
                  logger_(core::get_logger("BLETransport_L2CAP")),
                  running_(false)
            {
                logger_->info("BLE L2CAP CoC Transport created");
            }

            BLETransport::~BLETransport()
            {
                stop();
                logger_->info("BLE L2CAP CoC Transport destroyed");
            }

            bool BLETransport::start()
            {
                if (running_.load())
                {
                    logger_->warning("BLE transport already running");
                    return true;
                }

                logger_->info("Starting BLE L2CAP CoC transport...");

                // Enable Bluetooth adapter
                if (!enable_bluetooth_adapter())
                {
                    logger_->error("Failed to enable Bluetooth adapter");
                    return false;
                }

                // Create L2CAP CoC server
                l2cap_server_ = std::make_unique<BLEL2CAPServer>();

                // Set callbacks
                l2cap_server_->set_client_connected_callback(
                    [this](int fd, const std::string &addr)
                    { this->on_client_connected(fd, addr); });

                l2cap_server_->set_client_disconnected_callback(
                    [this](int fd, const std::string &addr)
                    { this->on_client_disconnected(fd, addr); });

                l2cap_server_->set_data_received_callback(
                    [this](int fd, const std::string &addr, const uint8_t *data, size_t len)
                    { this->on_data_received(fd, addr, data, len); });

                // Start the server
                if (!l2cap_server_->start())
                {
                    logger_->error("Failed to start L2CAP CoC server");
                    disable_bluetooth_adapter();
                    return false;
                }

                running_.store(true);

                // Register message handler
                device_management_.register_message_handler(
                    "ble",
                    [this](const std::string &device_id, const protocol::ProtocolPacket &packet)
                    { send_packet(device_id, packet); });

                // Start advertising watchdog thread
                advertising_watchdog_thread_ = std::thread(&BLETransport::advertising_watchdog_loop, this);

                logger_->info("BLE L2CAP CoC transport started successfully");
                return true;
            }

            void BLETransport::stop()
            {
                if (!running_.load())
                {
                    return;
                }

                logger_->info("Stopping BLE L2CAP CoC transport...");
                running_.store(false);

                // Stop advertising watchdog
                if (advertising_watchdog_thread_.joinable())
                {
                    advertising_watchdog_thread_.join();
                }

                // Stop L2CAP server
                if (l2cap_server_)
                {
                    l2cap_server_->stop();
                    l2cap_server_.reset();
                }

                // Clean up client handlers
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    client_handlers_.clear();
                }

                {
                    std::lock_guard<std::mutex> lock(device_map_mutex_);
                    device_id_to_fd_.clear();
                }

                // Disable Bluetooth adapter
                disable_bluetooth_adapter();

                logger_->info("BLE L2CAP CoC transport stopped");
            }

            bool BLETransport::send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
            {
                std::lock_guard<std::mutex> lock(device_map_mutex_);

                auto it = device_id_to_fd_.find(device_id);
                if (it == device_id_to_fd_.end())
                {
                    logger_->warning("Device not found",
                                     core::LogContext().add("device_id", device_id));
                    return false;
                }

                int client_fd = it->second;

                std::lock_guard<std::mutex> handler_lock(handlers_mutex_);
                auto handler_it = client_handlers_.find(client_fd);
                if (handler_it == client_handlers_.end())
                {
                    logger_->error("Handler not found for device",
                                   core::LogContext().add("device_id", device_id));
                    return false;
                }

                return handler_it->second->send_packet(packet);
            }

            int BLETransport::broadcast_packet(const protocol::ProtocolPacket &packet)
            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);
                int count = 0;

                for (auto &pair : client_handlers_)
                {
                    if (pair.second->is_authenticated())
                    {
                        if (pair.second->send_packet(packet))
                        {
                            count++;
                        }
                    }
                }

                logger_->debug("Broadcast packet",
                               core::LogContext().add("count", count));
                return count;
            }

            std::string BLETransport::get_connection_info() const
            {
                std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(handlers_mutex_));
                return "BLE L2CAP CoC: " + std::to_string(client_handlers_.size()) + " client(s) connected";
            }

            std::vector<std::pair<std::string, std::string>> BLETransport::get_all_device_handlers() const
            {
                std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(handlers_mutex_));
                std::vector<std::pair<std::string, std::string>> result;

                for (const auto &pair : client_handlers_)
                {
                    if (pair.second->is_authenticated())
                    {
                        result.emplace_back(pair.second->get_device_id(), pair.second->get_device_address());
                    }
                }

                return result;
            }

            void BLETransport::on_client_connected(int client_fd, const std::string &device_addr)
            {
                logger_->info("New client connected",
                              core::LogContext()
                                  .add("client_fd", client_fd)
                                  .add("device_addr", device_addr));

                try
                {
                    auto handler = std::make_unique<CoCClientHandler>(
                        client_fd,
                        device_addr,
                        config_,
                        routing_service_,
                        device_management_,
                        statistics_service_,
                        packet_monitor_);

                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    client_handlers_[client_fd] = std::move(handler);
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error creating client handler",
                                   core::LogContext().add("error", e.what()));
                }
            }

            void BLETransport::on_client_disconnected(int client_fd, const std::string &device_addr)
            {
                logger_->info("Client disconnected",
                              core::LogContext()
                                  .add("client_fd", client_fd)
                                  .add("device_addr", device_addr));

                std::string device_id;

                // Find and remove handler
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    auto it = client_handlers_.find(client_fd);
                    if (it != client_handlers_.end())
                    {
                        device_id = it->second->get_device_id();
                        client_handlers_.erase(it);
                    }
                }

                // Remove from device map
                if (!device_id.empty())
                {
                    std::lock_guard<std::mutex> lock(device_map_mutex_);
                    device_id_to_fd_.erase(device_id);

                    // Device will be unregistered by device management service automatically
                }

                // Ensure advertising stays on after disconnection
                ensure_advertising();
            }

            void BLETransport::on_data_received(int client_fd, const std::string &device_addr,
                                                const uint8_t *data, size_t length)
            {
                // Get handler pointer and update mapping without holding lock during data processing
                CoCClientHandler* handler = nullptr;
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    auto it = client_handlers_.find(client_fd);

                    if (it != client_handlers_.end())
                    {
                        handler = it->second.get();
                        
                        // Update device_id mapping BEFORE processing data so ACKs can be sent back
                        if (handler->is_authenticated())
                        {
                            std::string device_id = handler->get_device_id();
                            std::lock_guard<std::mutex> map_lock(device_map_mutex_);
                            device_id_to_fd_[device_id] = client_fd;
                        }
                    }
                }

                // Process data without holding handlers_mutex_ to avoid deadlock
                if (handler)
                {
                    handler->handle_received_data(data, length);
                }
                else
                {
                    logger_->warning("Received data for unknown client",
                                     core::LogContext().add("client_fd", client_fd));
                }
            }

            bool run_cmd(const std::string &cmd, std::shared_ptr<core::Logger> logger, int ok_min = 0)
            {
                logger->debug("exec", core::LogContext().add("cmd", cmd));
                int rc = system(cmd.c_str());
                if (rc < ok_min)
                {
                    logger->warning("non-zero exit", core::LogContext().add("rc", rc).add("cmd", cmd));
                }
                return rc == 0;
            }

            bool BLETransport::enable_bluetooth_adapter()
            {
                logger_->info("Enabling and configuring Bluetooth adapter (LE CoC, no PIN)…");

                // Make sure bluetoothd is up
                run_cmd("sudo systemctl start bluetooth", logger_);

                // Unblock radio, give the kernel a sec
                run_cmd("rfkill unblock bluetooth", logger_);
                std::this_thread::sleep_for(std::chrono::milliseconds(250));

                // Clean slate: power off first
                run_cmd("sudo btmgmt -i 0 power off", logger_);

                // LE only; no BR/EDR = no legacy PIN dance
                run_cmd("sudo btmgmt -i 0 bredr off", logger_);
                run_cmd("sudo btmgmt -i 0 le on", logger_);

                // Allow inbound links w/o bonding; keep pairable so Just Works can happen
                // io-cap 3 = NoInputNoOutput (forces Just Works for SMP)
                run_cmd("sudo btmgmt -i 0 connectable on", logger_);
                run_cmd("sudo btmgmt -i 0 bondable off", logger_);
                run_cmd("sudo btmgmt -i 0 io-cap 3", logger_); // NoInputNoOutput

                // Name before power on
                run_cmd("sudo btmgmt -i 0 name '" + config_.ble.device_name + "'", logger_);

                // Power on
                if (!run_cmd("sudo btmgmt -i 0 power on", logger_))
                {
                    logger_->error("btmgmt power on failed");
                    return false;
                }

                // Enable controller advertising feature
                run_cmd("sudo btmgmt -i 0 advertising on", logger_);

                // Create/refresh a persistent advertising instance.
                // -d : connectable + discoverable
                // -p 200: interval ~200ms
                // name + flags 0x06 (LE General Disc. + BR/EDR not supported)
                // If an instance already exists, BlueZ returns non-zero; we'll ignore and continue.
                run_cmd("sudo btmgmt -i 0 add-adv -d -p 200 "
                        "flags 0x06 name '" + config_.ble.device_name + "'",
                        logger_, /*ok_min*/ INT_MIN);

                // As a belt-and-suspenders, also set an agent that accepts Just Works w/out prompts.
                // This is harmless on headless devices and ensures “no PIN”.
                run_cmd(
                    "bash -lc \"bluetoothctl --timeout 3 <<'EOF'\n"
                    "agent NoInputNoOutput\n"
                    "default-agent\n"
                    "pairable on\n"
                    "discoverable on\n"
                    "system-alias " + config_.ble.device_name + "\n"
                    "EOF\"",
                    logger_);

                logger_->info("Bluetooth adapter enabled for LE CoC. Advertising should now be active.");
                return true;
            }

            void BLETransport::disable_bluetooth_adapter()
            {
                logger_->info("Disabling Bluetooth adapter (hard radio off)…");

                // Stop advertising (controller side)
                run_cmd("sudo btmgmt -i 0 advertising off", logger_);
                // Best effort: remove all adv instances (ignore errors)
                run_cmd("sudo btmgmt -i 0 rm-adv 0", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 rm-adv 1", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 rm-adv 2", logger_, INT_MIN);

                // Not pairable, not connectable
                run_cmd("sudo btmgmt -i 0 connectable off", logger_);
                run_cmd("sudo btmgmt -i 0 bondable off", logger_);

                // Power down controller
                run_cmd("sudo btmgmt -i 0 power off", logger_);

                // Bring interface down & block RF (actual radio kill)
                run_cmd("hciconfig hci0 down", logger_);
                run_cmd("rfkill block bluetooth", logger_);

                logger_->info("Bluetooth adapter fully disabled & radio blocked.");
            }

            void BLETransport::ensure_advertising()
            {
                // Keep advertising alive. If controller dropped instances, recreate.
                // Reduced logging to avoid spam - only runs periodically

                // If radio got blocked, silently un-block + power back on.
                run_cmd("rfkill unblock bluetooth", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 power on", logger_, INT_MIN);

                run_cmd("sudo btmgmt -i 0 le on", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 bredr off", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 connectable on", logger_, INT_MIN);
                run_cmd("sudo btmgmt -i 0 advertising on", logger_, INT_MIN);

                // Re-add adv if needed; ignore non-zero (already exists)
                run_cmd("sudo btmgmt -i 0 add-adv -d -p 200 flags 0x06 name '" + config_.ble.device_name + "'", logger_, INT_MIN);
            }

            void BLETransport::advertising_watchdog_loop()
            {
                logger_->info("Advertising watchdog started");

                while (running_.load())
                {
                    // Re-enable advertising every 10 seconds to keep it alive
                    ensure_advertising();

                    // Sleep for 10 seconds
                    for (int i = 0; i < 100 && running_.load(); ++i)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                logger_->info("Advertising watchdog stopped");
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
