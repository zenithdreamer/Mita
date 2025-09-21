#include "transports/ble_transport.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "protocol/protocol.hpp"

#include <thread>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <cctype>

namespace mita
{
    namespace transports
    {

        // BLEDeviceHandler Implementation
        BLEDeviceHandler::BLEDeviceHandler(IBLEBackend *backend,
                                           const std::string &device_address,
                                           const core::RouterConfig &config,
                                           services::RoutingService &routing_service,
                                           services::DeviceManagementService &device_management,
                                           services::StatisticsService &statistics_service)
            : config_(config), routing_service_(routing_service), device_management_(device_management), statistics_service_(statistics_service), device_address_(device_address), assigned_address_(0), connected_(false), authenticated_(false), running_(false), handshake_manager_(nullptr), session_crypto_(nullptr), backend_(backend), logger_(core::get_logger("BLEDeviceHandler"))
        {

            // Initialize handshake manager
            handshake_manager_ = std::make_unique<protocol::HandshakeManager>(
                config_.router_id, config_.shared_secret);

            logger_->debug("BLE device handler created", core::LogContext{}.add("address", device_address_));
        }

        BLEDeviceHandler::~BLEDeviceHandler()
        {
            disconnect();
        }

        bool BLEDeviceHandler::connect_and_setup()
        {
            logger_->info("Connecting to BLE device",
                          mita::core::LogContext{}.add("address", device_address_));
            connected_ = true; // backend already connected
            return true;
        }

        void BLEDeviceHandler::disconnect()
        {
            if (!connected_)
                return;

            logger_->info("Disconnecting from BLE device",
                          mita::core::LogContext{}.add("address", device_address_));

            running_ = false;
            connected_ = false;

            // Notify device management
            if (!device_id_.empty())
            {
                device_management_.notify_device_disconnected(device_id_);
            }
        }

        bool BLEDeviceHandler::send_packet(const protocol::ProtocolPacket &packet)
        {
            if (!connected_)
            {
                logger_->warning("Cannot send packet - BLE device not connected");
                return false;
            }

            try
            {
                // Serialize packet to bytes
                auto packet_data = packet.to_bytes();

                logger_->debug("Sending BLE packet", core::LogContext{}
                                                         .add("device_address", device_address_)
                                                         .add("packet_type", static_cast<int>(packet.get_message_type()))
                                                         .add("data_size", packet_data.size()));

                // Send via backend
                bool success = backend_->write_characteristic(
                    device_address_,
                    config_.ble.service_uuid,
                    config_.ble.characteristic_uuid,
                    packet_data);

                if (success)
                {
                    logger_->debug("BLE packet sent successfully", core::LogContext{}.add("device_address", device_address_));
                }
                else
                {
                    logger_->warning("Failed to send BLE packet", core::LogContext{}.add("device_address", device_address_));
                }

                return success;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error sending BLE packet", core::LogContext{}.add("error", e.what()));
                return false;
            }
        }

        void BLEDeviceHandler::handle_notification(const std::vector<uint8_t> &data)
        {
            try
            {
                logger_->info("[BLE] Device handler received notification", core::LogContext{}.add("device_address", device_address_).add("data_size", data.size()));

                // Log raw packet bytes (first 32 bytes) for debugging
                std::stringstream hex_stream;
                for (size_t i = 0; i < std::min(data.size(), size_t(32)); ++i)
                {
                    if (i > 0)
                        hex_stream << " ";
                    hex_stream << std::hex << (data[i] < 16 ? "0" : "") << static_cast<int>(data[i]);
                }
                logger_->info("[BLE] Raw packet bytes", core::LogContext{}
                                                            .add("hex_data", hex_stream.str())
                                                            .add("total_size", data.size()));

                // Parse the received data as a protocol packet
                auto parsed_packet = protocol::ProtocolPacket::from_bytes(data);
                if (parsed_packet)
                {
                    // Convert packet type to readable string
                    std::string packet_type_str;
                    switch (parsed_packet->get_message_type())
                    {
                    case MessageType::HELLO:
                        packet_type_str = "HELLO";
                        break;
                    case MessageType::CHALLENGE:
                        packet_type_str = "CHALLENGE";
                        break;
                    case MessageType::AUTH:
                        packet_type_str = "AUTH";
                        break;
                    case MessageType::AUTH_ACK:
                        packet_type_str = "AUTH_ACK";
                        break;
                    case MessageType::DATA:
                        packet_type_str = "DATA";
                        break;
                    case MessageType::ACK:
                        packet_type_str = "ACK";
                        break;
                    case MessageType::CONTROL:
                        packet_type_str = "CONTROL";
                        break;
                    case MessageType::ERROR:
                        packet_type_str = "ERROR";
                        break;
                    default:
                        packet_type_str = "UNKNOWN";
                        break;
                    }

                    logger_->info("[BLE] Parsed protocol packet",
                                  core::LogContext{}
                                      .add("device_id", device_id_)
                                      .add("packet_type", static_cast<int>(parsed_packet->get_message_type()))
                                      .add("packet_type_name", packet_type_str)
                                      .add("source_addr", parsed_packet->get_source_addr())
                                      .add("dest_addr", parsed_packet->get_dest_addr())
                                      .add("encrypted", parsed_packet->is_encrypted())
                                      .add("payload_size", parsed_packet->get_payload().size())
                                      .add("data_size", data.size()));

                    // Log payload for DATA packets to see what's being sent
                    if (parsed_packet->get_message_type() == MessageType::DATA)
                    {
                        const auto &payload = parsed_packet->get_payload();
                        std::stringstream payload_stream;
                        for (size_t i = 0; i < std::min(payload.size(), size_t(32)); ++i)
                        {
                            if (i > 0)
                                payload_stream << " ";
                            payload_stream << std::hex << (payload[i] < 16 ? "0" : "") << static_cast<int>(payload[i]);
                        }
                        logger_->info("[BLE] DATA packet payload", core::LogContext{}
                                                                       .add("payload_hex", payload_stream.str())
                                                                       .add("encrypted", parsed_packet->is_encrypted()));

                        // If encrypted and we have session crypto, try to decrypt
                        if (parsed_packet->is_encrypted() && session_crypto_)
                        {
                            try
                            {
                                auto decrypted = session_crypto_->decrypt(payload);
                                std::string decrypted_str(decrypted.begin(), decrypted.end());
                                logger_->info("[BLE] Decrypted DATA payload", core::LogContext{}
                                                                                  .add("decrypted_text", decrypted_str)
                                                                                  .add("decrypted_size", decrypted.size()));
                            }
                            catch (const std::exception &e)
                            {
                                logger_->warning("[BLE] Failed to decrypt DATA payload", core::LogContext{}
                                                                                             .add("error", e.what()));
                            }
                        }
                    }

                    // Route based on packet type
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
                else
                {
                    logger_->warning("Failed to parse BLE notification as protocol packet",
                                     core::LogContext{}
                                         .add("device_id", device_id_)
                                         .add("data_size", data.size()));
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
                if (packet.get_message_type() == MessageType::HELLO)
                {
                    std::string router_id, device_id;
                    std::vector<uint8_t> nonce;
                    if (protocol::utils::parse_hello_packet(packet, router_id, device_id, nonce))
                    {

                        if (router_id != config_.router_id)
                        {
                            logger_->warning("Wrong router ID from device", core::LogContext{}.add("router_id", router_id));
                            return;
                        }

                        device_id_ = device_id;
                        logger_->info("Received HELLO from BLE device", core::LogContext{}.add("device_id", device_id_));

                        // Register device in device management (must be done before authentication)
                        if (!device_management_.register_device(device_id_, core::TransportType::BLE))
                        {
                            logger_->warning("Failed to register BLE device", core::LogContext{}.add("device_id", device_id_));
                            return;
                        }

                        // Create and send CHALLENGE
                        auto challenge_packet = handshake_manager_->create_challenge_packet(device_id_, nonce);

                        // Log CHALLENGE packet details
                        auto challenge_data = challenge_packet->to_bytes();
                        std::stringstream challenge_hex;
                        for (size_t i = 0; i < std::min(challenge_data.size(), size_t(32)); ++i)
                        {
                            if (i > 0)
                                challenge_hex << " ";
                            challenge_hex << std::hex << (challenge_data[i] < 16 ? "0" : "") << static_cast<int>(challenge_data[i]);
                        }

                        bool sent = send_packet(*challenge_packet);

                        logger_->info("CHALLENGE packet details", core::LogContext{}
                                                                      .add("device_id", device_id_)
                                                                      .add("sent_successfully", sent)
                                                                      .add("packet_size", challenge_data.size())
                                                                      .add("hex_data", challenge_hex.str()));

                        logger_->debug("Sent CHALLENGE to BLE device", core::LogContext{}.add("device_id", device_id_));
                    }
                }
                else if (packet.get_message_type() == MessageType::AUTH)
                {
                    logger_->info("Received AUTH from BLE device", core::LogContext{}.add("device_id", device_id_));

                    if (device_id_.empty())
                    {
                        logger_->warning("Received AUTH without HELLO");
                        return;
                    }

                    // Verify authentication
                    if (handshake_manager_->verify_auth_packet(device_id_, packet))
                    {
                        // Authentication successful, assign address
                        assigned_address_ = routing_service_.add_device(device_id_, core::TransportType::BLE, this);

                        // Create AUTH_ACK before completing handshake
                        auto auth_ack_packet = handshake_manager_->create_auth_ack_packet(
                            device_id_, assigned_address_);

                        // Complete handshake and get session crypto
                        session_crypto_ = handshake_manager_->get_session_crypto(device_id_);
                        // Authenticate device in management service
                        if (session_crypto_)
                        {
                            device_management_.authenticate_device(device_id_, session_crypto_);
                        }
                        else
                        {
                            device_management_.authenticate_device(device_id_, nullptr);
                        }

                        // Add to routing table
                        std::map<std::string, std::string> connection_info = {
                            {"ble_address", device_address_},
                            {"service_uuid", config_.ble.service_uuid},
                            {"characteristic_uuid", config_.ble.characteristic_uuid}};

                        // Routing was already set up by add_device call above

                        // Send AUTH_ACK
                        send_packet(*auth_ack_packet);

                        // Mark as authenticated
                        authenticated_ = true;

                        // Notify device management
                        device_management_.notify_device_connected(device_id_);
                        // Handshake completed - could notify statistics service

                        running_ = true;
                        logger_->info("BLE device authenticated", core::LogContext{}.add("device_id", device_id_).add("address", "0x" + std::to_string(assigned_address_)));
                    }
                    else
                    {
                        // Authentication failed
                        logger_->warning("Authentication failed for BLE device", core::LogContext{}.add("device_id", device_id_));
                    }
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error handling handshake packet", core::LogContext{}.add("error", e.what()));
                statistics_service_.record_handshake_failed();
            }
        }

        void BLEDeviceHandler::handle_data_packet(const protocol::ProtocolPacket &packet)
        {
            try
            {
                auto data_packet = packet;

                // Decrypt packet if needed
                if (data_packet.get_flags() & 0x01)
                { // Encrypted flag
                    if (session_crypto_)
                    {
                        auto payload = data_packet.get_payload();
                        auto decrypted = session_crypto_->decrypt(payload);
                        data_packet.set_payload(decrypted);
                        data_packet.set_encrypted(false); // Mark as decrypted
                    }
                }

                // Forward to device management for processing
                device_management_.handle_packet(device_id_, data_packet, core::TransportType::BLE);
            }
            catch (const std::exception &e)
            {
                logger_->error("Error handling data packet", core::LogContext{}.add("error", e.what()));
                statistics_service_.record_packet_dropped();
            }
        }

        // BLETransport Implementation
        BLETransport::BLETransport(const core::RouterConfig &config,
                                   services::RoutingService &routing_service,
                                   services::DeviceManagementService &device_management,
                                   services::StatisticsService &statistics_service)
            : BaseTransport(config, routing_service, device_management, statistics_service), logger_(core::get_logger("BLETransport"))
        {

            // Register message handler
            device_management_.register_message_handler("ble", [this](const std::string &device_id, const protocol::ProtocolPacket &packet)
                                                        { send_packet(device_id, packet); });

            logger_->info("BLE transport initialized", core::LogContext{}.add("service_uuid", config_.ble.service_uuid).add("scan_interval", std::to_string(config_.ble.scan_interval)));
        }

        BLETransport::~BLETransport()
        {
            stop();

            // backend_ will cleans up itself
        }

        bool BLETransport::start()
        {
            if (running_)
                return true;

            try
            {
                logger_->info("BLE transport starting...");
                running_ = true;

                logger_->info("Initializing BLE adapter...");
                if (!initialize_adapter())
                {
                    logger_->error("Adapter initialization failed");
                    stop();
                    return false;
                }
                logger_->info("BLE adapter initialized successfully");

                logger_->info("Starting BLE discovery...");
                if (!start_discovery())
                {
                    logger_->error("Discovery start failed");
                    stop();
                    return false;
                }
                logger_->info("BLE discovery started successfully");

                // Start scanning thread
                logger_->info("Creating BLE scan thread...");
                scan_thread_ = std::make_unique<std::thread>(&BLETransport::scan_loop, this);
                logger_->info("BLE scan thread created successfully");

                // Wait a bit for initialization
                std::this_thread::sleep_for(std::chrono::seconds(1));

                logger_->info("BLE transport started with scan thread");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Failed to start BLE transport", core::LogContext{}.add("error", e.what()));
                stop();
                return false;
            }
        }

        void BLETransport::stop()
        {
            if (!running_)
                return;

            logger_->info("Stopping BLE transport...");
            running_ = false;

            // Wake up scan thread immediately
            scan_cv_.notify_all();

            // Stop discovery
            stop_discovery();

            // Disconnect all devices
            {
                std::lock_guard<std::mutex> lock(devices_mutex_);
                for (auto &[address, handler] : device_handlers_)
                {
                    handler->disconnect();
                }
                device_handlers_.clear();
                seen_devices_.clear();
            }

            // Wait for scan thread with aggressive timeout
            if (scan_thread_ && scan_thread_->joinable())
            {
                logger_->debug("Waiting for scan thread to stop...");

                // Aggressively notify the scan thread to wake up
                for (int i = 0; i < 10; ++i)
                {
                    scan_cv_.notify_all();
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }

                // Force join with timeout
                auto start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(3))
                {
                    scan_cv_.notify_all();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));

                    // Check if thread finished naturally
                    if (!scan_thread_->joinable())
                        break;
                }

                // Final join attempt
                if (scan_thread_->joinable())
                {
                    logger_->warning("Force joining scan thread...");
                    scan_thread_->join();
                }

                logger_->debug("Scan thread stopped");
            }

            logger_->info("BLE transport stopped");
        }

        bool BLETransport::send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            // Find device handler
            auto *handler = find_device_handler(device_id);
            if (!handler)
            {
                logger_->warning("No BLE connection found for device", core::LogContext{}.add("device_id", device_id));
                return false;
            }
            if (!backend_)
                return false;
            if (!handler->send_packet(packet))
                return false;
            auto bytes = packet.to_bytes();
            std::string address = device_address_from_id(device_id);
            if (!backend_->write_characteristic(address, config_.ble.service_uuid, config_.ble.characteristic_uuid, bytes))
            {
                logger_->warning("Backend write failed", core::LogContext{}.add("device_id", device_id));
                return false;
            }
            return true;
        }

        int BLETransport::broadcast_packet(const protocol::ProtocolPacket &packet)
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            int sent_count = 0;
            for (auto &[address, handler] : device_handlers_)
            {
                if (handler->is_authenticated())
                {
                    if (handler->send_packet(packet))
                    {
                        auto bytes = packet.to_bytes();
                        if (backend_ && backend_->write_characteristic(address, config_.ble.service_uuid, config_.ble.characteristic_uuid, bytes))
                        {
                            sent_count++;
                        }
                    }
                }
            }

            return sent_count;
        }

        std::string BLETransport::get_connection_info() const
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            std::ostringstream oss;
            oss << "BLE Transport: " << device_handlers_.size() << " connected devices\n";

            for (const auto &[address, handler] : device_handlers_)
            {
                if (!handler->get_device_id().empty())
                {
                    oss << "  Device: " << handler->get_device_id()
                        << " (0x" << std::hex << handler->get_assigned_address() << std::dec << ")"
                        << " - " << address << "\n";
                }
            }

            return oss.str();
        }

        void BLETransport::scan_loop()
        {
            logger_->info("[BLE SCAN] Starting BLE scan loop thread");

            int scan_cycles = 0;
            const int CLEAR_SEEN_DEVICES_CYCLES = 4; // Clear seen devices every 4 scan cycles

            while (running_)
            {
                try
                {
                    // Check running state before each operation
                    if (!running_)
                        break;

                    logger_->info("[BLE SCAN] Scan cycle starting...", core::LogContext{}.add("cycle", scan_cycles));
                    handle_device_discovery();
                    logger_->info("[BLE SCAN] Device discovery completed");

                    if (!running_)
                        break;

                    cleanup_disconnected_devices();
                    logger_->info("[BLE SCAN] Cleanup completed");

                    // Periodically clear seen devices to allow reconnection attempts
                    scan_cycles++;
                    if (scan_cycles >= CLEAR_SEEN_DEVICES_CYCLES)
                    {
                        std::lock_guard<std::mutex> lock(devices_mutex_);
                        int cleared_count = seen_devices_.size();
                        seen_devices_.clear();
                        if (cleared_count > 0)
                        {
                            logger_->debug("Cleared seen devices cache", core::LogContext{}.add("cleared_count", cleared_count));
                        }
                        scan_cycles = 0;
                    }

                    if (!running_)
                        break;

                    // Wait between scans with frequent checks for shutdown
                    auto pause_ms = static_cast<int>(config_.ble.scan_pause * 1000);
                    logger_->info("[BLE SCAN] Starting pause", core::LogContext{}.add("pause_ms", pause_ms));

                    auto check_interval = std::min(100, pause_ms / 10); // Check every 100ms or 1/10th of pause

                    for (int i = 0; i < pause_ms && running_; i += check_interval)
                    {
                        std::unique_lock<std::mutex> lock(scan_mutex_);
                        scan_cv_.wait_for(lock, std::chrono::milliseconds(check_interval), [this]
                                          { return !running_; });
                        if (!running_)
                            break;
                    }

                    logger_->info("[BLE SCAN] Pause completed, continuing to next cycle...");
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error in scan loop", core::LogContext{}.add("error", e.what()));

                    // Shorter error recovery delay and check running state
                    for (int i = 0; i < 50 && running_; ++i)
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                    logger_->info("[BLE SCAN] Error recovery completed, retrying...");
                }
            }

            logger_->info("[BLE SCAN] BLE scan loop thread exiting");
            logger_->debug("BLE scan loop stopped");
        }

        void BLETransport::handle_device_discovery()
        {
            // Check if we're still running before doing any work
            if (!running_)
                return;

            logger_->debug("[BLE SCAN] Acquiring devices mutex...");
            std::lock_guard<std::mutex> lock(devices_mutex_);
            logger_->debug("[BLE SCAN] Mutex acquired, starting discovery...");

            // Limit concurrent connections
            if (device_handlers_.size() >= static_cast<size_t>(config_.ble.max_connections))
            {
                logger_->debug("Max BLE connections reached", core::LogContext{}.add("current", device_handlers_.size()).add("max", config_.ble.max_connections));
                return;
            }

            logger_->info("[BLE SCAN] Scanning for BLE devices...", core::LogContext{}.add("current_connections", device_handlers_.size()).add("router_id", config_.router_id));
            if (backend_)
            {
                try
                {
                    auto devices = backend_->list_devices();
                    logger_->info("[BLE SCAN] Scan completed", core::LogContext{}.add("devices_found", devices.size()));

                    for (auto &d : devices)
                    {
                        if (!running_)
                            break; // Check running state in loop
                        logger_->debug("[BLE SCAN] Processing device", core::LogContext{}.add("address", d.address).add("name", d.name));
                        handle_device_found(d.address, d.name);
                        logger_->debug("[BLE SCAN] Device processed", core::LogContext{}.add("address", d.address));
                    }
                    logger_->info("[BLE SCAN] All devices processed");
                }
                catch (const std::exception &e)
                {
                    logger_->warning("BLE scan failed, will retry next cycle", core::LogContext{}.add("error", e.what()));
                    // Try to restart scanning on next cycle
                    if (backend_)
                    {
                        try
                        {
                            backend_->stop_scan();
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            backend_->start_scan();
                        }
                        catch (...)
                        {
                            // Ignore restart errors
                        }
                    }
                }
            }
            else
            {
                logger_->warning("No BLE backend available for scanning");
            }
        }

        void BLETransport::handle_device_found(const std::string &device_address, const std::string &device_name)
        {
            logger_->debug("[BLE SCAN] handle_device_found called", core::LogContext{}.add("address", device_address).add("name", device_name));
            // NOTE: devices_mutex_ is already held by calling function (handle_device_discovery)

            // Check if device name contains our router ID (case-insensitive)
            std::string lowercase_name = device_name;
            std::string lowercase_router_id = config_.router_id;
            std::transform(lowercase_name.begin(), lowercase_name.end(), lowercase_name.begin(), ::tolower);
            std::transform(lowercase_router_id.begin(), lowercase_router_id.end(), lowercase_router_id.begin(), ::tolower);

            if (lowercase_name.find(lowercase_router_id) == std::string::npos)
            {
                logger_->debug("Device name does not contain router ID",
                               core::LogContext{}.add("device_name", device_name).add("router_id", config_.router_id));
                return;
            }

            // Skip if already connected
            if (device_handlers_.find(device_address) != device_handlers_.end())
            {
                logger_->debug("Device already connected", core::LogContext{}.add("address", device_address));
                return;
            }

            // Skip if already seen recently
            if (seen_devices_.find(device_address) != seen_devices_.end())
            {
                logger_->debug("Device already seen recently", core::LogContext{}.add("address", device_address));
                return;
            }

            logger_->info("Found potential IoT device", core::LogContext{}.add("name", device_name).add("address", device_address));

            // Mark as seen
            seen_devices_.insert(device_address);

            // Try to connect
            connect_to_device(device_address, backend_);
        }

        bool BLETransport::connect_to_device(const std::string &device_address, std::unique_ptr<IBLEBackend> &backend)
        {
            try
            {
                if (!backend)
                {
                    logger_->warning("No BLE backend available", core::LogContext{}.add("address", device_address));
                    return false;
                }

                logger_->info("Attempting to connect to BLE device", core::LogContext{}.add("address", device_address));

                // Connect via backend first (synchronous)
                if (!backend->connect(device_address))
                {
                    logger_->warning("Backend connect failed", core::LogContext{}.add("address", device_address));
                    return false;
                }

                logger_->debug("Backend connected, setting up device handler", core::LogContext{}.add("address", device_address));

                // Create handler before enabling notifications so we don't drop early packets
                auto handler = std::make_unique<BLEDeviceHandler>(backend.get(),
                                                                  device_address,
                                                                  config_,
                                                                  routing_service_,
                                                                  device_management_,
                                                                  statistics_service_);

                logger_->debug("Calling handler connect_and_setup...", core::LogContext{}.add("address", device_address));
                if (!handler->connect_and_setup())
                {
                    logger_->warning("Handler setup failed", core::LogContext{}.add("address", device_address));
                    backend->disconnect(device_address);
                    return false;
                }
                logger_->debug("Handler setup completed successfully", core::LogContext{}.add("address", device_address));

                // Store handler BEFORE enabling notifications to avoid race condition
                // NOTE: devices_mutex_ is already held by calling function (handle_device_discovery)
                logger_->debug("Storing device handler in map...", core::LogContext{}.add("address", device_address));
                device_handlers_[device_address] = std::move(handler);
                logger_->debug("Device handler stored successfully", core::LogContext{}.add("address", device_address));

                // Enable notifications (handler already stored above)
                logger_->debug("Enabling notifications", core::LogContext{}.add("address", device_address).add("service_uuid", config_.ble.service_uuid).add("char_uuid", config_.ble.characteristic_uuid));

                bool notif_ok = backend->enable_notifications(
                    device_address,
                    config_.ble.service_uuid,
                    config_.ble.characteristic_uuid,
                    [this](const std::string &addr, const std::vector<uint8_t> &data)
                    {
                        logger_->info("[BLE] Notification received!", core::LogContext{}.add("address", addr).add("data_size", data.size()));
                        std::lock_guard<std::mutex> lock(devices_mutex_);
                        auto it = device_handlers_.find(addr);
                        if (it != device_handlers_.end())
                        {
                            logger_->debug("[BLE] Forwarding notification to handler", core::LogContext{}.add("address", addr));
                            it->second->notify_from_backend(data);
                        }
                        else
                        {
                            logger_->warning("Notification received for unknown device", core::LogContext{}.add("address", addr));
                        }
                    });

                if (!notif_ok)
                {
                    logger_->warning("Failed to enable notifications", core::LogContext{}.add("address", device_address));
                    // Remove handler since notifications failed
                    // NOTE: devices_mutex_ is already held by calling function (handle_device_discovery)
                    device_handlers_.erase(device_address);
                    backend->disconnect(device_address);
                    return false;
                }

                logger_->info("Successfully connected to BLE device", core::LogContext{}.add("address", device_address));
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error connecting to BLE device", core::LogContext{}.add("address", device_address).add("error", e.what()));
                if (backend)
                {
                    backend->disconnect(device_address);
                }
                return false;
            }
        }

        void BLETransport::cleanup_disconnected_devices()
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            auto it = device_handlers_.begin();
            while (it != device_handlers_.end())
            {
                if (!it->second->is_connected())
                {
                    logger_->debug("Removing disconnected device", core::LogContext{}.add("address", it->first));
                    it = device_handlers_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        BLEDeviceHandler *BLETransport::find_device_handler(const std::string &device_id)
        {
            for (auto &[address, handler] : device_handlers_)
            {
                if (handler->get_device_id() == device_id)
                {
                    return handler.get();
                }
            }
            return nullptr;
        }

        bool BLETransport::initialize_adapter()
        {
            try
            {
                backend_ = create_simplebluez_backend(config_);
                if (!backend_)
                    return false;
                logger_->info("BLE backend initialized (SimpleBluez)");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error initializing BLE adapter", core::LogContext{}.add("error", e.what()));
                return false;
            }
        }

        bool BLETransport::start_discovery()
        {
            try
            {
                if (backend_)
                {
                    logger_->info("Attempting to start BLE discovery...");

                    // Try to start scan
                    bool scan_started = backend_->start_scan();
                    if (scan_started)
                    {
                        logger_->info("BLE discovery started successfully");
                        return true;
                    }
                    else
                    {
                        logger_->warning("BLE scan failed to start, but transport will continue trying");
                        // Don't return false here, let the transport continue and retry in scan loop
                        return true;
                    }
                }
                logger_->error("No BLE backend available");
                return false;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error starting BLE discovery", core::LogContext{}.add("error", e.what()));
                // Don't fail completely, let scan loop retry
                return true;
            }
        }

        void BLETransport::stop_discovery()
        {
            if (backend_)
                backend_->stop_scan();
        }

        // Helper mapping function implementation
        std::string BLETransport::device_address_from_id(const std::string &device_id) const
        {
            for (auto &pair : device_handlers_)
            {
                if (pair.second->get_device_id() == device_id)
                    return pair.first;
            }
            return device_id; // fallback
        }

    } // namespace transports
} // namespace mita