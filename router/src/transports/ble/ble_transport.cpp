#include "transports/ble/ble_transport.hpp"
#include "transports/ble/ble_device_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "protocol/protocol.hpp"

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            BLETransport::BLETransport(
                const core::RouterConfig &config,
                services::RoutingService &routing_service,
                services::DeviceManagementService &device_management,
                services::StatisticsService &statistics_service,
                std::shared_ptr<services::PacketMonitorService> packet_monitor)
                : BaseTransport(config, routing_service, device_management, statistics_service),
                  event_queue_(1000), // queue max size
                  logger_(core::get_logger("BLETransport")),
                  packet_monitor_(packet_monitor)
            {
                logger_->info("BLE transport created",
                             core::LogContext{}
                                 .add("service_uuid", config_.ble.service_uuid)
                                 .add("max_connections", config_.ble.max_connections));
            }

            BLETransport::~BLETransport()
            {
                stop();
                logger_->info("BLE transport destroyed");
            }


            bool BLETransport::start()
            {
                if (running_)
                {
                    logger_->warning("BLE transport already running");
                    return true;
                }

                logger_->info("BLE transport starting...");
                running_ = true;

                try
                {
                    // start backend
                    logger_->info("Initializing BLE backend...");
                    if (!initialize_backend())
                    {
                        logger_->error("Failed to initialize BLE backend");
                        stop();
                        return false;
                    }
                    logger_->info("BLE backend initialized successfully");

                    // start discovery
                    logger_->info("Starting BLE discovery...");
                    if (!start_discovery())
                    {
                        logger_->error("Failed to start BLE discovery");
                        stop();
                        return false;
                    }
                    logger_->info("BLE discovery started successfully");

                    // create and start event processor
                    logger_->info("Creating event processor...");
                    event_processor_ = std::make_unique<BLEEventProcessor>(
                        event_queue_,
                        device_registry_,
                        routing_service_,
                        device_management_,
                        statistics_service_);

                    logger_->info("Starting event processor...");
                    if (!event_processor_->start())
                    {
                        logger_->error("Failed to start event processor");
                        stop();
                        return false;
                    }
                    logger_->info("Event processor started successfully");

                    // start scan thread
                    logger_->info("Starting scan thread...");
                    scan_thread_ = std::make_unique<std::thread>(&BLETransport::scan_loop, this);
                    logger_->info("Scan thread started successfully");

                    device_management_.register_message_handler("ble", [this](const std::string &device_id, const protocol::ProtocolPacket &packet)
                                                            { send_packet(device_id, packet); });

                    logger_->info("BLE transport started successfully",
                                 core::LogContext{}
                                     .add("service_uuid", config_.ble.service_uuid)
                                     .add("max_connections", config_.ble.max_connections));
                    return true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception during BLE transport start",
                                  core::LogContext{}.add("error", e.what()));
                    stop();
                    return false;
                }
            }

            void BLETransport::stop()
            {
                if (!running_)
                {
                    return;
                }

                logger_->info("Stopping BLE transport...");
                running_ = false;

                // wake up scan thread
                logger_->debug("Waking up scan thread...");
                scan_cv_.notify_all();

                // stop discovery
                logger_->debug("Stopping BLE discovery...");
                stop_discovery();

                // stop event processor (this will stop the event queue too)
                logger_->debug("Stopping event processor...");
                if (event_processor_)
                {
                    event_processor_->stop();
                    event_processor_.reset();
                }

                // wait for scan thread to finish
                logger_->debug("Waiting for scan thread to finish...");
                if (scan_thread_ && scan_thread_->joinable())
                {
    
                    auto start_time = std::chrono::steady_clock::now();
                    while (scan_thread_->joinable() &&
                           std::chrono::steady_clock::now() - start_time < std::chrono::seconds(3))
                    {
                        scan_cv_.notify_all();
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }

                    if (scan_thread_->joinable())
                    {
                        logger_->debug("Joining scan thread...");
                        scan_thread_->join();
                    }
                    scan_thread_.reset();
                    logger_->debug("Scan thread stopped");
                }

                // disconnect all devices
                logger_->debug("Disconnecting all devices...");
                auto all_devices = device_registry_.get_all_devices();
                for (auto &handler : all_devices)
                {
                    if (handler)
                    {
                        handler->disconnect();
                    }
                }

                // clear registry
                logger_->debug("Clearing device registry...");
                device_registry_.clear();

                // clear seen devices cache
                {
                    std::lock_guard<std::mutex> lock(seen_devices_mutex_);
                    seen_devices_.clear();
                }

                logger_->info("BLE transport stopped");
            }

            bool BLETransport::send_packet(const std::string &device_id,
                                          const protocol::ProtocolPacket &packet)
            {
                logger_->debug("send_packet called",
                              core::LogContext{}.add("device_id", device_id));

                // get device handler from registry by device_id
                auto handler = device_registry_.find_by_device_id(device_id);
                if (!handler)
                {
                    logger_->warning("No BLE connection found for device",
                                    core::LogContext{}.add("device_id", device_id));
                    return false;
                }

                // send packet through handler
                if (!handler->send_packet(packet))
                {
                    logger_->warning("Failed to send packet via BLE",
                                    core::LogContext{}.add("device_id", device_id));
                    return false;
                }

                logger_->debug("Packet sent successfully via BLE",
                              core::LogContext{}.add("device_id", device_id));
                return true;
            }

            int BLETransport::broadcast_packet(const protocol::ProtocolPacket &packet)
            {
                logger_->debug("broadcast_packet called");

                // get all authenticated devices from registry
                auto authenticated_devices = device_registry_.get_authenticated_devices();

                if (authenticated_devices.empty())
                {
                    logger_->debug("No authenticated BLE devices to broadcast to");
                    return 0;
                }

                // send packet to each authenticated device
                int sent_count = 0;
                for (const auto &handler : authenticated_devices)
                {
                    if (handler && handler->send_packet(packet))
                    {
                        sent_count++;
                    }
                }

                logger_->debug("Broadcast packet sent",
                              core::LogContext{}
                                  .add("total_devices", authenticated_devices.size())
                                  .add("sent_count", sent_count));

                return sent_count;
            }

            std::string BLETransport::get_connection_info() const
            {

                int device_count = device_registry_.get_device_count();

                return "BLE Transport: " + std::to_string(device_count) + " devices connected" ;
            }



            bool BLETransport::initialize_backend()
            {
                logger_->info("Initializing BLE backend...");

                try{
                    // Use peripheral backend instead of SimpleBluez
                    logger_->info("Creating peripheral mode backend");
                    backend_ = create_peripheral_backend(config_);

                    if (!backend_)
                    {
                        logger_->error("Failed to create BLE peripheral backend");
                        return false;
                    }

                    // Register GATT service and characteristic
                    logger_->info("Registering GATT service",
                                  core::LogContext{}
                                      .add("service_uuid", config_.ble.service_uuid)
                                      .add("char_uuid", config_.ble.characteristic_uuid));

                    bool gatt_ok = backend_->register_gatt_service(
                        config_.ble.service_uuid,
                        config_.ble.characteristic_uuid,
                        [this](const std::string &client_addr, const std::vector<uint8_t> &data)
                        {
                            // Handle incoming data from client
                            this->on_data_received(client_addr, data);
                        },
                        [this](const std::string &client_addr) -> std::vector<uint8_t>
                        {
                            // Handle read requests (not commonly used)
                            return {};
                        });

                    if (!gatt_ok)
                    {
                        logger_->warning("GATT service registration returned false (may need manual setup)");
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Failed to create BLE backend", core::LogContext{}.add("error", e.what()));
                    return false;
                }

                logger_->info("BLE peripheral backend initialized");
                return true;
            }

            bool BLETransport::start_discovery()
            {
                logger_->info("Starting BLE advertising (peripheral mode)...");

                // In peripheral mode, we advertise instead of scanning
                bool adv_started = backend_->start_advertising(config_.ble.device_name);
                if (!adv_started)
                {
                    logger_->error("BLE backend failed to start advertising");
                    return false;
                }

                logger_->info("BLE advertising started",
                              core::LogContext{}.add("device_name", config_.ble.device_name));
                return true;
            }

            void BLETransport::stop_discovery()
            {
                logger_->info("Stopping BLE advertising...");
                backend_->stop_advertising();
                logger_->info("BLE advertising stopped");
            }

            void BLETransport::scan_loop()
            {
                logger_->info("Peripheral mode monitoring thread started");

                while (running_)
                {
                    try
                    {
                        // In peripheral mode, we don't scan for devices
                        // Instead, we monitor connected clients and handle timeouts

                        logger_->debug("Peripheral mode: monitoring clients");

                        // Check heartbeat timeouts for connected clients
                        check_heartbeat_timeouts();

                        // Cleanup disconnected devices
                        cleanup_disconnected_devices();

                        // Sleep for the configured interval
                        std::unique_lock<std::mutex> lock(scan_mutex_);
                        scan_cv_.wait_for(lock, std::chrono::duration<double>(config_.ble.scan_pause),
                                         [this] { return !running_; });
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Error in peripheral monitoring loop",
                                       core::LogContext{}.add("error", e.what()));

                        std::unique_lock<std::mutex> lock(scan_mutex_);
                        scan_cv_.wait_for(lock, std::chrono::seconds(5),
                                          [this]
                                          { return !running_; });
                    }
                }

                logger_->info("Peripheral monitoring thread stopped");
            }

            void BLETransport::handle_device_found(const std::string &address,
                                                   const std::string &name)
            {
                if (!running_)
                {
                    return;
                }

                // comment debug log cause it too much I cant take it
                // logger_->debug("Device found",
                // core::LogContext{}.add("address", address).add("name", name));

                // check if already connected
                auto existing_handler = device_registry_.get_device(address);
                if (existing_handler)
                {
                    // reconnect device handler still in retgistry
                    if (!existing_handler->is_connected())
                    {
                        logger_->info("Device found in registry but disconnected - attempting reconnect",
                                      core::LogContext{}
                                          .add("address", address)
                                          .add("device_id", existing_handler->get_device_id()));

                        if (backend_->connect(address))
                        {
                            // enable notifications
                            if (backend_->enable_notifications(
                                    address,
                                    config_.ble.service_uuid,
                                    config_.ble.characteristic_uuid,
                                    [this](const std::string &addr, const std::vector<uint8_t> &data)
                                    {
                                        on_notification_received(addr, data);
                                    }))
                            {
                                // reconnect handler
                                if (existing_handler->reconnect())
                                {
                                    logger_->info("Device successfully reconnected",
                                                  core::LogContext{}
                                                      .add("address", address)
                                                      .add("device_id", existing_handler->get_device_id()));
                                }
                                else
                                {
                                    logger_->warning("Handler reconnect failed",
                                                     core::LogContext{}.add("address", address));
                                }
                            }
                            else
                            {
                                logger_->warning("Failed to re-enable notifications on reconnect",
                                                 core::LogContext{}.add("address", address));
                                backend_->disconnect(address);
                            }
                        }
                        else
                        {
                            logger_->warning("Backend reconnect failed",
                                             core::LogContext{}.add("address", address));
                        }
                    }

                    return;
                }

                // check if we've already seen and rejected this device recently
                {
                    std::lock_guard<std::mutex> lock(seen_devices_mutex_);
                    auto it = seen_devices_.find(address);
                    if (it != seen_devices_.end())
                    {
                        return;
                    }
                }

                // check max connections limit
                if (device_registry_.get_device_count() >= config_.ble.max_connections)
                {
                    logger_->debug("Max connections reached - skipping device",
                                   core::LogContext{}.add("address", address).add("max_connections", config_.ble.max_connections));
                    return;
                }

                // check if device has required Mita service
                if (!device_has_service(address))
                {
                    // Mark as seen so we don't check again
                    std::lock_guard<std::mutex> lock(seen_devices_mutex_);
                    seen_devices_.insert(address);

                    // same here, too much logs
                    // logger_->debug("Device does not have required service",
                    // core::LogContext{}.add("address", address)
                    //.add("service_uuid", config_.ble.service_uuid));
                    return;
                }

                logger_->info("Connecting to new device",
                              core::LogContext{}.add("address", address).add("name", name));

                if (connect_to_device(address))
                {
                    logger_->info("Successfully connect to new device",
                                  core::LogContext{}.add("address", address).add("name", name));
                }
                else
                {
                    // mark as seen to avoid immediate retry
                    std::lock_guard<std::mutex> lock(seen_devices_mutex_);
                    seen_devices_.insert(address);

                    logger_->warning("Failed to connect to device",
                                     core::LogContext{}.add("address", address).add("name", name));
                }
            }

            bool BLETransport::connect_to_device(const std::string &address)
            {
                if (!running_)
                {
                    return false;
                }

                logger_->info("Connecting to device",
                              core::LogContext{}.add("address", address));

                if (!backend_->connect(address))
                {
                    logger_->warning("Backend failed to connect to device",
                                     core::LogContext{}.add("address", address));
                    return false;
                }

                auto handler = std::make_shared<BLEDeviceHandler>(
                    backend_.get(),
                    address,
                    config_,
                    routing_service_,
                    device_management_,
                    statistics_service_,
                    packet_monitor_);

                if (!handler->connect())
                {
                    logger_->error("Device handler failed to connect",
                                   core::LogContext{}.add("address", address));
                    backend_->disconnect(address);
                    return false;
                }

                // Step 4: Add handler to registry FIRST (before enabling notifications!)
                // This prevents race condition where notification arrives before handler is registered
                if (!device_registry_.add_device(address, handler))
                {
                    logger_->error("Failed to add device to registry",
                                   core::LogContext{}.add("address", address));
                    backend_->disconnect(address);
                    return false;
                }

                // red alert!!! handler MUST be in registry before this, as notifications can arrive immediately
                if (!backend_->enable_notifications(
                        address,
                        config_.ble.service_uuid,
                        config_.ble.characteristic_uuid,
                        [this](const std::string &addr, const std::vector<uint8_t> &data)
                        {
                            // this runs in SimpleBluez thread
                            on_notification_received(addr, data);
                        }))
                {
                    logger_->error("Failed to enable notifications",
                                   core::LogContext{}.add("address", address));
                    device_registry_.remove_device(address);
                    backend_->disconnect(address);
                    return false;
                }

                logger_->info("Successfully connected and registered device",
                              core::LogContext{}.add("address", address).add("registry_size", device_registry_.get_device_count()));

                return true;
            }

            bool BLETransport::device_has_service(const std::string &address)
            {

                if (!running_)
                {
                    return false;
                }

                if (backend_->has_service(address, config_.ble.service_uuid))
                {
                    logger_->debug("Device has required service",
                                   core::LogContext{}.add("address", address).add("service_uuid", config_.ble.service_uuid));
                    return true;
                }

                return false;
            }

            void BLETransport::on_notification_received(const std::string &address,
                                                        const std::vector<uint8_t> &data)
            {

                logger_->debug("Notification received",
                               core::LogContext{}.add("address", address).add("size", data.size()));

                if (!event_queue_.enqueue(BLEEvent::notification(address, data)))
                {
                    logger_->warning("Failed to enqueue notification - queue full",
                                     core::LogContext{}.add("address", address));
                }
            }

            void BLETransport::check_heartbeat_timeouts()
            {
                auto all_devices = device_registry_.get_all_devices();
                for (auto &handler : all_devices)
                {
                    if (handler)
                    {
                        handler->check_heartbeat_timeout();
                    }
                }
            }

            std::vector<std::shared_ptr<BLEDeviceHandler>> BLETransport::get_all_device_handlers() const
            {
                return device_registry_.get_all_devices();
            }

            void BLETransport::cleanup_disconnected_devices()
            {
                logger_->debug("Cleaning up disconnected devices");

                auto all_devices = device_registry_.get_all_devices();
                int removed_count = 0;

                for (auto &handler : all_devices)
                {
                    if (handler && handler->check_for_disconnected())
                    {
                        std::string device_id = handler->get_device_id();
                        std::string address = handler->get_device_address();

                        logger_->info("Removing device after grace period",
                                      core::LogContext{}
                                          .add("device_id", device_id)
                                          .add("address", address));

                        // disconnect backend
                        backend_->disconnect(address);

                        // remove from device registry
                        if (device_registry_.remove_device(address))
                        {
                            removed_count++;

                            if (!device_id.empty())
                            {
                                device_management_.remove_device(device_id);
                            }
                        }
                    }
                }

                if (removed_count > 0)
                {
                    logger_->info("Removed disconnected devices",
                                  core::LogContext{}.add("count", removed_count));
                }
            }

            void BLETransport::on_data_received(const std::string &client_address, const std::vector<uint8_t> &data)
            {
                logger_->debug("Data received from client",
                               core::LogContext{}
                                   .add("client_address", client_address)
                                   .add("data_size", data.size()));

                // Check if we already have a device handler for this client
                auto handler = device_registry_.get_device(client_address);

                if (!handler)
                {
                    // New client connection - create device handler
                    logger_->info("New client connected via BLE",
                                  core::LogContext{}.add("address", client_address));

                    // Queue a notification event for processing
                    // The event processor will handle creating the device handler
                    BLEEvent event = BLEEvent::notification(client_address, data);
                    event_queue_.enqueue(event);
                }
                else
                {
                    // Existing client - process data via notification event
                    on_notification_received(client_address, data);
                }
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
