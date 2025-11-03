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
                services::StatisticsService &statistics_service)
                : BaseTransport(config, routing_service, device_management, statistics_service),
                  event_queue_(1000), // queue max size
                  logger_(core::get_logger("BLETransport"))
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
                    backend_ = create_simplebluez_backend(config_);
                    if (!backend_)
                    {
                        logger_->error("Failed to create BLE backend");
                        return false;
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("Failed to create BLE backend", core::LogContext{}.add("error", e.what()));
                    return false;
                }

                logger_->info("BLE backend initialized");
                return true;
            }

            bool BLETransport::start_discovery()
            {
                logger_->info("Starting BLE discovery...");

                bool scan_started = backend_->start_scan();
                if (!scan_started)
                {
                    logger_->error("BLE backend failed to start scan");
                    return false;
                }

                logger_->info("BLE discovery started");
                return true;
            }

            void BLETransport::stop_discovery()
            {
                logger_->info("Stopping BLE discovery...");
                backend_->stop_scan();
                logger_->info("BLE discovery stopped");
            }

            void BLETransport::scan_loop()
            {
                logger_->info("Scan loop thread started");

                while (running_)
                {
                    try
                    {
                        // get list of discovered devices from backend
                        auto devices = backend_->list_devices();

                        logger_->debug("Scan cycle",
                                      core::LogContext{}.add("discovered_devices", devices.size()));

                        // process each discovered device
                        for (const auto &device : devices)
                        {
                            if (!running_)
                            {
                                break; 
                            }

                            handle_device_found(device.address, device.name);
                        }

                        // Cleanup disconnected devices
                        cleanup_disconnected_devices();

                        std::unique_lock<std::mutex> lock(scan_mutex_);
                        scan_cv_.wait_for(lock, std::chrono::duration<double>(config_.ble.scan_pause),
                                         [this] { return !running_; });
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Error in scan loop",
                                      core::LogContext{}.add("error", e.what()));

                        std::unique_lock<std::mutex> lock(scan_mutex_);
                        scan_cv_.wait_for(lock, std::chrono::seconds(5),
                                         [this] { return !running_; });
                    }
                }

                logger_->info("Scan loop thread stopped");
            }

            void BLETransport::handle_device_found(const std::string &address,
                                                  const std::string &name)
            {
                if (!running_)
                {
                    return;
                }

                // comment debug log cause it too much I cant take it
                //logger_->debug("Device found",
                              //core::LogContext{}.add("address", address).add("name", name));

                // check if already connected
                if (device_registry_.has_device(address))
                {
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
                                  core::LogContext{}.add("address", address)
                                      .add("max_connections", config_.ble.max_connections));
                    return;
                }

                // check if device has required Mita service
                if (!device_has_service(address))
                {
                    // Mark as seen so we don't check again
                    std::lock_guard<std::mutex> lock(seen_devices_mutex_);
                    seen_devices_.insert(address);

                    // same here, too much logs
                    //logger_->debug("Device does not have required service",
                                  //core::LogContext{}.add("address", address)
                                      //.add("service_uuid", config_.ble.service_uuid));
                    return;
                }

                logger_->info("Attempting to connect to device",
                             core::LogContext{}.add("address", address).add("name", name));

                if (connect_to_device(address))
                {
                    logger_->info("Successfully connected to device",
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
                    statistics_service_);


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
                             core::LogContext{}.add("address", address)
                                 .add("registry_size", device_registry_.get_device_count()));

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
                                  core::LogContext{}.add("address", address)
                                      .add("service_uuid", config_.ble.service_uuid));
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

            // ========== PRIVATE METHODS: CLEANUP ==========

            void BLETransport::cleanup_disconnected_devices()
            {
                logger_->debug("Cleaning up disconnected devices");

                int removed_count = device_registry_.remove_disconnected();
                logger_->info("Removed disconnected devices",
                              core::LogContext{}.add("count", removed_count));
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
