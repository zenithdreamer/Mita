#include "core/router.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/statistics_service.hpp"
#include "services/device_management_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "transports/wifi_transport.hpp"
#include "transports/ble/ble_transport.hpp"
#include "transports/lora/lora_transport.hpp"
#include "infrastructure/wifi_manager.hpp"
#include <thread>
#include <chrono>

namespace mita
{
    namespace core
    {

        MitaRouter::MitaRouter(std::unique_ptr<RouterConfig> config, std::shared_ptr<mita::db::Storage> storage)
            : config_(std::move(config)), storage_(storage), logger_(get_logger("MitaRouter")), start_time_(std::chrono::steady_clock::now())
        {

            if (!config_)
            {
                throw std::invalid_argument("Router configuration cannot be null");
            }

            logger_->info("Mita Router initialized",
                          LogContext()
                            .add("router_id", config_->router_id)
                            .add("wifi_enabled", true)
                            .add("ble_enabled", true)
                            .add("database_enabled", storage_ != nullptr));
        }

        MitaRouter::~MitaRouter()
        {
            stop();
        }

        bool MitaRouter::start()
        {
            if (running_.exchange(true))
            {
                return true; // Already running
            }

            try
            {
                logger_->info("Starting Mita Router...");

                // Initialize core services
                routing_service_ = std::make_unique<services::RoutingService>(config_->routing);
                statistics_service_ = std::make_unique<services::StatisticsService>();
                device_management_ = std::make_shared<services::DeviceManagementService>(
                    *routing_service_, *statistics_service_);
                packet_monitor_ = std::make_shared<services::PacketMonitorService>(storage_);

                // Connect packet monitor to services
                routing_service_->set_packet_monitor(packet_monitor_);
                device_management_->set_packet_monitor(packet_monitor_);

                // Start services
                routing_service_->start();
                statistics_service_->start();
                device_management_->start();
                packet_monitor_->start(); // Start async writer thread

                // Initialize transports
                bool any_transport_started = false;

                // Only attempt to start enabled transports
                if (config_->wifi.enabled)
                {
                    if (setup_wifi_transport())
                    {
                        any_transport_started = true;
                        logger_->info("WiFi transport started successfully");
                    }
                    else
                    {
                        logger_->warning("WiFi transport failed to start");
                    }
                }
                else
                {
                    logger_->info("WiFi transport disabled");
                }

                if (config_->ble.enabled)
                {
                    if (setup_ble_transport())
                    {
                        any_transport_started = true;
                        logger_->info("BLE transport started successfully");
                    }
                    else
                    {
                        logger_->warning("BLE transport failed to start");
                    }
                }
                else
                {
                    logger_->info("BLE transport disabled");
                }


                if (config_->lora.enabled)
                {
                    if (setup_lora_transport())
                    {
                        any_transport_started = true;
                        logger_->info("LoRa transport started successfully");
                    }
                    else
                    {
                        logger_->warning("LoRa transport failed to start");
                    }
                }
                else
                {
                    logger_->info("LoRa transport disabled");
                }


                if (!any_transport_started)
                {
                    logger_->warning("No transports enabled - router running in configuration-only mode");
                }

                // Start background tasks
                start_background_tasks();

                logger_->info("Mita Router started successfully",
                              LogContext().add("transports", transports_.size()).add("router_id", config_->router_id));

                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Failed to start router",
                               LogContext().add("error", e.what()));
                stop();
                return false;
            }
        }

        void MitaRouter::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            logger_->info("Stopping Mita Router...");

            //wake up the shutdown thread
            shutdown_cv_.notify_all();

            // Stop all transports
            for (auto &[name, transport] : transports_)
            {
                try
                {
                    logger_->debug("Stopping transport", LogContext().add("transport", name));
                    transport->stop();
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error stopping transport",
                                   LogContext().add("transport", name).add("error", e.what()));
                }
            }
            transports_.clear();

            // Stop WiFi Access Point
            if (wifi_ap_manager_)
            {
                try
                {
                    wifi_ap_manager_->teardown_hotspot();
                    wifi_ap_manager_.reset();
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error stopping WiFi AP",
                                   LogContext().add("error", e.what()));
                }
            }

            // Stop background threads
            if (main_loop_thread_ && main_loop_thread_->joinable())
            {
                main_loop_thread_->join();
            }

            if (status_thread_ && status_thread_->joinable())
            {
                status_thread_->join();
            }

            // Stop services
            if (device_management_)
            {
                device_management_->stop();
            }
            if (routing_service_)
            {
                routing_service_->stop();
            }
            if (statistics_service_)
            {
                statistics_service_->stop();
            }

            logger_->info("Mita Router stopped");
        }

        bool MitaRouter::send_message(const std::string &device_id, const std::vector<uint8_t> &message)
        {
            if (!running_ || !device_management_)
            {
                return false;
            }

            try
            {
                return device_management_->send_message_to_device(device_id, message);
            }
            catch (const std::exception &e)
            {
                logger_->error("Error sending message to device",
                               LogContext().add("device_id", device_id).add("error", e.what()));
                return false;
            }
        }

        int MitaRouter::broadcast_message(const std::vector<uint8_t> &message)
        {
            if (!running_ || !device_management_)
            {
                return 0;
            }

            try
            {
                return device_management_->broadcast_message(message);
            }
            catch (const std::exception &e)
            {
                logger_->error("Error broadcasting message",
                               LogContext().add("error", e.what()));
                return 0;
            }
        }

        std::map<std::string, std::map<std::string, std::string>> MitaRouter::get_connected_devices()
        {
            std::map<std::string, std::map<std::string, std::string>> result;

            if (!device_management_)
            {
                return result;
            }

            try
            {
                auto devices = device_management_->get_device_list();
                for (const auto &[device_id, device] : devices)
                {
                    std::map<std::string, std::string> device_info;
                    device_info["device_id"] = device.device_id;
                    device_info["assigned_address"] = std::to_string(device.assigned_address);
                    device_info["transport_type"] = (device.transport_type == TransportType::WIFI) ? "wifi" : "ble";
                    device_info["state"] = std::to_string(static_cast<int>(device.state));

                    auto now = std::chrono::steady_clock::now();
                    auto last_activity = std::chrono::duration_cast<std::chrono::seconds>(
                                             now - device.last_activity)
                                             .count();
                    device_info["last_activity_seconds"] = std::to_string(last_activity);

                    result[device_id] = device_info;
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error getting device list",
                               LogContext().add("error", e.what()));
            }

            return result;
        }

        std::map<std::string, uint64_t> MitaRouter::get_statistics()
        {
            if (!statistics_service_)
            {
                return {};
            }

            try
            {
                return statistics_service_->get_statistics().to_map();
            }
            catch (const std::exception &e)
            {
                logger_->error("Error getting statistics",
                               LogContext().add("error", e.what()));
                return {};
            }
        }

        std::map<std::string, std::string> MitaRouter::get_router_info()
        {
            std::map<std::string, std::string> info;

            info["router_id"] = config_->router_id;
            info["running"] = running_ ? "true" : "false";

            // Transport information
            std::string transport_list;
            for (const auto &[name, transport] : transports_)
            {
                if (!transport_list.empty())
                {
                    transport_list += ",";
                }
                transport_list += name;
            }
            info["transports"] = transport_list;

            // Device count
            if (device_management_)
            {
                info["connected_devices"] = std::to_string(device_management_->get_device_count());
            }
            else
            {
                info["connected_devices"] = "0";
            }

            // Uptime
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_);
            info["uptime_seconds"] = std::to_string(uptime.count());

            return info;
        }

        bool MitaRouter::setup_wifi_transport()
        {
            // Check if WiFi is enabled in configuration
            if (!config_->wifi.enabled)
            {
                logger_->info("WiFi transport disabled in configuration - skipping WiFi AP setup");
                return false;
            }

            try
            {
                logger_->info("Setting up WiFi transport...");

                // Setup WiFi Access Point if not skipping
                if (!config_->development.skip_ap_setup)
                {
                    wifi_ap_manager_ = std::make_unique<infrastructure::WiFiAccessPointManager>(
                        std::shared_ptr<core::RouterConfig>(config_.get(), [](RouterConfig *) {}));

                    if (!wifi_ap_manager_->setup_hotspot())
                    {
                        logger_->error("Failed to setup WiFi Access Point");
                        return false;
                    }

                    // Display security settings for debugging
                    wifi_ap_manager_->show_security_settings();

                    // Wait for interface to be ready
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                }
                else
                {
                    logger_->info("Skipping WiFi AP setup (development mode)");
                }

                // Initialize WiFi transport with packet monitor
                auto wifi_transport = std::make_unique<transports::WiFiTransport>(
                    *config_, *routing_service_, *device_management_, *statistics_service_, packet_monitor_);

                if (wifi_transport->start())
                {
                    std::lock_guard<std::mutex> lock(transports_mutex_);
                    transports_["wifi"] = std::move(wifi_transport);
                    logger_->info("WiFi transport setup complete");
                    return true;
                }
                else
                {
                    logger_->error("Failed to start WiFi transport");
                    // Cleanup AP on transport failure
                    if (wifi_ap_manager_)
                    {
                        wifi_ap_manager_->teardown_hotspot();
                        wifi_ap_manager_.reset();
                    }
                    return false;
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error setting up WiFi transport",
                               LogContext().add("error", e.what()));
                // Cleanup AP on exception
                if (wifi_ap_manager_)
                {
                    wifi_ap_manager_->teardown_hotspot();
                    wifi_ap_manager_.reset();
                }
                return false;
            }
        }

        bool MitaRouter::start_wifi_transport()
        {
            if (!running_)
            {
                logger_->warning("Cannot start WiFi transport: router not running");
                return false;
            }

            std::lock_guard<std::mutex> lock(transports_mutex_);

            // Check if WiFi is already running
            if (transports_.find("wifi") != transports_.end())
            {
                logger_->info("WiFi transport is already running");
                return true;
            }

            logger_->info("Starting WiFi transport dynamically...");

            // Enable WiFi interface first
            logger_->info("Enabling WiFi interface...");

            // Unblock WiFi via rfkill
            system("rfkill unblock wifi 2>/dev/null");

            // Enable WiFi radio using nmcli
            system("nmcli radio wifi on 2>/dev/null");

            // Bring up WiFi interface
            system("ip link set wlan0 up 2>/dev/null");
            system("ip link set wlp0s20f3 up 2>/dev/null");

            // Small delay to let interface come up
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            // Temporarily enable WiFi in config
            config_->wifi.enabled = true;

            // Release lock to avoid deadlock when calling setup
            transports_mutex_.unlock();
            bool success = setup_wifi_transport();
            transports_mutex_.lock();

            if (success)
            {
                logger_->info("WiFi transport started successfully");
            }
            else
            {
                logger_->error("Failed to start WiFi transport");
                config_->wifi.enabled = false;
            }

            return success;
        }

        bool MitaRouter::stop_wifi_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);

            auto it = transports_.find("wifi");
            if (it == transports_.end())
            {
                logger_->info("WiFi transport is not running");
                return true;
            }

            logger_->info("Stopping WiFi transport...");

            try
            {
                // Stop the transport
                it->second->stop();

                // Remove from transports map
                transports_.erase(it);

                // Stop WiFi Access Point
                if (wifi_ap_manager_)
                {
                    wifi_ap_manager_->teardown_hotspot();
                    wifi_ap_manager_.reset();
                }

                // Disable WiFi interface completely
                logger_->info("Disabling WiFi interface...");

                // Bring down WiFi interface using nmcli
                system("nmcli radio wifi off 2>/dev/null");

                // Alternative: bring down specific WiFi interfaces
                system("ip link set wlan0 down 2>/dev/null");
                system("ip link set wlp0s20f3 down 2>/dev/null");

                // Use rfkill to block WiFi
                system("rfkill block wifi 2>/dev/null");

                // Update config
                config_->wifi.enabled = false;

                logger_->info("WiFi transport and interface disabled successfully");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error stopping WiFi transport",
                               LogContext().add("error", e.what()));
                return false;
            }
        }

        bool MitaRouter::setup_ble_transport()
        {
            // Check if BLE is enabled in configuration
            if (!config_->ble.enabled)
            {
                logger_->info("BLE transport disabled in configuration");
                return false;
            }

            try
            {
                logger_->info("Setting up BLE transport...");

                // use new BLE transport with packet monitor
                auto ble_transport = std::make_unique<transports::ble::BLETransport>(
                    *config_, *routing_service_, *device_management_, *statistics_service_, packet_monitor_);

                if (ble_transport->start())
                {
                    std::lock_guard<std::mutex> lock(transports_mutex_);
                    transports_["ble"] = std::move(ble_transport);
                    logger_->info("BLE transport started successfully");
                    return true;
                }
                else
                {
                    logger_->error("Failed to start BLE transport");
                    return false;
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error setting up BLE transport",
                               LogContext().add("error", e.what()));
                return false;
            }
        }

        bool MitaRouter::start_ble_transport()
        {
            if (!running_)
            {
                logger_->warning("Cannot start BLE transport: router not running");
                return false;
            }

            std::lock_guard<std::mutex> lock(transports_mutex_);

            // Check if BLE is already running
            if (transports_.find("ble") != transports_.end())
            {
                logger_->info("BLE transport is already running");
                return true;
            }

            logger_->info("Starting BLE transport dynamically...");

            // Temporarily enable BLE in config
            config_->ble.enabled = true;

            // Release lock to avoid deadlock when calling setup
            transports_mutex_.unlock();
            bool success = setup_ble_transport();
            transports_mutex_.lock();

            if (success)
            {
                logger_->info("BLE transport started successfully");
            }
            else
            {
                logger_->error("Failed to start BLE transport");
                config_->ble.enabled = false;
            }

            return success;
        }

        bool MitaRouter::stop_ble_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);

            auto it = transports_.find("ble");
            if (it == transports_.end())
            {
                logger_->info("BLE transport is not running");
                return true;
            }

            logger_->info("Stopping BLE transport...");

            try
            {
                // Stop the transport
                it->second->stop();

                // Remove from transports map
                transports_.erase(it);

                // Update config
                config_->ble.enabled = false;

                logger_->info("BLE transport stopped successfully");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error stopping BLE transport",
                               LogContext().add("error", e.what()));
                return false;
            }
        }


        bool MitaRouter::setup_lora_transport()
        {
            if (!config_->lora.enabled)
            {
                logger_->info("LoRa transport disabled in configuration");
                return false;
            }

            try
            {
                logger_->info("Setting up LoRa transport...");

                auto lora_transport = std::make_unique<transports::lora::LoRaTransport>(
                    *config_, *routing_service_, *device_management_, *statistics_service_, packet_monitor_);

                if (lora_transport->start())
                {
                    std::lock_guard<std::mutex> lock(transports_mutex_);
                    transports_["lora"] = std::move(lora_transport);
                    logger_->info("LoRa transport started successfully");
                    return true;
                }
                else
                {
                    logger_->error("Failed to start LoRa transport");
                    return false;
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error setting up LoRa transport",
                               LogContext().add("error", e.what()));
                return false;
            }
        }

        bool MitaRouter::start_lora_transport()
        {
            if (!running_)
            {
                logger_->warning("Cannot start LoRa transport: router not running");
                return false;
            }

            std::lock_guard<std::mutex> lock(transports_mutex_);

            if (transports_.find("lora") != transports_.end())
            {
                logger_->info("LoRa transport is already running");
                return true;
            }

            config_->lora.enabled = true;

            // Release lock to avoid deadlock when calling setup
            transports_mutex_.unlock();
            bool success = setup_lora_transport();
            transports_mutex_.lock();

            if (success)
            {
                logger_->info("LoRa transport started successfully");
            }
            else
            {
                logger_->error("Failed to start LoRa transport");
                config_->lora.enabled = false;
            }

            return success;
        }

        bool MitaRouter::stop_lora_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);

            auto it = transports_.find("lora");
            if (it == transports_.end())
            {
                logger_->info("LoRa transport is not running");
                return true;
            }

            logger_->info("Stopping LoRa transport...");

            try
            {

                it->second->stop();

                transports_.erase(it);

                config_->lora.enabled = false;

                logger_->info("LoRa transport stopped successfully");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error stopping LoRa transport",
                               LogContext().add("error", e.what()));
                return false;
            }
        }

        core::TransportInterface* MitaRouter::get_lora_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);
            auto it = transports_.find("lora");
            return (it != transports_.end()) ? it->second.get() : nullptr;
        }


        bool MitaRouter::is_transport_running(const std::string& transport_name) const
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);
            return transports_.find(transport_name) != transports_.end();
        }

        void MitaRouter::start_background_tasks()
        {
            // Start main loop thread
            main_loop_thread_ = std::make_unique<std::thread>(&MitaRouter::run_main_loop, this);

            // Start status monitoring thread if enabled
            if (config_->logging.status_interval > 0)
            {
                status_thread_ = std::make_unique<std::thread>(&MitaRouter::run_status_monitor, this);
                logger_->debug("Status monitoring thread started",
                               LogContext().add("interval_seconds", config_->logging.status_interval));
            }
        }

        void MitaRouter::run_main_loop()
        {
            logger_->info("Router main loop started");

            try 
            {
                while (running_)
                {
                    // Perform periodic maintenance
                    periodic_maintenance();

                    // Sleep for cleanup interval
                    std::unique_lock<std::mutex> lock(shutdown_mutex_);
                    shutdown_cv_.wait_for(lock, std::chrono::seconds(config_->routing.cleanup_interval),
                                        [this] { return !running_; });
                }

            } catch (const std::exception &e)
            {
                logger_->error("Error in main loop",
                            LogContext().add("error", e.what()));
            }

            logger_->info("Router main loop stopped");
        }

        void MitaRouter::run_status_monitor()
        {
            logger_->debug("Status monitor started");

            while (running_)
            {
                try
                {
                    log_status();

                    //sleep for status interval
                    std::unique_lock<std::mutex> lock(shutdown_mutex_);
                    shutdown_cv_.wait_for(lock, std::chrono::seconds(config_->logging.status_interval),
                                        [this] { return !running_; });
                }
                catch(const std::exception& e)
                 {
                    logger_->error("Error in status monitor",
                                   LogContext().add("error", e.what()));
                    std::this_thread::sleep_for(std::chrono::seconds(10)); // Wait before retrying
                }
            }
        }

        void MitaRouter::periodic_maintenance()
        {
            try
            {
                // Clean up stale routes
                if (routing_service_)
                {
                    int removed_routes = routing_service_->cleanup_stale_routes(
                        std::chrono::seconds(config_->routing.device_timeout));

                    if (removed_routes > 0)
                    {
                        logger_->info("Cleaned up stale routes",
                                      LogContext().add("removed_count", removed_routes));
                    }
                }

                // Clean up inactive devices
                if (device_management_)
                {
                    int removed_devices = device_management_->cleanup_inactive_devices(
                        std::chrono::seconds(config_->routing.device_timeout));

                    if (removed_devices > 0)
                    {
                        logger_->info("Cleaned up inactive devices",
                                      LogContext().add("removed_count", removed_devices));
                    }

                    // Update periodic statistics
                    device_management_->periodic_maintenance();
                }

                // Update statistics
                if (statistics_service_)
                {
                    statistics_service_->update_periodic_stats();
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error in periodic maintenance",
                               LogContext().add("error", e.what()));
            }
        }

        void MitaRouter::log_status()
        {
            try
            {
                // Get current statistics
                auto stats = get_statistics();
                auto devices = get_connected_devices();

                // Log summary
                logger_->info("Router Status",
                              LogContext().add("devices", devices.size()).add("packets_routed", stats["packets_routed"]).add("packets_dropped", stats["packets_dropped"]).add("bytes_transferred", stats["bytes_transferred"]).add("handshakes", stats["handshakes_completed"]).add("errors", stats["errors"]));

                // Log device details in debug mode
                if (logger_->is_enabled(LogLevel::DEBUG))
                {
                    for (const auto &[device_id, device_info] : devices)
                    {
                        logger_->debug("Connected device",
                                       LogContext().add("device_id", device_id).add("address", device_info.at("assigned_address")).add("transport", device_info.at("transport_type")).add("last_activity", device_info.at("last_activity_seconds")));
                    }
                }

                // Log transport status
                for (const auto &[name, transport] : transports_)
                {
                    auto connected_devices = transport->get_connected_devices();
                    logger_->debug("Transport status",
                                   LogContext().add("transport", name).add("connected_devices", connected_devices.size()));
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error logging status",
                               LogContext().add("error", e.what()));
            }
        }

        core::TransportInterface* MitaRouter::get_wifi_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);
            auto it = transports_.find("wifi");
            if (it != transports_.end())
            {
                return it->second.get();
            }
            return nullptr;
        }

        core::TransportInterface* MitaRouter::get_ble_transport()
        {
            std::lock_guard<std::mutex> lock(transports_mutex_);
            auto it = transports_.find("ble");
            if (it != transports_.end())
            {
                return it->second.get();
            }
            return nullptr;
        }

    } // namespace core
} // namespace mita