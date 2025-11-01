#include "transports/ble/ble_backend.hpp"
#include "core/logger.hpp"
#include "core/config.hpp"

#include <simpleble/Adapter.h>
#include <simpleble/Peripheral.h>

#include <mutex>
#include <unordered_map>
#include <optional>
#include <thread>
#include <chrono>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            class SimpleBleBackend : public IBLEBackend
            {
            public:
                explicit SimpleBleBackend(const core::RouterConfig &config)
                    : config_(config), logger_(core::get_logger("SimpleBLE")) {}

                bool initialize()
                {
                    try
                    {
                        auto adapters = SimpleBLE::Adapter::get_adapters();
                        if (adapters.empty())
                        {
                            if (logger_)
                                logger_->error("No BLE adapters found");
                            return false;
                        }
                        adapter_ = adapters.front();

                        if (!adapter_.initialized())
                        {
                            if (logger_)
                                logger_->error("BLE adapter failed to initialize");
                            return false;
                        }

                        if (logger_)
                            logger_->info("Using BLE adapter", core::LogContext{}.add("identifier", adapter_.identifier()).add("address", adapter_.address()));
                        return true;
                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->error("initialize failed", core::LogContext{}.add("error", e.what()));
                        return false;
                    }
                }

                bool start_scan() override
                {
                    try
                    {
                        if (!adapter_.initialized())
                            return false;

                        if (scanning_)
                        {
                            if (logger_)
                                logger_->debug("BLE scan already active");
                            return true;
                        }

                        if (logger_)
                            logger_->info("Starting BLE scan with shorter timeout...");

                        adapter_.scan_start();
                        scanning_ = true;


                        std::this_thread::sleep_for(std::chrono::milliseconds(200));

                        if (logger_)
                            logger_->info("BLE scan started successfully");
                        return true;
                    }
                    catch (const std::exception &e)
                    {
                        std::string error_msg = e.what();

                        if (error_msg.find("InProgress") != std::string::npos)
                        {
                            scanning_ = true;
                            if (logger_)
                                logger_->info("BLE scan already active (InProgress) - continuing");
                            return true;
                        }

                        if (error_msg.find("NoReply") != std::string::npos || error_msg.find("timeout") != std::string::npos)
                        {
                            if (logger_)
                                logger_->warning("D-Bus timeout starting scan - will retry on next attempt", core::LogContext{}.add("error", error_msg));
                            return false;
                        }

                        if (logger_)
                            logger_->error("start_scan failed", core::LogContext{}.add("error", error_msg));
                        return false;
                    }
                }
                void stop_scan() override
                {
                    try
                    {
                        if (adapter_.initialized() && scanning_)
                        {
                            adapter_.scan_stop();
                            scanning_ = false;
                            if (logger_)
                                logger_->info("BLE scanning stopped");
                        }
                    }
                    catch (...)
                    {
                        scanning_ = false;
                    }
                }

                std::vector<BLEDeviceInfo> list_devices() override
                {
                    std::vector<BLEDeviceInfo> out;
                    if (!adapter_.initialized())
                        return out;

                    try
                    {
                        if (logger_)
                            logger_->debug("Checking BLE scan status...");

                        if (!scanning_)
                        {
                            if (logger_)
                                logger_->info("Starting SimpleBLE scan...");

                            adapter_.scan_start();
                            scanning_ = true;

                            std::this_thread::sleep_for(std::chrono::milliseconds(4000));

                            if (logger_)
                                logger_->info("SimpleBLE scan initialized");
                        }
                        else
                        {

                            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                        }

                        // get current scan results
                        auto results = adapter_.scan_get_results();

                        if (logger_)
                            logger_->info("SimpleBLE scan results", core::LogContext{}.add("devices_found", results.size()));

                        for (auto &p : results)
                        {
                            // use identifier as name if available (properly not available maybe libary issue(esp) or I am drunk), otherwise use address
                            std::string name = p.identifier().empty() ? p.address() : p.identifier();
                            BLEDeviceInfo info{p.address(), name};
                            out.push_back(info);
  
                            peripherals_[p.address()] = p;

                            if (logger_)
                                logger_->info("SimpleBLE found device", core::LogContext{}.add("address", p.address()).add("identifier", p.identifier()).add("name_used", name).add("connectable", p.is_connectable()));
                        }


                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->error("BLE scan failed", core::LogContext{}.add("error", e.what()));
                        if (std::string(e.what()).find("InProgress") == std::string::npos)
                        {
                            scanning_ = false;
                        }
                    }
                    return out;
                }

                bool connect(const std::string &address) override
                {
                    auto dev = get_or_refresh_peripheral(address);
                    if (!dev.has_value())
                        return false;
                    try
                    {
                        if (!dev->is_connected())
                            dev->connect();
                        (void)dev->services();
                        peripherals_[address] = *dev;
                        return true;
                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->error("connect failed", core::LogContext{}.add("address", address).add("error", e.what()));
                        return false;
                    }
                }

                bool disconnect(const std::string &address) override
                {
                    auto it = peripherals_.find(address);
                    if (it == peripherals_.end())
                        return false;
                    try
                    {
                        if (it->second.is_connected())
                            it->second.disconnect();
                        return true;
                    }
                    catch (...)
                    {
                        return false;
                    }
                }

                bool write_characteristic(const std::string &address, const std::string &service_uuid,
                                          const std::string &char_uuid, const std::vector<uint8_t> &data) override
                {
                    auto dev = get_or_refresh_peripheral(address);
                    if (!dev.has_value())
                        return false;
                    try
                    {
                        dev->write_command(service_uuid, char_uuid, data);
                        return true;
                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->error("write failed", core::LogContext{}.add("error", e.what()));
                        return false;
                    }
                }

                bool enable_notifications(const std::string &address, const std::string &service_uuid,
                                          const std::string &char_uuid,
                                          std::function<void(const std::string &, const std::vector<uint8_t> &)> cb) override
                {
                    auto dev = get_or_refresh_peripheral(address);
                    if (!dev.has_value())
                    {
                        if (logger_)
                            logger_->error("Device not found for notifications", core::LogContext{}.add("address", address));
                        return false;
                    }
                    try
                    {
                        if (logger_)
                            logger_->info("Setting up notifications...", core::LogContext{}.add("address", address).add("service_uuid", service_uuid).add("char_uuid", char_uuid));


                        if (!dev->is_connected())
                        {
                            if (logger_)
                                logger_->error("Device not connected for notifications", core::LogContext{}.add("address", address));
                            return false;
                        }


                        auto services = dev->services();
                        if (logger_)
                            logger_->info("Available services", core::LogContext{}.add("count", services.size()));

                        for (auto &service : services)
                        {
                            if (logger_)
                                logger_->debug("Service found", core::LogContext{}.add("uuid", service.uuid()));
                        }

                        dev->notify(service_uuid, char_uuid,
                                    [address, cb](SimpleBLE::ByteArray bytes)
                                    {
                                        if (cb)
                                            cb(address, std::vector<uint8_t>(bytes.begin(), bytes.end()));
                                    });

                        peripherals_[address] = *dev;

                        if (logger_)
                            logger_->info("Notifications enabled successfully", core::LogContext{}.add("address", address));
                        return true;
                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->error("enable_notifications failed", core::LogContext{}.add("address", address).add("error", e.what()));
                        return false;
                    }
                }

                bool has_service(const std::string &address, const std::string &service_uuid) override
                {
                    auto dev = get_or_refresh_peripheral(address);
                    if (!dev.has_value())
                    {
                        if (logger_)
                            logger_->debug("Device not found in scan results", core::LogContext{}.add("address", address));
                        return false;
                    }

                    try
                    {
                        // get advertised services to verify its our esp device (I use this for now since identifier isnt working)
                        auto services = dev->services();

                        for (auto &service : services)
                        {
                            if (logger_)

                                if (service.uuid() == service_uuid)
                                {
                                    if (logger_)
                                        logger_->info("Device HAS required service - MATCH!", core::LogContext{}
                                                                                                 .add("address", address)
                                                                                                 .add("service_uuid", service_uuid));
                                    return true;
                                }
                        }

                        if (logger_)
                            logger_->info("Device does NOT have required service", core::LogContext{}
                                                                                       .add("address", address)
                                                                                       .add("required_uuid", service_uuid));
                        return false;
                    }
                    catch (const std::exception &e)
                    {
                        if (logger_)
                            logger_->warning("Exception checking services", core::LogContext{}
                                                                                .add("address", address)
                                                                                .add("error", e.what()));
                        return false;
                    }
                }

            private:
                std::optional<SimpleBLE::Peripheral> get_or_refresh_peripheral(const std::string &address)
                {
                    auto it = peripherals_.find(address);
                    if (it != peripherals_.end())
                        return it->second;

                    if (!adapter_.initialized())
                        return std::nullopt;
                    auto results = adapter_.scan_get_results();
                    for (auto &p : results)
                    {
                        peripherals_[p.address()] = p;
                        if (p.address() == address)
                            return p;
                    }
                    return std::nullopt;
                }

                const core::RouterConfig &config_;
                SimpleBLE::Adapter adapter_;
                std::unordered_map<std::string, SimpleBLE::Peripheral> peripherals_;
                std::shared_ptr<core::Logger> logger_;
                bool scanning_ = false;
            };


            std::unique_ptr<IBLEBackend> create_simplebluez_backend(const core::RouterConfig &cfg)
            {
                auto backend = std::make_unique<SimpleBleBackend>(cfg);
                if (!backend->initialize())
                    return nullptr;
                return backend;
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
