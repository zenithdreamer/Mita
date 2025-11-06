#include "transports/ble/ble_backend.hpp"
#include "core/logger.hpp"
#include "core/config.hpp"

#include <mutex>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace mita
{
    namespace transports
    {
        namespace ble
        {
            /**
             * BlueZ Peripheral Backend
             *
             * This implementation uses bluetoothctl commands to set up a GATT server
             * in peripheral mode. It's a simplified approach that works with existing
             * BlueZ infrastructure without requiring complex D-Bus programming.
             *
             * Maybe, in future might consider using proper BlueZ D-Bus API or gattlib.
             */
            class PeripheralBackend : public IBLEBackend
            {
            public:
                explicit PeripheralBackend(const core::RouterConfig &config)
                    : config_(config), logger_(core::get_logger("BLEPeripheral")),
                      advertising_(false), gatt_registered_(false) {}

                ~PeripheralBackend()
                {
                    stop_advertising();
                }

                // Central mode methods (not used in peripheral mode, but must implement interface)
                bool start_scan() override { return false; }
                void stop_scan() override {}
                std::vector<BLEDeviceInfo> list_devices() override { return {}; }
                bool connect(const std::string &address) override { return false; }
                bool disconnect(const std::string &address) override
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    auto it = std::find(connected_clients_.begin(), connected_clients_.end(), address);
                    if (it != connected_clients_.end())
                    {
                        connected_clients_.erase(it);
                        if (logger_)
                            logger_->info("Client disconnected", core::LogContext{}.add("address", address));
                        return true;
                    }
                    return false;
                }

                bool write_characteristic(
                    const std::string &address,
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    const std::vector<uint8_t> &data) override { return false; }

                bool enable_notifications(
                    const std::string &address,
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    std::function<void(const std::string &, const std::vector<uint8_t> &)> callback) override { return false; }

                bool has_service(const std::string &address, const std::string &service_uuid) override { return false; }

                // Peripheral mode methods
                bool start_advertising(const std::string &device_name) override
                {
                    if (advertising_)
                    {
                        if (logger_)
                            logger_->debug("Already advertising");
                        return true;
                    }

                    if (logger_)
                        logger_->info("Starting BLE advertising",
                                      core::LogContext{}
                                          .add("device_name", device_name)
                                          .add("service_uuid", config_.ble.service_uuid));

                    // First, unblock Bluetooth (RF-kill)
                    if (logger_)
                        logger_->info("Unblocking Bluetooth adapter...");

                    std::string cmd_unblock = "rfkill unblock bluetooth";
                    int ret_unblock = std::system(cmd_unblock.c_str());

                    if (ret_unblock != 0)
                    {
                        if (logger_)
                            logger_->warning("Failed to unblock Bluetooth (may need manual intervention)");
                    }

                    // Small delay to let rfkill apply
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));

                    // Bring up the Bluetooth adapter
                    if (logger_)
                        logger_->info("Bringing up Bluetooth adapter...");

                    std::string cmd_up = "hciconfig hci0 up";
                    int ret_up = std::system(cmd_up.c_str());

                    if (ret_up != 0)
                    {
                        if (logger_)
                            logger_->error("Failed to bring up Bluetooth adapter - may be RF-killed or missing");
                        return false;
                    }

                    // Small delay to let adapter initialize
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));

                    // Set device name and make discoverable using hciconfig
                    std::string cmd_name = "hciconfig hci0 name '" + device_name + "'";
                    std::string cmd_discoverable = "hciconfig hci0 piscan";

                    // Build advertising data: Flags + 128-bit Service UUID
                    // Format: length flags_type flags_value length uuid_type uuid_bytes...
                    std::string adv_data = "hcitool -i hci0 cmd 0x08 0x0008 ";

                    // Flags field
                    adv_data += "02 01 06 "; // Length=2, Type=Flags, Value=0x06

                    // 128-bit Complete Service UUID (config_.ble.service_uuid)
                    // UUID format: 4fafc201-1fb5-459e-8fcc-c5c9c331914b
                    // Need to reverse byte order for BLE
                    adv_data += "11 07 "; // Length=17 (1+16), Type=0x07 (Complete 128-bit UUID)

                    // Parse UUID and add in reverse byte order
                    std::string uuid = config_.ble.service_uuid;
                    // Remove dashes: 4fafc2011fb5459e8fccc5c9c331914b
                    uuid.erase(std::remove(uuid.begin(), uuid.end(), '-'), uuid.end());
                    // Add bytes in reverse order
                    for (int i = uuid.length() - 2; i >= 0; i -= 2)
                    {
                        adv_data += uuid.substr(i, 2) + " ";
                    }

                    // Build scan response data with the device name
                    std::string scan_rsp = "hcitool -i hci0 cmd 0x08 0x0009 ";

                    char len_hex[8];

                    // Scan response format: length_byte field1_len field1_type field1_data ...
                    int name_len = device_name.length();
                    int name_field_len = 1 + name_len; // Type (0x09) + name bytes

                    // Length of name field (type + data)
                    snprintf(len_hex, sizeof(len_hex), "%02x ", name_field_len);
                    scan_rsp += len_hex;

                    scan_rsp += "09 "; // Complete Local Name type

                    // Add device name as hex bytes
                    for (char c : device_name)
                    {
                        snprintf(len_hex, sizeof(len_hex), "%02x ", (unsigned char)c);
                        scan_rsp += len_hex;
                    }

                    // Enable advertising parameters for continuous advertising
                    std::string adv_params = "hcitool -i hci0 cmd 0x08 0x0006 00 08 00 08 00 00 00 00 00 00 00 00 00 07 00";
                    std::string cmd_leadv = "hcitool -i hci0 cmd 0x08 0x000a 01"; // Enable LE advertising

                    int ret1 = std::system(cmd_name.c_str());
                    int ret2 = std::system(cmd_discoverable.c_str());
                    int ret_adv = std::system(adv_data.c_str());      // Set BLE advertisement data
                    int ret_scan = std::system(scan_rsp.c_str());     // Set scan response data
                    int ret_params = std::system(adv_params.c_str()); // Set advertising parameters
                    int ret3 = std::system(cmd_leadv.c_str());

                    if (ret1 != 0 || ret2 != 0 || ret3 != 0 || ret_adv != 0 || ret_scan != 0 || ret_params != 0)
                    {
                        if (logger_)
                            logger_->warning("Some hciconfig commands failed",
                                             core::LogContext{}
                                                 .add("name_ret", ret1)
                                                 .add("piscan_ret", ret2)
                                                 .add("adv_data_ret", ret_adv)
                                                 .add("scan_rsp_ret", ret_scan)
                                                 .add("adv_params_ret", ret_params)
                                                 .add("leadv_ret", ret3));
                    }

                    advertising_ = true;

                    if (logger_)
                        logger_->info("BLE advertising started successfully",
                                      core::LogContext{}.add("device_name", device_name));

                    return true;
                }

                void stop_advertising() override
                {
                    if (!advertising_)
                        return;

                    if (logger_)
                        logger_->info("Stopping BLE advertising");

                    std::system("hciconfig hci0 noscan");
                    advertising_ = false;

                    if (logger_)
                        logger_->info("BLE advertising stopped");
                }

                bool register_gatt_service(
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    std::function<void(const std::string &, const std::vector<uint8_t> &)> on_write,
                    std::function<std::vector<uint8_t>(const std::string &)> on_read) override
                {
                    std::lock_guard<std::mutex> lock(gatt_mutex_);

                    if (logger_)
                        logger_->info("Registering GATT service",
                                      core::LogContext{}
                                          .add("service_uuid", service_uuid)
                                          .add("char_uuid", char_uuid));

                    // Store callbacks
                    write_callback_ = on_write;
                    read_callback_ = on_read;
                    service_uuid_ = service_uuid;
                    char_uuid_ = char_uuid;

                    gatt_registered_ = true;

                    // Note: would use BlueZ D-Bus API to properly register
                    // a GATT service with characteristics. This simplified implementation
                    // relies on the system's existing GATT setup or manual configuration.

                    if (logger_)
                        logger_->info("GATT service registered (simplified mode)");

                    return true;
                }

                bool notify_characteristic(
                    const std::string &client_address,
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    const std::vector<uint8_t> &data) override
                {
                    // In a full implementation, this would send a GATT notification
                    // For now, log the attempt
                    if (logger_)
                        logger_->debug("Notify characteristic",
                                       core::LogContext{}
                                           .add("client", client_address)
                                           .add("data_size", data.size()));

                    // Check if client is connected
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    auto it = std::find(connected_clients_.begin(), connected_clients_.end(), client_address);
                    if (it == connected_clients_.end())
                    {
                        if (logger_)
                            logger_->warning("Client not connected", core::LogContext{}.add("address", client_address));
                        return false;
                    }

                    return true;
                }

                std::vector<std::string> get_connected_clients() override
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    return connected_clients_;
                }

                // Helper to simulate client connection (called when data received)
                void add_client(const std::string &address)
                {
                    std::lock_guard<std::mutex> lock(clients_mutex_);
                    auto it = std::find(connected_clients_.begin(), connected_clients_.end(), address);
                    if (it == connected_clients_.end())
                    {
                        connected_clients_.push_back(address);
                        if (logger_)
                            logger_->info("New client connected", core::LogContext{}.add("address", address));
                    }
                }

                // Helper to process incoming data
                void process_write(const std::string &client_address, const std::vector<uint8_t> &data)
                {
                    std::lock_guard<std::mutex> lock(gatt_mutex_);
                    if (write_callback_)
                    {
                        write_callback_(client_address, data);
                    }
                }

            private:
                const core::RouterConfig &config_;
                std::shared_ptr<core::Logger> logger_;

                bool advertising_;
                bool gatt_registered_;

                std::string service_uuid_;
                std::string char_uuid_;

                std::function<void(const std::string &, const std::vector<uint8_t> &)> write_callback_;
                std::function<std::vector<uint8_t>(const std::string &)> read_callback_;

                std::vector<std::string> connected_clients_;
                std::mutex clients_mutex_;
                std::mutex gatt_mutex_;
            };

            std::unique_ptr<IBLEBackend> create_peripheral_backend(const core::RouterConfig &config)
            {
                auto backend = std::make_unique<PeripheralBackend>(config);
                return backend;
            }

        } // namespace ble
    } // namespace transports
} // namespace mita
