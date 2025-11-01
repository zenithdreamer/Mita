#ifndef MITA_BLE_DEVICE_REGISTRY_HPP
#define MITA_BLE_DEVICE_REGISTRY_HPP

#include <map>
#include <memory>
#include <shared_mutex>
#include <optional>
#include <vector>
#include <string>

namespace mita
{
    namespace transports
    {
        namespace ble
        {
            class BLEDeviceHandler;

            class BLEDeviceRegistry
            {
            public:
                BLEDeviceRegistry() = default;
                ~BLEDeviceRegistry() = default;

                BLEDeviceRegistry(const BLEDeviceRegistry &) = delete;
                BLEDeviceRegistry &operator=(const BLEDeviceRegistry &) = delete;

                bool add_device(const std::string &address, std::shared_ptr<BLEDeviceHandler> handler);
                bool remove_device(const std::string &address);
                std::shared_ptr<BLEDeviceHandler> get_device(const std::string &address) const;
                std::shared_ptr<BLEDeviceHandler> find_by_device_id(const std::string &device_id) const;
                std::vector<std::shared_ptr<BLEDeviceHandler>> get_all_devices() const;
                std::vector<std::shared_ptr<BLEDeviceHandler>> get_authenticated_devices() const;
                bool has_device(const std::string &address) const;
                size_t device_count() const;
                size_t remove_disconnected();
                void clear();
                int get_device_count() const;

            private:
                mutable std::shared_mutex mutex_;
                std::map<std::string, std::shared_ptr<BLEDeviceHandler>> devices_;
                size_t device_count_;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_DEVICE_REGISTRY_HPP
