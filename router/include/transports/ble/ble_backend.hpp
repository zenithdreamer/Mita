#ifndef MITA_BLE_BACKEND_HPP
#define MITA_BLE_BACKEND_HPP

#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace mita
{
    namespace core
    {
        struct RouterConfig;
    }

    namespace transports
    {
        namespace ble
        {


            struct BLEDeviceInfo
            {
                std::string address;
                std::string name;
            };

            class IBLEBackend
            {
            public:
                virtual ~IBLEBackend() = default;

                virtual bool start_scan() = 0;
                virtual void stop_scan() = 0;
                virtual std::vector<BLEDeviceInfo> list_devices() = 0;
                virtual bool connect(const std::string &address) = 0;
                virtual bool disconnect(const std::string &address) = 0;
                virtual bool write_characteristic(
                    const std::string &address,
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    const std::vector<uint8_t> &data) = 0;
                virtual bool enable_notifications(
                    const std::string &address,
                    const std::string &service_uuid,
                    const std::string &char_uuid,
                    std::function<void(const std::string &, const std::vector<uint8_t> &)> callback) = 0;
                virtual bool has_service(const std::string &address, const std::string &service_uuid) = 0;
            };

            std::unique_ptr<IBLEBackend> create_simplebluez_backend(const core::RouterConfig &config);

        } // namespace ble
    }  // namespace transports
} // namespace mita

#endif // MITA_BLE_BACKEND_HPP
