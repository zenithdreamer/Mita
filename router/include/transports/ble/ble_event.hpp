#ifndef MITA_BLE_EVENT_HPP
#define MITA_BLE_EVENT_HPP

#include <string>
#include <vector>
#include <chrono>
#include <variant>
#include <memory>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            enum class BLEEventType
            {
                NOTIFICATION_RECEIVED,
                DEVICE_CONNECTED,
                DEVICE_DISCONNECTED,
                SCAN_CYCLE_COMPLETE,
                CONNECTION_FAILED,
                BACKEND_ERROR
            };

            struct NotificationData
            {
                std::string device_address;
                std::vector<uint8_t> data;
            };

            struct DeviceConnectionData
            {
                std::string device_address;
                std::string device_name;
            };

            struct DeviceDisconnectionData
            {
                std::string device_address;
                std::string reason;
            };

            struct ErrorData
            {
                std::string device_address;
                std::string error_message;
                int error_code;
            };

            struct EmptyData
            {
            };

            using BLEEventData = std::variant<
                NotificationData,
                DeviceConnectionData,
                DeviceDisconnectionData,
                ErrorData,
                EmptyData>;

            struct BLEEvent
            {
                BLEEventType type;
                BLEEventData data;
                std::chrono::steady_clock::time_point timestamp;

                static BLEEvent notification(const std::string &addr, const std::vector<uint8_t> &d);
                static BLEEvent device_connected(const std::string &addr, const std::string &name);
                static BLEEvent device_disconnected(const std::string &addr, const std::string &reason);
                static BLEEvent connection_failed(const std::string &addr, const std::string &reason);
                static BLEEvent backend_error(const std::string &addr, const std::string &msg, int code);
                static BLEEvent scan_complete();

                std::string type_name() const;
                int64_t age_ms() const;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_EVENT_HPP
