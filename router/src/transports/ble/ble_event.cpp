#include "transports/ble/ble_event.hpp"

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            BLEEvent BLEEvent::notification(const std::string &addr, const std::vector<uint8_t> &d)
            {
                BLEEvent event;
                event.type = BLEEventType::NOTIFICATION_RECEIVED;
                event.data = NotificationData{addr, d};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            BLEEvent BLEEvent::device_connected(const std::string &addr, const std::string &name)
            {
                BLEEvent event;
                event.type = BLEEventType::DEVICE_CONNECTED;
                event.data = DeviceConnectionData{addr, name};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            BLEEvent BLEEvent::device_disconnected(const std::string &addr, const std::string &reason)
            {
                BLEEvent event;
                event.type = BLEEventType::DEVICE_DISCONNECTED;
                event.data = DeviceDisconnectionData{addr, reason};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            BLEEvent BLEEvent::connection_failed(const std::string &addr, const std::string &reason)
            {
                BLEEvent event;
                event.type = BLEEventType::CONNECTION_FAILED;
                event.data = ErrorData{addr, reason, -1};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            BLEEvent BLEEvent::backend_error(const std::string &addr, const std::string &msg, int code)
            {
                BLEEvent event;
                event.type = BLEEventType::BACKEND_ERROR;
                event.data = ErrorData{addr, msg, code};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            BLEEvent BLEEvent::scan_complete()
            {
                BLEEvent event;
                event.type = BLEEventType::SCAN_CYCLE_COMPLETE;
                event.data = EmptyData{};
                event.timestamp = std::chrono::steady_clock::now();
                return event;
            }

            std::string BLEEvent::type_name() const
            {
                switch (type)
                {
                case BLEEventType::NOTIFICATION_RECEIVED:
                    return "NOTIFICATION_RECEIVED";
                case BLEEventType::DEVICE_CONNECTED:
                    return "DEVICE_CONNECTED";
                case BLEEventType::DEVICE_DISCONNECTED:
                    return "DEVICE_DISCONNECTED";
                case BLEEventType::SCAN_CYCLE_COMPLETE:
                    return "SCAN_CYCLE_COMPLETE";
                case BLEEventType::CONNECTION_FAILED:
                    return "CONNECTION_FAILED";
                case BLEEventType::BACKEND_ERROR:
                    return "BACKEND_ERROR";
                default:
                    return "UNKNOWN";
                }
            }

            int64_t BLEEvent::age_ms() const
            {
                auto now = std::chrono::steady_clock::now();
                return std::chrono::duration_cast<std::chrono::milliseconds>(now - timestamp).count();
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
