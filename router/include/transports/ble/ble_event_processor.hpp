#ifndef MITA_BLE_EVENT_PROCESSOR_HPP
#define MITA_BLE_EVENT_PROCESSOR_HPP

#include "ble_event.hpp"
#include "ble_event_queue.hpp"
#include "ble_device_registry.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include <thread>
#include <atomic>
#include <memory>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            class BLEEventProcessor
            {
            public:
                BLEEventProcessor(
                    BLEEventQueue &event_queue,
                    BLEDeviceRegistry &device_registry,
                    services::RoutingService &routing_service,
                    services::DeviceManagementService &device_management,
                    services::StatisticsService &statistics_service);

                ~BLEEventProcessor();

                BLEEventProcessor(const BLEEventProcessor &) = delete;
                BLEEventProcessor &operator=(const BLEEventProcessor &) = delete;

                bool start();
                void stop();

                bool is_running() const { return running_; }
                size_t events_processed() const { return events_processed_; }
                size_t events_failed() const { return events_failed_; }

            private:
                void processing_loop();
                void handle_notification(const NotificationData &data);
                void handle_device_connected(const DeviceConnectionData &data);
                void handle_device_disconnected(const DeviceDisconnectionData &data);
                void handle_error(const ErrorData &data);
                void handle_scan_complete();

                BLEEventQueue &event_queue_;
                BLEDeviceRegistry &device_registry_;
                services::RoutingService &routing_service_;
                services::DeviceManagementService &device_management_;
                services::StatisticsService &statistics_service_;

                std::unique_ptr<std::thread> processor_thread_;
                std::atomic<bool> running_{false};

                std::atomic<size_t> events_processed_{0};
                std::atomic<size_t> events_failed_{0};

                std::shared_ptr<core::Logger> logger_;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_EVENT_PROCESSOR_HPP
