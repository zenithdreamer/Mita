#ifndef MITA_BLE_TRANSPORT_HPP
#define MITA_BLE_TRANSPORT_HPP

#include "core/transport_interface.hpp"
#include "ble_event_queue.hpp"
#include "ble_event_processor.hpp"
#include "ble_device_registry.hpp"
#include "ble_backend.hpp"
#include "core/logger.hpp"
#include <thread>
#include <atomic>
#include <memory>
#include <set>
#include <mutex>
#include <condition_variable>

namespace mita
{
    namespace services
    {
        class PacketMonitorService;
    }

    namespace transports
    {
        namespace ble
        {

            class BLETransport : public core::BaseTransport
            {
            public:
                BLETransport(
                    const core::RouterConfig &config,
                    services::RoutingService &routing_service,
                    services::DeviceManagementService &device_management,
                    services::StatisticsService &statistics_service,
                    std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);

                ~BLETransport();

                BLETransport(const BLETransport &) = delete;
                BLETransport &operator=(const BLETransport &) = delete;

                bool start() override;
                void stop() override;
                core::TransportType get_type() const override { return core::TransportType::BLE; }
                bool send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet) override;
                int broadcast_packet(const protocol::ProtocolPacket &packet) override;
                std::string get_connection_info() const override;
                std::vector<std::shared_ptr<BLEDeviceHandler>> get_all_device_handlers() const;

            private:
                bool initialize_backend();
                bool start_discovery();
                void stop_discovery();
                void scan_loop();
                void handle_device_found(const std::string &address, const std::string &name);
                bool connect_to_device(const std::string &address);
                bool device_has_service(const std::string &address);
                void on_notification_received(const std::string &address, const std::vector<uint8_t> &data);
                void check_heartbeat_timeouts();
                void cleanup_disconnected_devices();

                std::unique_ptr<IBLEBackend> backend_;
                BLEEventQueue event_queue_;
                BLEDeviceRegistry device_registry_;
                std::unique_ptr<BLEEventProcessor> event_processor_;

                std::unique_ptr<std::thread> scan_thread_;
                std::mutex scan_mutex_;
                std::condition_variable scan_cv_;

                std::set<std::string> seen_devices_;
                std::mutex seen_devices_mutex_;

                std::shared_ptr<core::Logger> logger_;
                std::shared_ptr<services::PacketMonitorService> packet_monitor_;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_TRANSPORT_HPP