#ifndef MITA_BLE_DEVICE_HANDLER_HPP
#define MITA_BLE_DEVICE_HANDLER_HPP

#include "ble_backend.hpp"
#include "core/config.hpp"
#include "protocol/protocol.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "core/logger.hpp"
#include <string>
#include <atomic>
#include <memory>
#include <mutex>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            class BLEDeviceHandler
            {
            public:
                BLEDeviceHandler(
                    IBLEBackend *backend,
                    const std::string &device_address,
                    const core::RouterConfig &config,
                    services::RoutingService &routing_service,
                    services::DeviceManagementService &device_management,
                    services::StatisticsService &statistics_service);

                ~BLEDeviceHandler();

                BLEDeviceHandler(const BLEDeviceHandler &) = delete;
                BLEDeviceHandler &operator=(const BLEDeviceHandler &) = delete;

                bool connect();
                void disconnect();
                void process_notification(const std::vector<uint8_t> &data);
                bool send_packet(const protocol::ProtocolPacket &packet);

                bool is_connected() const { return connected_; }
                bool is_authenticated() const { return authenticated_; }
                const std::string &get_device_address() const { return device_address_; }
                const std::string &get_device_id() const { return device_id_; }
                uint16_t get_assigned_address() const { return assigned_address_; }

            private:
                void handle_handshake_packet(const protocol::ProtocolPacket &packet);
                void handle_data_packet(const protocol::ProtocolPacket &packet);

                const core::RouterConfig &config_;

                services::RoutingService &routing_service_;
                services::DeviceManagementService &device_management_;
                services::StatisticsService &statistics_service_;

                IBLEBackend *backend_;

                std::string device_address_;
                std::string device_id_;
                uint16_t assigned_address_;

                std::atomic<bool> connected_;
                std::atomic<bool> authenticated_;

                std::unique_ptr<protocol::HandshakeManager> handshake_manager_;
                std::shared_ptr<protocol::PacketCrypto> session_crypto_;
                std::mutex crypto_mutex_;

                std::shared_ptr<core::Logger> logger_;
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_DEVICE_HANDLER_HPP
