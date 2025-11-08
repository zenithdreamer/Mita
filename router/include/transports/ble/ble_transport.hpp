#ifndef MITA_ROUTER_BLE_TRANSPORT_HPP
#define MITA_ROUTER_BLE_TRANSPORT_HPP

#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"
#include "transports/ble/ble_l2cap_server.hpp"
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <memory>

namespace mita
{
    namespace core
    {
        class RouterConfig;
        class Logger;
    }
    namespace services
    {
        class RoutingService;
        class DeviceManagementService;
        class StatisticsService;
        class PacketMonitorService;
    }
}

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            class CoCClientHandler
            {
            public:
                CoCClientHandler(int client_fd,
                                 const std::string &device_address,
                                 const core::RouterConfig &config,
                                 services::RoutingService &routing_service,
                                 services::DeviceManagementService &device_management,
                                 services::StatisticsService &statistics_service,
                                 std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);
                ~CoCClientHandler();

                bool is_connected() const { return connected_; }
                bool is_authenticated() const { return authenticated_; }
                const std::string &get_device_id() const { return device_id_; }
                const std::string &get_device_address() const { return device_address_; }
                uint16_t get_assigned_address() const { return assigned_address_; }
                int get_client_fd() const { return client_fd_; }

                bool send_packet(const protocol::ProtocolPacket &packet);
                void handle_received_data(const uint8_t *data, size_t length);
                void disconnect();

            private:
                void handle_packet(const protocol::ProtocolPacket &packet);
                void handle_handshake_packet(const protocol::ProtocolPacket &packet);
                void handle_data_packet(const protocol::ProtocolPacket &packet);

                const core::RouterConfig &config_;
                services::RoutingService &routing_service_;
                services::DeviceManagementService &device_management_;
                services::StatisticsService &statistics_service_;

                int client_fd_;
                std::string device_address_;
                std::string device_id_;
                uint16_t assigned_address_;

                bool connected_;
                bool authenticated_;

                std::unique_ptr<protocol::HandshakeManager> handshake_manager_;
                std::shared_ptr<protocol::PacketCrypto> session_crypto_;

                std::vector<uint8_t> receive_buffer_;
                std::shared_ptr<services::PacketMonitorService> packet_monitor_;
                std::shared_ptr<core::Logger> logger_;
            };

            class BLETransport : public core::BaseTransport
            {
            public:
                BLETransport(const core::RouterConfig &config,
                             services::RoutingService &routing_service,
                             services::DeviceManagementService &device_management,
                             services::StatisticsService &statistics_service,
                             std::shared_ptr<services::PacketMonitorService> packet_monitor);
                ~BLETransport() override;

                bool start() override;
                void stop() override;
                bool send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet) override;
                int broadcast_packet(const protocol::ProtocolPacket &packet) override;
                std::string get_connection_info() const override;
                core::TransportType get_type() const override { return core::TransportType::BLE; }

                // For API compatibility
                std::vector<std::pair<std::string, std::string>> get_all_device_handlers() const;

            private:
                std::unique_ptr<BLEL2CAPServer> l2cap_server_;

                std::map<int, std::unique_ptr<CoCClientHandler>> client_handlers_;
                std::mutex handlers_mutex_;

                std::map<std::string, int> device_id_to_fd_;
                std::mutex device_map_mutex_;

                void on_client_connected(int client_fd, const std::string &device_addr);
                void on_client_disconnected(int client_fd, const std::string &device_addr);
                void on_data_received(int client_fd, const std::string &device_addr, const uint8_t *data, size_t length);

                // Bluetooth adapter management
                bool enable_bluetooth_adapter();
                void disable_bluetooth_adapter();
                void ensure_advertising();
                void advertising_watchdog_loop();

                std::shared_ptr<services::PacketMonitorService> packet_monitor_;
                std::shared_ptr<core::Logger> logger_;
                std::atomic<bool> running_;
                std::thread advertising_watchdog_thread_;
            };

        }
    }
}

#endif
