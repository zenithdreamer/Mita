#ifndef MITA_ROUTER_WIFI_TRANSPORT_HPP
#define MITA_ROUTER_WIFI_TRANSPORT_HPP

#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"
#include "transports/wifi_client_handler.hpp"
#include <thread>
#include <atomic>
#include <map>
#include <mutex>
#include <memory>

// Linux networking
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unordered_map>

namespace mita {
namespace core {
class RouterConfig;
class Logger;
}
namespace services {
class RoutingService;
class DeviceManagementService;
class StatisticsService;
class PacketMonitorService;
}
}

namespace mita {
namespace transports {

    /**
     * WiFi transport implementation
     * Handles WiFi Access Point and client connections using custom IP protocol
     */
    class WiFiTransport : public core::BaseTransport
    {
    public:
        WiFiTransport(const core::RouterConfig &config,
                      services::RoutingService &routing_service,
                      services::DeviceManagementService &device_management,
                      services::StatisticsService &statistics_service,
                      std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);
        ~WiFiTransport();

        // TransportInterface implementation
        bool start() override;
        void stop() override;
        core::TransportType get_type() const override { return core::TransportType::WIFI; }
        bool send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet) override;
        int broadcast_packet(const protocol::ProtocolPacket &packet) override;
        std::string get_connection_info() const override;
        std::vector<WiFiClientHandler *> get_all_client_handlers() const;

    private:
        void receive_packets();
        void handle_packet_from_ip(const std::string &source_ip, const uint8_t *data, size_t length);
        void cleanup_disconnected_clients();
        WiFiClientHandler *find_client_handler(const std::string &device_id);
        WiFiClientHandler *find_client_by_ip(const std::string &ip_address);

        // Raw IP packet handling
        bool send_raw_packet(const std::string &dest_ip, const uint8_t *data, size_t length);

        // Raw socket
        int raw_socket_;
        std::string local_ip_;    // Router's local IP address (main network interface)
        std::string wifi_ap_ip_;  // WiFi AP interface IP address

        // Client management (maps device_id to handler)
        mutable std::recursive_mutex clients_mutex_; // Recursive to allow reentrant calls from handler callbacks
        std::map<std::string, std::unique_ptr<WiFiClientHandler>> client_handlers_;

        // IP to device_id mapping
        std::unordered_map<std::string, std::string> ip_to_device_;

        // Threading
        std::unique_ptr<std::thread> receive_thread_;

        std::shared_ptr<core::Logger> logger_;
        std::shared_ptr<services::PacketMonitorService> packet_monitor_;
    };

} // namespace transports
} // namespace mita

#endif // MITA_ROUTER_WIFI_TRANSPORT_HPP