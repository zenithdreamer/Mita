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

namespace mita {
namespace core {
class RouterConfig;
class Logger;
}
namespace services {
class RoutingService;
class DeviceManagementService;
class StatisticsService;
}
}

namespace mita {
namespace transports {

/**
 * WiFi transport implementation using TCP sockets
 * Handles WiFi Access Point and client connections
 */
class WiFiTransport : public core::BaseTransport {
public:
    WiFiTransport(const core::RouterConfig& config,
                 services::RoutingService& routing_service,
                 services::DeviceManagementService& device_management,
                 services::StatisticsService& statistics_service);
    ~WiFiTransport();

    // TransportInterface implementation
    bool start() override;
    void stop() override;
    core::TransportType get_type() const override { return core::TransportType::WIFI; }
    bool send_packet(const std::string& device_id, const protocol::ProtocolPacket& packet) override;
    int broadcast_packet(const protocol::ProtocolPacket& packet) override;
    std::string get_connection_info() const override;

private:
    void accept_connections();
    void handle_new_client(int client_socket, const sockaddr_in& client_addr);
    void cleanup_disconnected_clients();
    WiFiClientHandler* find_client_handler(const std::string& device_id);
    bool receive_hello_packet(int socket, protocol::ProtocolPacket& packet, int timeout_ms);
    // Server socket
    int server_socket_;
    sockaddr_in server_addr_;

    // Client management
    std::mutex clients_mutex_;
    std::map<std::string, std::unique_ptr<WiFiClientHandler>> client_handlers_;

    // Threading
    std::unique_ptr<std::thread> accept_thread_;

    std::shared_ptr<core::Logger> logger_;
};

} // namespace transports
} // namespace mita

#endif // MITA_ROUTER_WIFI_TRANSPORT_HPP