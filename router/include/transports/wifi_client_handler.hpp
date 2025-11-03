#ifndef MITA_ROUTER_WIFI_CLIENT_HANDLER_HPP
#define MITA_ROUTER_WIFI_CLIENT_HANDLER_HPP

#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"
#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <optional>

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
class PacketMonitorService;
}
}

namespace mita {
namespace transports {

/**
 * WiFi client connection handler
 * Manages individual client connections and handshakes
 */
class WiFiClientHandler {
public:
    WiFiClientHandler(int client_socket, const sockaddr_in& client_addr,
                     const core::RouterConfig& config,
                     services::RoutingService& routing_service,
                     services::DeviceManagementService& device_management,
                     services::StatisticsService& statistics_service,
                     std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);
    ~WiFiClientHandler();

    void start(std::optional<protocol::ProtocolPacket> initial_hello = std::nullopt);
    void stop();
    void reconnect(int new_socket, const sockaddr_in& new_addr,
                   const protocol::ProtocolPacket& hello_packet);

    bool is_authenticated() const { return authenticated_; }
    bool is_running() const { return running_; }
    const std::string& get_device_id() const { return device_id_; }
    uint16_t get_assigned_address() const { return assigned_address_; }

    // Packet transmission
    bool send_packet(const protocol::ProtocolPacket& packet);

private:
    void handle_client();
    bool receive_packet(protocol::ProtocolPacket& packet, int timeout_ms = 5000);
    void handle_handshake_packet(const protocol::ProtocolPacket& packet);
    void handle_data_packet(const protocol::ProtocolPacket& packet);
    void cleanup();

    // Network
    int client_socket_;
    sockaddr_in client_addr_;
    std::string client_address_str_;

    // Configuration and services
    const core::RouterConfig& config_;
    services::RoutingService& routing_service_;
    services::DeviceManagementService& device_management_;
    services::StatisticsService& statistics_service_;
    std::shared_ptr<services::PacketMonitorService> packet_monitor_;

    // Client state
    std::string device_id_;
    uint16_t assigned_address_;
    std::unique_ptr<protocol::PacketCrypto> session_crypto_;
    std::unique_ptr<protocol::HandshakeManager> handshake_manager_;
    bool authenticated_;
    std::atomic<bool> running_;
    std::optional<protocol::ProtocolPacket> pending_hello_;

    // Threading
    std::unique_ptr<std::thread> handler_thread_;

    std::shared_ptr<core::Logger> logger_;
};

} // namespace transports
} // namespace mita

#endif // MITA_ROUTER_WIFI_CLIENT_HANDLER_HPP
