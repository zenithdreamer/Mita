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
     * Manages individual client connections and handshakes using IP addresses
     */
    class WiFiClientHandler
    {
    public:
        WiFiClientHandler(const std::string &client_ip,
                          const core::RouterConfig &config,
                          services::RoutingService &routing_service,
                          services::DeviceManagementService &device_management,
                          services::StatisticsService &statistics_service,
                          std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);
        ~WiFiClientHandler();

        void start(const protocol::ProtocolPacket &initial_hello);
        void stop();
        void handle_packet(const protocol::ProtocolPacket &packet);

        bool is_authenticated() const { return authenticated_; }
        bool is_running() const { return running_; }
        const std::string &get_device_id() const { return device_id_; }
        const std::string &get_client_ip() const { return client_ip_; }
        uint16_t get_assigned_address() const { return assigned_address_; }

        bool check_heartbeat_timeout();
        bool check_for_disconnected() const;
        std::chrono::steady_clock::time_point get_disconnect_time() const;

        // Packet transmission (called from transport with raw socket)
        bool send_packet(const protocol::ProtocolPacket &packet);
        void set_send_callback(std::function<bool(const std::string &, const uint8_t *, size_t)> callback);

    private:
        void handle_handshake_packet(const protocol::ProtocolPacket &packet);
        void handle_data_packet(const protocol::ProtocolPacket &packet);
        void handle_heartbeat_packet(const protocol::ProtocolPacket &packet);
        void update_heartbeat();
        void cleanup();

        // Network
        std::string client_ip_;
        std::function<bool(const std::string &, const uint8_t *, size_t)> send_raw_packet_;

        // Configuration and services
        const core::RouterConfig &config_;
        services::RoutingService &routing_service_;
        services::DeviceManagementService &device_management_;
        services::StatisticsService &statistics_service_;
        std::shared_ptr<services::PacketMonitorService> packet_monitor_;

        // Client state
        std::string device_id_;
        uint16_t assigned_address_;
        std::unique_ptr<protocol::PacketCrypto> session_crypto_;
        std::unique_ptr<protocol::HandshakeManager> handshake_manager_;
        bool authenticated_;
        std::atomic<bool> running_;

        // track heart beat
        std::chrono::steady_clock::time_point last_heartbeat_;
        std::chrono::steady_clock::time_point disconnect_time_;
        mutable std::mutex heartbeat_mutex_;

        std::shared_ptr<core::Logger> logger_;
    };

} // namespace transports
} // namespace mita

#endif // MITA_ROUTER_WIFI_CLIENT_HANDLER_HPP
