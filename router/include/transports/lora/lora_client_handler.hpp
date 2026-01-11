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
        namespace lora {
            class LoRaClientHandler
            {
            public:
                LoRaClientHandler(uint8_t lora_address,
                                  const core::RouterConfig &config,
                                  services::RoutingService &routing_service,
                                  services::DeviceManagementService &device_management,
                                  services::StatisticsService &statistics_service,
                                  std::shared_ptr<services::PacketMonitorService> packet_monitor = nullptr);
                ~LoRaClientHandler();

                void start(const protocol::ProtocolPacket &initial_hello);
                void stop();
                void handle_packet(const protocol::ProtocolPacket &packet);

                bool is_authenticated() const { return authenticated_; }
                bool is_running() const { return running_; }
                const std::string &get_device_id() const { return device_id_; }
                uint8_t get_lora_address() const { return lora_address_; }

                bool check_heartbeat_timeout();
                bool check_for_disconnected() const;
                std::chrono::steady_clock::time_point get_disconnect_time() const;

            private:
                uint8_t lora_address_;
                std::string device_id_;
                bool authenticated_;
                std::atomic<bool> running_;

                std::chrono::steady_clock::time_point last_heartbeat_time_;
                std::chrono::steady_clock::time_point disconnect_time_;

                const core::RouterConfig &config_;
                services::RoutingService &routing_service_;
                services::DeviceManagementService &device_management_;
                services::StatisticsService &statistics_service_;
                std::shared_ptr<services::PacketMonitorService> packet_monitor_;
                std::shared_ptr<core::Logger> logger_;
            };
        }
}}        

    
#endif