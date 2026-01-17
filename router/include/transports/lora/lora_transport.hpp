#ifndef MITA_ROUTER_LORA_TRANSPORT_HPP
#define MITA_ROUTER_LORA_TRANSPORT_HPP

#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"
#include "transports/lora/lora_radio.hpp"
#include "transports/lora/lora_client_handler.hpp"
#include <thread>
#include <atomic>
#include <map>
#include <set>
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
        namespace lora
        {

            class LoRaTransport : public core::BaseTransport
            {
            public:
                LoRaTransport(const core::RouterConfig &config,
                              services::RoutingService &routing_service,
                              services::DeviceManagementService &device_management,
                              services::StatisticsService &statistics_service,
                              std::shared_ptr<services::PacketMonitorService> packet_monitor);
                ~LoRaTransport() override;


                bool start() override;
                void stop() override;
                bool send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet) override;
                int broadcast_packet(const protocol::ProtocolPacket &packet) override;
                std::string get_connection_info() const override;
                core::TransportType get_type() const override { return core::TransportType::LORA; }


                std::vector<std::pair<std::string, uint8_t>> get_all_device_handlers() const;

            private:

                void receive_loop();


                void handle_incoming_packet(uint8_t src_addr, const protocol::ProtocolPacket &packet);
                LoRaClientHandler *find_client_by_device_id(const std::string &device_id);
                LoRaClientHandler *find_client_by_lora_addr(uint8_t lora_addr);
                uint8_t allocate_lora_address();
                void cleanup_inactive_clients();


                std::unique_ptr<LoRaRadio> radio_;

  
                std::map<std::string, std::unique_ptr<LoRaClientHandler>> client_handlers_;
                mutable std::mutex handlers_mutex_;


                std::map<uint8_t, std::string> lora_addr_to_device_;
                std::mutex address_map_mutex_;

  
                std::set<uint8_t> allocated_addresses_;
                uint8_t next_address_;

                std::atomic<bool> running_;
                std::unique_ptr<std::thread> receive_thread_;

                std::shared_ptr<services::PacketMonitorService> packet_monitor_;
                std::shared_ptr<core::Logger> logger_;
            };

        } // namespace lora
    } // namespace transports
} // namespace mita

#endif // MITA_ROUTER_LORA_TRANSPORT_HPP