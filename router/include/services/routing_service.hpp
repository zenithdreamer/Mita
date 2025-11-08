#ifndef MITA_ROUTER_ROUTING_SERVICE_HPP
#define MITA_ROUTER_ROUTING_SERVICE_HPP

#include <string>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <vector>
#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"

namespace mita
{
    namespace core
    {
        struct RoutingConfig;
        class Logger;
    }

    namespace services
    {
        class PacketMonitorService;

        /**
         * Routing table entry for a device
         */
        struct RouteEntry
        {
            uint16_t node_addr;
            std::string device_id;
            core::TransportType interface_type;
            void *connection_handle; // Transport-specific handle
            std::shared_ptr<protocol::PacketCrypto> session_crypto;
            std::chrono::steady_clock::time_point last_seen;
            std::map<std::string, std::string> connection_info;

            RouteEntry() = default;
            RouteEntry(uint16_t addr, const std::string &id, core::TransportType type, void *handle)
                : node_addr(addr), device_id(id), interface_type(type), connection_handle(handle), last_seen(std::chrono::steady_clock::now()) {}
        };

        /**
         * Routing service for managing device routes and message forwarding
         */
        class RoutingService
        {
        public:
            // Address space constants - use shared constants for ROUTER and BROADCAST
            static constexpr uint16_t MIN_CLIENT_ADDRESS = 0x0001;
            static constexpr uint16_t MAX_CLIENT_ADDRESS = 0xFFFE;

            explicit RoutingService(const core::RoutingConfig &config);
            ~RoutingService();

            // Service lifecycle
            void start();
            void stop();
            bool is_running() const { return running_; }

            // Device management
            uint16_t add_device(const std::string &device_id, core::TransportType interface_type,
                                void *connection_handle);
            bool remove_device(const std::string &device_id);
            bool remove_device_by_address(uint16_t address);

            // Route management
            const RouteEntry *get_route(uint16_t address) const;
            const RouteEntry *get_route_by_device_id(const std::string &device_id) const;
            std::map<uint16_t, RouteEntry> get_all_routes() const;

            // Address assignment
            uint16_t assign_address(const std::string &device_id);
            bool is_address_available(uint16_t address) const;
            uint16_t get_device_address(const std::string &device_id) const;

            // Session management
            void set_session_crypto(const std::string &device_id,
                                    std::shared_ptr<protocol::PacketCrypto> crypto);
            std::shared_ptr<protocol::PacketCrypto> get_session_crypto(const std::string &device_id) const;

            // Packet routing
            bool route_packet(const protocol::ProtocolPacket &packet);
            bool forward_to_device(uint16_t dest_address, const protocol::ProtocolPacket &packet);
            int broadcast_packet(const protocol::ProtocolPacket &packet);

            // Maintenance
            int cleanup_stale_routes(std::chrono::seconds timeout_seconds);
            void update_device_last_seen(const std::string &device_id);

            // Statistics
            size_t get_device_count() const;
            std::vector<std::string> get_connected_device_ids() const;

            // Packet monitoring
            void set_packet_monitor(std::shared_ptr<PacketMonitorService> monitor) { packet_monitor_ = monitor; }

        private:
            // Address management
            uint16_t find_free_address();
            void release_address(uint16_t address);

            // Route table operations (thread-safe)
            void add_route_entry(uint16_t address, const RouteEntry &entry);
            void remove_route_entry(uint16_t address);

            const core::RoutingConfig &config_;
            std::shared_ptr<core::Logger> logger_;

            // Routing table: address -> route entry
            mutable std::shared_mutex routes_mutex_;
            std::map<uint16_t, RouteEntry> routing_table_;

            // Device ID to address mapping
            mutable std::shared_mutex device_map_mutex_;
            std::map<std::string, uint16_t> device_to_address_;

            // Address allocation tracking
            mutable std::mutex allocation_mutex_;
            std::set<uint16_t> allocated_addresses_;

            std::atomic<bool> running_{false};
            
            // Packet monitoring
            std::shared_ptr<PacketMonitorService> packet_monitor_;
        };

    } // namespace services
} // namespace mita

#endif // MITA_ROUTER_ROUTING_SERVICE_HPP