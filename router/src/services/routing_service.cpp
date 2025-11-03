#include "services/routing_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "protocol/protocol.hpp"
#include <algorithm>
#include <set>

namespace mita
{
    namespace services
    {

        RoutingService::RoutingService(const core::RoutingConfig &config)
            : config_(config), logger_(core::get_logger("RoutingService")), next_address_(MIN_CLIENT_ADDRESS), packet_monitor_(nullptr)
        {

            logger_->info("Routing service initialized",
                          core::LogContext().add("max_devices", config_.max_devices).add("device_timeout", config_.device_timeout).add("cleanup_interval", config_.cleanup_interval));
        }

        RoutingService::~RoutingService()
        {
            stop();
        }

        void RoutingService::start()
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            logger_->info("Routing service started");
        }

        void RoutingService::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            // Clear all routes
            {
                std::unique_lock<std::shared_mutex> routes_lock(routes_mutex_);
                std::lock_guard<std::shared_mutex> device_map_lock(device_map_mutex_);
                std::lock_guard<std::mutex> allocation_lock(allocation_mutex_);

                routing_table_.clear();
                device_to_address_.clear();
                allocated_addresses_.clear();
                next_address_ = MIN_CLIENT_ADDRESS;
            }

            logger_->info("Routing service stopped");
        }

        uint16_t RoutingService::add_device(const std::string &device_id, core::TransportType interface_type,
                                            void *connection_handle)
        {
            // Check if device already exists
            {
                std::shared_lock<std::shared_mutex> lock(device_map_mutex_);
                auto it = device_to_address_.find(device_id);
                if (it != device_to_address_.end())
                {
                    logger_->warning("Device already exists in routing table",
                                     core::LogContext().add("device_id", device_id).add("existing_address", it->second));
                    return it->second;
                }
            }

            // Assign new address
            uint16_t address = assign_address(device_id);
            if (address == 0)
            {
                logger_->error("Failed to assign address to device",
                               core::LogContext().add("device_id", device_id));
                return 0;
            }

            // Create route entry
            RouteEntry entry(address, device_id, interface_type, connection_handle);

            // Add to routing table
            add_route_entry(address, entry);

            logger_->info("Device added to routing table",
                          core::LogContext().add("device_id", device_id).add("address", address).add("interface_type", static_cast<int>(interface_type)));

            return address;
        }

        bool RoutingService::remove_device(const std::string &device_id)
        {
            uint16_t address = 0;

            // Find device address
            {
                std::shared_lock<std::shared_mutex> lock(device_map_mutex_);
                auto it = device_to_address_.find(device_id);
                if (it == device_to_address_.end())
                {
                    logger_->warning("Device not found in routing table",
                                     core::LogContext().add("device_id", device_id));
                    return false;
                }
                address = it->second;
            }

            return remove_device_by_address(address);
        }

        bool RoutingService::remove_device_by_address(uint16_t address)
        {
            std::string device_id;

            // Remove from routing table
            {
                std::unique_lock<std::shared_mutex> lock(routes_mutex_);
                auto it = routing_table_.find(address);
                if (it == routing_table_.end())
                {
                    return false;
                }
                device_id = it->second.device_id;
                routing_table_.erase(it);
            }

            // Remove from device mapping
            {
                std::unique_lock<std::shared_mutex> lock(device_map_mutex_);
                device_to_address_.erase(device_id);
            }

            // Release address
            release_address(address);

            logger_->info("Device removed from routing table",
                          core::LogContext().add("device_id", device_id).add("address", address));

            return true;
        }

        const RouteEntry *RoutingService::get_route(uint16_t address) const
        {
            std::shared_lock<std::shared_mutex> lock(routes_mutex_);
            auto it = routing_table_.find(address);
            return (it != routing_table_.end()) ? &it->second : nullptr;
        }

        const RouteEntry *RoutingService::get_route_by_device_id(const std::string &device_id) const
        {
            uint16_t address = get_device_address(device_id);
            if (address == 0)
            {
                return nullptr;
            }
            return get_route(address);
        }

        std::map<uint16_t, RouteEntry> RoutingService::get_all_routes() const
        {
            std::shared_lock<std::shared_mutex> lock(routes_mutex_);
            return routing_table_;
        }

        uint16_t RoutingService::assign_address(const std::string &device_id)
        {
            if (!config_.auto_assign_addresses)
            {
                logger_->error("Automatic address assignment is disabled");
                return 0;
            }

            std::lock_guard<std::mutex> lock(allocation_mutex_);

            // Check device limit
            if (allocated_addresses_.size() >= static_cast<size_t>(config_.max_devices))
            {
                logger_->error("Maximum device limit reached",
                               core::LogContext().add("max_devices", config_.max_devices));
                return 0;
            }

            uint16_t address = find_free_address();
            if (address == 0)
            {
                logger_->error("No free addresses available");
                return 0;
            }

            allocated_addresses_.insert(address);

            // Update device mapping
            {
                std::unique_lock<std::shared_mutex> lock(device_map_mutex_);
                device_to_address_[device_id] = address;
            }

            return address;
        }

        bool RoutingService::is_address_available(uint16_t address) const
        {
            if (address < MIN_CLIENT_ADDRESS || address > MAX_CLIENT_ADDRESS)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(allocation_mutex_);
            return allocated_addresses_.find(address) == allocated_addresses_.end();
        }

        uint16_t RoutingService::get_device_address(const std::string &device_id) const
        {
            std::shared_lock<std::shared_mutex> lock(device_map_mutex_);
            auto it = device_to_address_.find(device_id);
            return (it != device_to_address_.end()) ? it->second : 0;
        }

        void RoutingService::set_session_crypto(const std::string &device_id,
                                                std::shared_ptr<protocol::PacketCrypto> crypto)
        {
            const RouteEntry *route = get_route_by_device_id(device_id);
            if (!route)
            {
                logger_->warning("Cannot set session crypto for unknown device",
                                 core::LogContext().add("device_id", device_id));
                return;
            }

            std::unique_lock<std::shared_mutex> lock(routes_mutex_);
            auto it = routing_table_.find(route->node_addr);
            if (it != routing_table_.end())
            {
                it->second.session_crypto = crypto;
            }
        }

        std::shared_ptr<protocol::PacketCrypto> RoutingService::get_session_crypto(const std::string &device_id) const
        {
            const RouteEntry *route = get_route_by_device_id(device_id);
            return route ? route->session_crypto : nullptr;
        }

        bool RoutingService::route_packet(const protocol::ProtocolPacket &packet)
        {
            uint16_t dest_address = packet.get_dest_addr();

            // Capture packet for monitoring
            if (packet_monitor_)
            {
                // Determine direction based on source/destination
                std::string direction = "forwarded";
                if (packet.get_source_addr() == ROUTER_ADDRESS)
                {
                    direction = "outbound";
                }
                else if (dest_address == ROUTER_ADDRESS)
                {
                    direction = "inbound";
                }

                // Get transport type from route (default to WiFi if unknown)
                core::TransportType transport = core::TransportType::WIFI;
                const RouteEntry *route = get_route(packet.get_source_addr());
                if (route)
                {
                    transport = route->interface_type;
                }

                packet_monitor_->capture_packet(packet, direction, transport);
            }

            if (dest_address == BROADCAST_ADDRESS)
            {
                return broadcast_packet(packet) > 0;
            }

            return forward_to_device(dest_address, packet);
        }

        bool RoutingService::forward_to_device(uint16_t dest_address, const protocol::ProtocolPacket &packet)
        {
            const RouteEntry *route = get_route(dest_address);
            if (!route)
            {
                logger_->warning("No route found for destination",
                                 core::LogContext().add("dest_address", dest_address));
                return false;
            }

            // Note: Actual packet forwarding is handled by the transport layer/device management
            // This service only validates routes and updates timestamps
            logger_->debug("Route found for packet forwarding",
                           core::LogContext().add("device_id", route->device_id).add("dest_address", dest_address).add("packet_size", packet.get_payload().size()));

            // Update last seen
            {
                std::unique_lock<std::shared_mutex> lock(routes_mutex_);
                auto it = routing_table_.find(dest_address);
                if (it != routing_table_.end())
                {
                    it->second.last_seen = std::chrono::steady_clock::now();
                }
            }

            return true;
        }

        int RoutingService::broadcast_packet(const protocol::ProtocolPacket &packet)
        {
            auto routes = get_all_routes();
            int sent_count = 0;

            for (const auto &[address, route] : routes)
            {
                if (forward_to_device(address, packet))
                {
                    sent_count++;
                }
            }

            logger_->debug("Broadcast packet sent",
                           core::LogContext().add("recipients", sent_count).add("packet_size", packet.get_payload().size()));

            return sent_count;
        }

        int RoutingService::cleanup_stale_routes(std::chrono::seconds timeout_seconds)
        {
            auto cutoff_time = std::chrono::steady_clock::now() - timeout_seconds;
            std::vector<uint16_t> stale_addresses;

            // Find stale routes
            {
                std::shared_lock<std::shared_mutex> lock(routes_mutex_);
                for (const auto &[address, route] : routing_table_)
                {
                    if (route.last_seen < cutoff_time)
                    {
                        stale_addresses.push_back(address);
                    }
                }
            }

            // Remove stale routes
            int removed_count = 0;
            for (uint16_t address : stale_addresses)
            {
                if (remove_device_by_address(address))
                {
                    removed_count++;
                }
            }

            if (removed_count > 0)
            {
                logger_->info("Cleaned up stale routes",
                              core::LogContext().add("removed_count", removed_count));
            }

            return removed_count;
        }

        void RoutingService::update_device_last_seen(const std::string &device_id)
        {
            const RouteEntry *route = get_route_by_device_id(device_id);
            if (!route)
            {
                return;
            }

            std::unique_lock<std::shared_mutex> lock(routes_mutex_);
            auto it = routing_table_.find(route->node_addr);
            if (it != routing_table_.end())
            {
                it->second.last_seen = std::chrono::steady_clock::now();
            }
        }

        size_t RoutingService::get_device_count() const
        {
            std::shared_lock<std::shared_mutex> lock(routes_mutex_);
            return routing_table_.size();
        }

        std::vector<std::string> RoutingService::get_connected_device_ids() const
        {
            std::vector<std::string> device_ids;

            std::shared_lock<std::shared_mutex> lock(routes_mutex_);
            device_ids.reserve(routing_table_.size());

            for (const auto &[address, route] : routing_table_)
            {
                device_ids.push_back(route.device_id);
            }

            return device_ids;
        }

        // Private methods

        uint16_t RoutingService::find_free_address()
        {
            // Start from next_address_ and wrap around
            uint16_t start_address = next_address_;

            do
            {
                if (allocated_addresses_.find(next_address_) == allocated_addresses_.end())
                {
                    uint16_t result = next_address_;

                    // Advance for next allocation
                    next_address_++;
                    if (next_address_ > MAX_CLIENT_ADDRESS)
                    {
                        next_address_ = MIN_CLIENT_ADDRESS;
                    }

                    return result;
                }

                next_address_++;
                if (next_address_ > MAX_CLIENT_ADDRESS)
                {
                    next_address_ = MIN_CLIENT_ADDRESS;
                }

            } while (next_address_ != start_address);

            return 0; // No free address found
        }

        void RoutingService::release_address(uint16_t address)
        {
            std::lock_guard<std::mutex> lock(allocation_mutex_);
            allocated_addresses_.erase(address);
        }

        void RoutingService::add_route_entry(uint16_t address, const RouteEntry &entry)
        {
            std::unique_lock<std::shared_mutex> lock(routes_mutex_);
            routing_table_[address] = entry;
        }

        void RoutingService::remove_route_entry(uint16_t address)
        {
            std::unique_lock<std::shared_mutex> lock(routes_mutex_);
            routing_table_.erase(address);
        }

    } // namespace services
} // namespace mita