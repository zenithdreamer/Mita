#include "core/transport_interface.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include <chrono>

namespace mita
{
    namespace core
    {

        // TransportInterface implementation
        TransportInterface::TransportInterface(const RouterConfig &config,
                                               ::mita::services::RoutingService &routing_service,
                                               ::mita::services::DeviceManagementService &device_management,
                                               ::mita::services::StatisticsService &statistics_service)
            : config_(config), routing_service_(routing_service), device_management_(device_management), statistics_service_(statistics_service)
        {
        }

        // BaseTransport implementation
        BaseTransport::BaseTransport(const RouterConfig &config,
                                     ::mita::services::RoutingService &routing_service,
                                     ::mita::services::DeviceManagementService &device_management,
                                     ::mita::services::StatisticsService &statistics_service)
            : TransportInterface(config, routing_service, device_management, statistics_service), logger_(core::get_logger("BaseTransport"))
        {
        }

        std::map<std::string, DeviceInfo> BaseTransport::get_connected_devices() const
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);
            return connected_devices_;
        }

        void BaseTransport::handle_incoming_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
        {
            try
            {
                // Update last seen timestamp
                update_device_last_seen(device_id);

                // Forward to device management service
                device_management_.handle_packet(device_id, packet, get_type());

                // Update statistics
                statistics_service_.record_packet_received(packet.get_payload().size());
            }
            catch (const std::exception &e)
            {
                logger_->error("Error handling incoming packet",
                               LogContext().add("device_id", device_id).add("error", e.what()));
                statistics_service_.record_error();
            }
        }

        void BaseTransport::handle_device_connected(const std::string &device_id,
                                                    const std::string &connection_info)
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            DeviceInfo info;
            info.device_id = device_id;
            info.connection_info = connection_info;
            info.transport_type = get_type();
            info.assigned_address = 0; // Will be assigned during handshake
            info.authenticated = false;
            info.last_seen = std::chrono::steady_clock::now();

            connected_devices_[device_id] = info;

            logger_->info("Device connected",
                          LogContext().add("device_id", device_id).add("transport", connection_info));
        }

        void BaseTransport::handle_device_disconnected(const std::string &device_id)
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            auto it = connected_devices_.find(device_id);
            if (it != connected_devices_.end())
            {
                logger_->info("Device disconnected",
                              LogContext().add("device_id", device_id).add("transport_type", static_cast<int>(it->second.transport_type)));

                // Notify routing service
                routing_service_.remove_device(device_id);

                // Remove from connected devices
                connected_devices_.erase(it);
            }
        }

        void BaseTransport::update_device_last_seen(const std::string &device_id)
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            auto it = connected_devices_.find(device_id);
            if (it != connected_devices_.end())
            {
                it->second.last_seen = std::chrono::steady_clock::now();
            }
        }

        const DeviceInfo *BaseTransport::get_device_info(const std::string &device_id) const
        {
            std::lock_guard<std::mutex> lock(devices_mutex_);

            auto it = connected_devices_.find(device_id);
            return (it != connected_devices_.end()) ? &it->second : nullptr;
        }

    } // namespace core
} // namespace mita