#ifndef MITA_ROUTER_TRANSPORT_INTERFACE_HPP
#define MITA_ROUTER_TRANSPORT_INTERFACE_HPP

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include "core/logger.hpp"
#include "protocol/protocol.hpp"

namespace mita
{
    namespace core
    {
        // Forward declarations
        class RouterConfig;
    }

    namespace services
    {
        class RoutingService;
        class DeviceManagementService;
        class StatisticsService;
    }

    namespace core
    {

        /**
         * Transport type enumeration
         */
        enum class TransportType
        {
            WIFI,
            BLE
        };

        /**
         * Device information structure
         */
        struct DeviceInfo
        {
            std::string device_id;
            std::string connection_info;
            TransportType transport_type;
            uint16_t assigned_address;
            bool authenticated;
            std::chrono::steady_clock::time_point last_seen;
        };

        /**
         * Abstract transport interface
         * All transport implementations must inherit from this interface
         */
        class TransportInterface
        {
        public:
            virtual ~TransportInterface() = default;

            /**
             * Start the transport layer
             * @return true if started successfully
             */
            virtual bool start() = 0;

            /**
             * Stop the transport layer
             */
            virtual void stop() = 0;

            /**
             * Check if transport is running
             */
            virtual bool is_running() const = 0;

            /**
             * Get transport type
             */
            virtual TransportType get_type() const = 0;

            /**
             * Get list of connected devices
             */
            virtual std::map<std::string, DeviceInfo> get_connected_devices() const = 0;

            /**
             * Send packet to specific device
             * @param device_id Target device ID
             * @param packet Packet to send
             * @return true if sent successfully
             */
            virtual bool send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet) = 0;

            /**
             * Broadcast packet to all connected devices
             * @param packet Packet to broadcast
             * @return number of devices that received the packet
             */
            virtual int broadcast_packet(const protocol::ProtocolPacket &packet) = 0;

            /**
             * Get transport-specific connection information
             */
            virtual std::string get_connection_info() const = 0;

        protected:
            /**
             * Constructor for derived classes
             */
            TransportInterface(const RouterConfig &config,
                               services::RoutingService &routing_service,
                               services::DeviceManagementService &device_management,
                               services::StatisticsService &statistics_service);

            // Service references
            const RouterConfig &config_;
            ::mita::services::RoutingService &routing_service_;
            ::mita::services::DeviceManagementService &device_management_;
            ::mita::services::StatisticsService &statistics_service_;
        };

        /**
         * Base transport implementation with common functionality
         */
        class BaseTransport : public TransportInterface
        {
        public:
            BaseTransport(const RouterConfig &config,
                          ::mita::services::RoutingService &routing_service,
                          ::mita::services::DeviceManagementService &device_management,
                          ::mita::services::StatisticsService &statistics_service);

            virtual ~BaseTransport() = default;

            // Common implementations
            bool is_running() const override { return running_; }
            std::map<std::string, DeviceInfo> get_connected_devices() const override;

        protected:
            /**
             * Handle incoming packet from device
             * @param device_id Source device ID
             * @param packet Received packet
             */
            virtual void handle_incoming_packet(const std::string &device_id, const protocol::ProtocolPacket &packet);

            /**
             * Handle device connection
             * @param device_id New device ID
             * @param connection_info Transport-specific connection info
             */
            virtual void handle_device_connected(const std::string &device_id, const std::string &connection_info);

            /**
             * Handle device disconnection
             * @param device_id Disconnected device ID
             */
            virtual void handle_device_disconnected(const std::string &device_id);

            /**
             * Update device last seen timestamp
             * @param device_id Device ID to update
             */
            void update_device_last_seen(const std::string &device_id);

            /**
             * Get device info by ID
             * @param device_id Device ID
             * @return Device info or nullptr if not found
             */
            const DeviceInfo *get_device_info(const std::string &device_id) const;

            // State management
            mutable std::mutex devices_mutex_;
            std::map<std::string, DeviceInfo> connected_devices_;
            std::atomic<bool> running_{false};

        private:
            std::shared_ptr<core::Logger> logger_;
        };

    } // namespace core
} // namespace mita

#endif // MITA_ROUTER_TRANSPORT_INTERFACE_HPP