#ifndef MITA_ROUTER_DEVICE_MANAGEMENT_SERVICE_HPP
#define MITA_ROUTER_DEVICE_MANAGEMENT_SERVICE_HPP

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <functional>
#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"

namespace mita
{
    namespace core
    {
        class Logger;
    }
    namespace services
    {
        class RoutingService;
        class StatisticsService;
        class PacketMonitorService;
    }
}

namespace mita
{
    namespace services
    {

        /**
         * Device connection state
         */
        enum class DeviceState
        {
            CONNECTING,
            HANDSHAKING,
            AUTHENTICATED,
            ACTIVE,
            DISCONNECTING,
            ERROR
        };

        /**
         * Device information and state
         */
        struct ManagedDevice
        {
            std::string device_id;
            uint16_t assigned_address;
            core::TransportType transport_type;
            DeviceState state;
            std::chrono::steady_clock::time_point connected_time;
            std::chrono::steady_clock::time_point last_activity;
            std::shared_ptr<protocol::PacketCrypto> session_crypto;
            std::map<std::string, std::string> metadata;

            ManagedDevice() = default;
            ManagedDevice(const std::string &id, core::TransportType type)
                : device_id(id), assigned_address(0), transport_type(type), state(DeviceState::CONNECTING), connected_time(std::chrono::steady_clock::now()), last_activity(std::chrono::steady_clock::now()) {}
        };

        /**
         * Message handler function type
         */
        using MessageHandler = std::function<void(const std::string &device_id,
                                                  const protocol::ProtocolPacket &packet)>;

        /**
         * Device Management Service
         * Handles device lifecycle, messaging, and coordination between transports
         */
        class DeviceManagementService
        {
        public:
            DeviceManagementService(RoutingService &routing_service,
                                    StatisticsService &statistics_service);
            ~DeviceManagementService() = default;

            // Service lifecycle
            void start();
            void stop();
            bool is_running() const { return running_; }

            // Device lifecycle management
            bool register_device(const std::string &device_id, core::TransportType transport_type);
            bool authenticate_device(const std::string &device_id,
                                     std::shared_ptr<protocol::PacketCrypto> session_crypto);
            bool remove_device(const std::string &device_id);
            void update_device_activity(const std::string &device_id);

            // Packet handling
            void handle_packet(const std::string &device_id, const protocol::ProtocolPacket &packet,
                               core::TransportType transport_type);

            // Message transmission
            bool send_message_to_device(const std::string &device_id, const std::vector<uint8_t> &message);
            int broadcast_message(const std::vector<uint8_t> &message);

            // Device information
            std::map<std::string, ManagedDevice> get_device_list() const;
            const ManagedDevice *get_device_info(const std::string &device_id) const;
            std::vector<std::string> get_connected_device_ids() const;
            size_t get_device_count() const;
            size_t get_device_count_by_transport(core::TransportType transport) const;

            // Message handlers
            void register_message_handler(const std::string &handler_name, MessageHandler handler);
            void unregister_message_handler(const std::string &handler_name);

            // Device state management
            bool set_device_state(const std::string &device_id, DeviceState state);
            DeviceState get_device_state(const std::string &device_id) const;

            // Maintenance
            int cleanup_inactive_devices(std::chrono::seconds timeout);
            void periodic_maintenance();

            // Device management notifications (called by transports)
            void notify_device_connected(const std::string &device_id);
            void notify_device_disconnected(const std::string &device_id);

            // Packet monitoring
            void set_packet_monitor(std::shared_ptr<PacketMonitorService> monitor) { packet_monitor_ = monitor; }

        private:
            // Internal packet processing
            void process_hello_packet(const std::string &device_id, const protocol::ProtocolPacket &packet);
            void process_data_packet(const std::string &device_id, const protocol::ProtocolPacket &packet);
            void process_control_packet(const std::string &device_id, const protocol::ProtocolPacket &packet);

            // Device management helpers
            ManagedDevice *find_device(const std::string &device_id);
            const ManagedDevice *find_device(const std::string &device_id) const;

            // Service references
            RoutingService &routing_service_;
            StatisticsService &statistics_service_;

            // Device registry
            mutable std::shared_mutex devices_mutex_;
            std::map<std::string, ManagedDevice> managed_devices_;

            // Message handlers
            mutable std::mutex handlers_mutex_;
            std::map<std::string, MessageHandler> message_handlers_;

            // Service state
            std::atomic<bool> running_{false};

            // Packet monitoring
            std::shared_ptr<PacketMonitorService> packet_monitor_;
            
            std::shared_ptr<core::Logger> logger_;
        };

    } // namespace services
} // namespace mita

#endif // MITA_ROUTER_DEVICE_MANAGEMENT_SERVICE_HPP