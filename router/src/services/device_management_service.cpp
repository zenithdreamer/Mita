#include "services/device_management_service.hpp"
#include "services/routing_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "core/logger.hpp"

namespace mita
{
    namespace services
    {

        DeviceManagementService::DeviceManagementService(RoutingService &routing_service,
                                                         StatisticsService &statistics_service)
            : routing_service_(routing_service), statistics_service_(statistics_service), packet_monitor_(nullptr), logger_(core::get_logger("DeviceManagementService"))
        {

            logger_->info("Device management service initialized");
        }

        void DeviceManagementService::start()
        {
            if (running_.exchange(true))
            {
                return; // Already running
            }

            logger_->info("Device management service started");
        }

        void DeviceManagementService::stop()
        {
            if (!running_.exchange(false))
            {
                return; // Already stopped
            }

            // Disconnect all devices
            {
                std::unique_lock<std::shared_mutex> lock(devices_mutex_);
                for (auto &[device_id, device] : managed_devices_)
                {
                    notify_device_disconnected(device_id);
                }
                managed_devices_.clear();
            }

            logger_->info("Device management service stopped");
        }

        bool DeviceManagementService::register_device(const std::string &device_id,
                                                      core::TransportType transport_type)
        {
            if (!running_)
            {
                logger_->warning("Cannot register device - service not running",
                                 core::LogContext().add("device_id", device_id));
                return false;
            }

            std::unique_lock<std::shared_mutex> lock(devices_mutex_);

            // Check if device already exists
            auto it = managed_devices_.find(device_id);
            if (it != managed_devices_.end())
            {


                //reuse existing device entry
                it->second.state = DeviceState::CONNECTING;
                it->second.transport_type = transport_type;
                it->second.connected_time = std::chrono::steady_clock::now();
                it->second.last_activity = std::chrono::steady_clock::now();
                it->second.session_crypto.reset();


                it->second.state = DeviceState::HANDSHAKING;

                logger_->info("device reconnect",
                              core::LogContext().add("device_id", device_id)
                                  .add("address", it->second.assigned_address)
                                  .add("transport_type", static_cast<int>(transport_type)));

                statistics_service_.record_connection_established();
                notify_device_connected(device_id);
                return true;
            }

            // Create new managed device
            ManagedDevice device(device_id, transport_type);
            managed_devices_[device_id] = device;

            logger_->info("Device registered",
                          core::LogContext().add("device_id", device_id).add("transport_type", static_cast<int>(transport_type)));

            // Add to routing service
            uint16_t address = routing_service_.add_device(device_id, transport_type, nullptr);
            if (address != 0)
            {
                managed_devices_[device_id].assigned_address = address;
                managed_devices_[device_id].state = DeviceState::HANDSHAKING;

                statistics_service_.record_connection_established();
                notify_device_connected(device_id);
                return true;
            }
            else
            {
                managed_devices_.erase(device_id);
                logger_->error("Failed to assign address to device",
                               core::LogContext().add("device_id", device_id));
                return false;
            }
        }

        bool DeviceManagementService::authenticate_device(const std::string &device_id,
                                                          std::shared_ptr<protocol::PacketCrypto> session_crypto)
        {
            std::unique_lock<std::shared_mutex> lock(devices_mutex_);

            auto *device = find_device(device_id);
            if (!device)
            {
                logger_->warning("Cannot authenticate unknown device",
                                 core::LogContext().add("device_id", device_id));
                return false;
            }

            if (device->state != DeviceState::HANDSHAKING)
            {
                logger_->warning("Device not in handshaking state",
                                 core::LogContext().add("device_id", device_id).add("current_state", static_cast<int>(device->state)));
                return false;
            }

            device->session_crypto = session_crypto;
            device->state = DeviceState::AUTHENTICATED;
            device->last_activity = std::chrono::steady_clock::now();

            // Update routing service with session crypto
            routing_service_.set_session_crypto(device_id, session_crypto);

            logger_->info("Device authenticated",
                          core::LogContext().add("device_id", device_id).add("address", device->assigned_address));

            statistics_service_.record_handshake_completed();
            return true;
        }

        bool DeviceManagementService::remove_device(const std::string &device_id)
        {
            std::unique_lock<std::shared_mutex> lock(devices_mutex_);

            auto it = managed_devices_.find(device_id);
            if (it == managed_devices_.end())
            {
                logger_->warning("Cannot remove unknown device",
                                 core::LogContext().add("device_id", device_id));
                return false;
            }

            // Remove from routing service
            routing_service_.remove_device(device_id);

            // Notify about disconnection
            notify_device_disconnected(device_id);

            // Remove from managed devices
            managed_devices_.erase(it);

            logger_->info("Device removed",
                          core::LogContext().add("device_id", device_id));

            statistics_service_.record_connection_dropped();
            return true;
        }

        void DeviceManagementService::update_device_activity(const std::string &device_id)
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);

            auto *device = find_device(device_id);
            if (device)
            {
                device->last_activity = std::chrono::steady_clock::now();
                if (device->state == DeviceState::AUTHENTICATED)
                {
                    device->state = DeviceState::ACTIVE;
                }
            }

            // Also update routing service
            routing_service_.update_device_last_seen(device_id);
        }

        void DeviceManagementService::handle_packet(const std::string &device_id,
                                                    const protocol::ProtocolPacket &packet,
                                                    core::TransportType transport_type)
        {
            if (!running_)
            {
                return;
            }

            try
            {
                // Capture incoming packet for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "inbound", transport_type);
                }

                update_device_activity(device_id);

                // Process packet based on message type
                switch (packet.get_message_type())
                {
                case MessageType::HELLO:
                    process_hello_packet(device_id, packet);
                    break;

                case MessageType::DATA:
                    process_data_packet(device_id, packet, transport_type);
                    break;

                case MessageType::CONTROL:
                    process_control_packet(device_id, packet);
                    break;

                case MessageType::ACK:
                    // Handle acknowledgments
                    logger_->debug("Received ACK packet",
                                   core::LogContext().add("device_id", device_id));
                    break;

                default:
                    logger_->warning("Received unknown packet type",
                                     core::LogContext().add("device_id", device_id).add("packet_type", static_cast<int>(packet.get_message_type())));
                    statistics_service_.record_protocol_error();
                    break;
                }

                statistics_service_.record_transport_packet_received(
                    transport_type == core::TransportType::WIFI ? "wifi" : "ble",
                    packet.get_payload().size());
            }
            catch (const std::exception &e)
            {
                logger_->error("Error handling packet",
                               core::LogContext().add("device_id", device_id).add("error", e.what()));
                statistics_service_.record_protocol_error();
            }
        }

        bool DeviceManagementService::send_message_to_device(const std::string &device_id,
                                                             const std::vector<uint8_t> &message)
        {
            const ManagedDevice *device = get_device_info(device_id);
            if (!device || device->state != DeviceState::ACTIVE)
            {
                logger_->warning("Cannot send message to inactive device",
                                 core::LogContext().add("device_id", device_id));
                return false;
            }

            try
            {
                // Create data packet
                protocol::ProtocolPacket packet(MessageType::DATA,
                                                0, // Router address
                                                device->assigned_address,
                                                message);

                // Encrypt if session crypto is available
                if (device->session_crypto)
                {
                    auto encrypted_payload = device->session_crypto->encrypt(message);
                    packet.set_payload(encrypted_payload);
                    packet.set_encrypted(true);
                }

                // Capture outbound packet for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "outbound", device->transport_type);
                    packet.set_encrypted(true);
                }

                //validate routee
                if (!routing_service_.forward_to_device(device->assigned_address, packet))
                {
                    logger_->warning("validation fail", core::LogContext().add("device_id", device_id).add("address", device->assigned_address));
                    return false;
                }

                std::string handler_name = (device->transport_type == core::TransportType::WIFI) ? "wifi" : "ble";

                bool sent = false;
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    auto handler_it = message_handlers_.find(handler_name);
                    if (handler_it != message_handlers_.end())
                    {
                        try
                        {
                            handler_it->second(device_id, packet);
                            sent = true;
                        }
                        catch (const std::exception& e)
                        {
                            logger_->error("Transport handler failed",
                                           core::LogContext().add("device_id", device_id).add("error", e.what()));
                        }
                    }
                    else
                    {
                        logger_->warning("Transport handler not found",
                                         core::LogContext().add("handler_name", handler_name));
                    }
                }

                if (sent)
                {
                    statistics_service_.record_packet_sent(message.size());
                    logger_->debug("Message sent to device",
                                   core::LogContext().add("device_id", device_id).add("message_size", message.size()));
                }

                return sent;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error sending message to device",
                               core::LogContext().add("device_id", device_id).add("error", e.what()));
                statistics_service_.record_error();
                return false;
            }
        }

        int DeviceManagementService::broadcast_message(const std::vector<uint8_t> &message)
        {
            try
            {
                // Create broadcast packet
                protocol::ProtocolPacket packet(MessageType::DATA,
                                                0,      // Router address
                                                0xFFFF, // Broadcast address
                                                message);

                int sent_count = routing_service_.broadcast_packet(packet);

                if (sent_count > 0)
                {
                    statistics_service_.record_packet_sent(message.size());
                    logger_->debug("Broadcast message sent",
                                   core::LogContext().add("recipients", sent_count).add("message_size", message.size()));
                }

                return sent_count;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error broadcasting message",
                               core::LogContext().add("error", e.what()));
                statistics_service_.record_error();
                return 0;
            }
        }

        std::map<std::string, ManagedDevice> DeviceManagementService::get_device_list() const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            return managed_devices_;
        }

        const ManagedDevice *DeviceManagementService::get_device_info(const std::string &device_id) const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            return find_device(device_id);
        }

        std::vector<std::string> DeviceManagementService::get_connected_device_ids() const
        {
            std::vector<std::string> device_ids;

            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            device_ids.reserve(managed_devices_.size());

            for (const auto &[device_id, device] : managed_devices_)
            {
                if (device.state == DeviceState::ACTIVE || device.state == DeviceState::AUTHENTICATED)
                {
                    device_ids.push_back(device_id);
                }
            }

            return device_ids;
        }

        size_t DeviceManagementService::get_device_count() const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            return managed_devices_.size();
        }

        size_t DeviceManagementService::get_device_count_by_transport(core::TransportType transport) const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            size_t count = 0;
            for (const auto& [id, device] : managed_devices_) {
                if (device.transport_type == transport && 
                    (device.state == DeviceState::ACTIVE || device.state == DeviceState::AUTHENTICATED)) {
                    count++;
                }
            }
            return count;
        }

        void DeviceManagementService::register_message_handler(const std::string &handler_name,
                                                               MessageHandler handler)
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            message_handlers_[handler_name] = handler;

            logger_->debug("Message handler registered",
                           core::LogContext().add("handler_name", handler_name));
        }

        void DeviceManagementService::unregister_message_handler(const std::string &handler_name)
        {
            std::lock_guard<std::mutex> lock(handlers_mutex_);
            message_handlers_.erase(handler_name);

            logger_->debug("Message handler unregistered",
                           core::LogContext().add("handler_name", handler_name));
        }

        bool DeviceManagementService::set_device_state(const std::string &device_id, DeviceState state)
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);

            auto *device = find_device(device_id);
            if (!device)
            {
                return false;
            }

            DeviceState old_state = device->state;
            device->state = state;

            logger_->debug("Device state changed",
                           core::LogContext().add("device_id", device_id).add("old_state", static_cast<int>(old_state)).add("new_state", static_cast<int>(state)));

            return true;
        }

        DeviceState DeviceManagementService::get_device_state(const std::string &device_id) const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);

            const auto *device = find_device(device_id);
            return device ? device->state : DeviceState::ERROR;
        }

        int DeviceManagementService::cleanup_inactive_devices(std::chrono::seconds timeout)
        {
            auto cutoff_time = std::chrono::steady_clock::now() - timeout;
            std::vector<std::string> inactive_devices;

            // Find inactive devices
            {
                std::shared_lock<std::shared_mutex> lock(devices_mutex_);
                for (const auto &[device_id, device] : managed_devices_)
                {
                    if (device.last_activity < cutoff_time)
                    {
                        inactive_devices.push_back(device_id);
                    }
                }
            }

            // Remove inactive devices
            int removed_count = 0;
            for (const std::string &device_id : inactive_devices)
            {
                if (remove_device(device_id))
                {
                    removed_count++;
                }
            }

            if (removed_count > 0)
            {
                logger_->info("Cleaned up inactive devices",
                              core::LogContext().add("removed_count", removed_count));
            }

            return removed_count;
        }

        void DeviceManagementService::periodic_maintenance()
        {
            // Update statistics with current device count
            statistics_service_.update_peak_connections(get_device_count());
        }

        // Private methods

        void DeviceManagementService::process_hello_packet(const std::string &device_id,
                                                           const protocol::ProtocolPacket & /* packet */)
        {
            logger_->debug("Processing HELLO packet",
                           core::LogContext().add("device_id", device_id));

            // HELLO packets are typically handled during initial connection
            // This might be a re-connection attempt??
            const ManagedDevice *device = get_device_info(device_id);
            if (device && device->state != DeviceState::CONNECTING)
            {
                logger_->warning("Received HELLO from already connected device",
                                 core::LogContext().add("device_id", device_id).add("current_state", static_cast<int>(device->state)));
            }
        }

        void DeviceManagementService::process_data_packet(const std::string &device_id,
                                                          const protocol::ProtocolPacket &packet,
                                                          core::TransportType transport_type)
        {
            const ManagedDevice *device = get_device_info(device_id);
            if (!device || (device->state != DeviceState::ACTIVE && device->state != DeviceState::AUTHENTICATED))
            {
                logger_->warning("Received data packet from inactive device",
                                 core::LogContext().add("device_id", device_id));
                return;
            }

            std::vector<uint8_t> payload = packet.get_payload();

            auto to_hex = [](const std::vector<uint8_t> &v)
            {
                std::string s;
                s.reserve(v.size() * 2);
                const char *hex = "0123456789ABCDEF";
                for (auto b : v)
                {
                    s.push_back(hex[b >> 4]);
                    s.push_back(hex[b & 0x0F]);
                }
                return s;
            };

            if (logger_->is_enabled(core::LogLevel::DEBUG))
            {
                logger_->debug("Received DATA packet payload",
                               core::LogContext().add("device_id", device_id).add("length", payload.size()).add("encrypted", packet.is_encrypted()).add("hex", to_hex(payload)));
            }

            // Decrypt if encrypted
            bool decrypted = false;
            if (packet.is_encrypted() && device->session_crypto)
            {
                try
                {
                    payload = device->session_crypto->decrypt(payload);
                    decrypted = true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Failed to decrypt packet",
                                   core::LogContext().add("device_id", device_id).add("error", e.what()));
                    statistics_service_.record_protocol_error();
                    return;
                }
            }

            if (logger_->is_enabled(core::LogLevel::DEBUG))
            {
                // Produce printable preview for debugging
                std::string preview;
                preview.reserve(std::min<size_t>(payload.size(), 64));
                for (size_t i = 0; i < payload.size() && i < 64; ++i)
                {
                    unsigned char c = payload[i];
                    if (c >= 32 && c < 127)
                        preview.push_back(static_cast<char>(c));
                    else
                        preview.push_back('.');
                }
                logger_->debug(decrypted ? "Decrypted DATA packet" : "Plain DATA packet",
                               core::LogContext().add("device_id", device_id).add("length", payload.size()).add("hex", to_hex(payload)).add("preview", preview));
            }

            //forwarding case
            uint16_t dest_addr = packet.get_dest_addr();
            if (dest_addr != 0 && dest_addr != 0xFFFF && dest_addr != device->assigned_address)
            {

                const auto* route = routing_service_.get_route(dest_addr);
                if (route)
                {

                    if (send_message_to_device(route->device_id, payload))
                    {
                        logger_->debug("forward successfully", core::LogContext().add("from_device", device_id).add("to_device", route->device_id));
                    }
                    else
                    {
                        logger_->warning("failed to forward", core::LogContext().add("from_device", device_id).add("to_device", route->device_id));
                        statistics_service_.record_protocol_error();
                    }
                }
                else
                {
                    logger_->warning("No route found", core::LogContext().add("dest_addr", dest_addr));
                    statistics_service_.record_protocol_error();
                }

                return;
            }

            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);
                for (const auto &[handler_name, handler] : message_handlers_)
                {
                    try
                    {
                        handler(device_id, packet);
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Message handler error",
                                       core::LogContext().add("handler_name", handler_name).add("device_id", device_id).add("error", e.what()));
                    }
                }
            }

            statistics_service_.record_packet_routed(payload.size());
            
            // Send ACK packet back to device to confirm receipt
            send_ack_packet(device_id, packet.get_sequence_number(), transport_type);
        }

        void DeviceManagementService::process_control_packet(const std::string &device_id,
                                                             const protocol::ProtocolPacket & /* packet */)
        {
            logger_->debug("Processing CONTROL packet",
                           core::LogContext().add("device_id", device_id));

            // Handle control messages (ping, configuration updates, etc.)
            // TODO: Implement control message handling
        }

        void DeviceManagementService::send_ack_packet(const std::string &device_id, 
                                                      uint16_t sequence_number,
                                                      core::TransportType transport_type)
        {
            const ManagedDevice *device = get_device_info(device_id);
            if (!device || device->state != DeviceState::ACTIVE)
            {
                return;
            }

            try
            {
                // Create ACK packet with the sequence number being acknowledged
                std::vector<uint8_t> payload;
                payload.push_back((sequence_number >> 8) & 0xFF);
                payload.push_back(sequence_number & 0xFF);

                protocol::ProtocolPacket ack_packet(
                    MessageType::ACK,
                    ROUTER_ADDRESS,              // source is router
                    device->assigned_address,    // destination is the device
                    payload
                );

                // Capture outbound ACK for monitoring before sending
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(ack_packet, "outbound", transport_type);
                }

                // Forward ACK packet to device via routing service
                if (routing_service_.forward_to_device(device->assigned_address, ack_packet))
                {
                    logger_->debug("Sent ACK packet",
                                  core::LogContext()
                                      .add("device_id", device_id)
                                      .add("sequence", sequence_number));
                }
                else
                {
                    logger_->warning("Failed to forward ACK packet",
                                    core::LogContext()
                                        .add("device_id", device_id)
                                        .add("sequence", sequence_number));
                }
            }
            catch (const std::exception &e)
            {
                logger_->warning("Failed to send ACK packet",
                                core::LogContext()
                                    .add("device_id", device_id)
                                    .add("sequence", sequence_number)
                                    .add("error", e.what()));
            }
        }

        void DeviceManagementService::notify_device_connected(const std::string &device_id)
        {
            logger_->info("Device connected notification",
                          core::LogContext().add("device_id", device_id));
        }

        void DeviceManagementService::notify_device_disconnected(const std::string &device_id)
        {
            logger_->info("Device disconnected notification",
                          core::LogContext().add("device_id", device_id));
        }

        ManagedDevice *DeviceManagementService::find_device(const std::string &device_id)
        {
            auto it = managed_devices_.find(device_id);
            return (it != managed_devices_.end()) ? &it->second : nullptr;
        }

        const ManagedDevice *DeviceManagementService::find_device(const std::string &device_id) const
        {
            auto it = managed_devices_.find(device_id);
            return (it != managed_devices_.end()) ? &it->second : nullptr;
        }

    } // namespace services
} // namespace mita