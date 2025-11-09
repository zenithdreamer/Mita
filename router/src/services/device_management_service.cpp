#include "services/device_management_service.hpp"
#include "services/routing_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"
#include "core/logger.hpp"
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>

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

                // reuse existing device entry
                it->second.state = DeviceState::CONNECTING;
                it->second.transport_type = transport_type;
                it->second.connected_time = std::chrono::steady_clock::now();
                it->second.last_activity = std::chrono::steady_clock::now();
                it->second.session_crypto.reset();

                // Reset sequence tracking on reconnect
                reset_sequence_tracking(&it->second);

                it->second.state = DeviceState::HANDSHAKING;

                logger_->info("device reconnect",
                              core::LogContext().add("device_id", device_id).add("address", it->second.assigned_address).add("transport_type", static_cast<int>(transport_type)));

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

            // Set session expiration (1 hour from now)
            device->session_created = std::chrono::steady_clock::now();
            device->session_expires = device->session_created + ManagedDevice::SESSION_LIFETIME;

            // Reset sequence tracking on new authentication
            // This ensures fresh sequence validation for the new session
            reset_sequence_tracking(device);

            // Update routing service with session crypto
            routing_service_.set_session_crypto(device_id, session_crypto);

#ifdef DEBUG_CRYPTO
            // DEBUG: Log session key for decryption (ONLY in debug builds)
            std::vector<uint8_t> session_key = session_crypto->get_session_key();
            std::stringstream key_hex;
            for (size_t i = 0; i < session_key.size(); i++)
            {
                key_hex << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(session_key[i]);
            }
            logger_->debug("Device authenticated - session key",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("address", device->assigned_address)
                               .add("session_key", key_hex.str()));
#else
            logger_->info("Device authenticated",
                          core::LogContext()
                              .add("device_id", device_id)
                              .add("address", device->assigned_address));
#endif

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
                                                    core::TransportType transport_type,
                                                    const std::string &current_fingerprint)
        {
            if (!running_)
            {
                return;
            }

            logger_->debug("handle_packet ENTRY",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("msg_type", static_cast<int>(packet.get_message_type()))
                               .add("seq", packet.get_sequence_number()));

            try
            {
                // Validate transport fingerprint for authenticated devices (except HELLO)
                // This prevents session hijacking attacks
                if (packet.get_message_type() != MessageType::HELLO && !current_fingerprint.empty())
                {
                    std::shared_lock<std::shared_mutex> lock(devices_mutex_);
                    const auto *device = find_device(device_id);

                    if (device && device->state != DeviceState::HANDSHAKING)
                    {
                        // Validate against stored fingerprint
                        if (!validate_transport_fingerprint(device, current_fingerprint))
                        {
                            logger_->error("SECURITY: Transport fingerprint validation failed - rejecting packet",
                                           core::LogContext()
                                               .add("device_id", device_id)
                                               .add("msg_type", static_cast<int>(packet.get_message_type())));

                            send_error_packet(device_id, 0x0A, packet.get_sequence_number(), transport_type);
                            statistics_service_.record_protocol_error();
                            return; // Reject packet
                        }
                    }
                }

                // Capture incoming packet for monitoring and get packet ID
                std::string packet_id;
                if (packet_monitor_)
                {
                    logger_->debug("ABOUT TO CAPTURE packet", core::LogContext().add("seq", packet.get_sequence_number()));
                    packet_id = packet_monitor_->capture_packet(packet, "inbound", transport_type);
                    logger_->debug("CAPTURED packet", core::LogContext().add("packet_id", packet_id));
                }

                update_device_activity(device_id);

                // Process packet based on message type
                switch (packet.get_message_type())
                {
                case MessageType::HELLO:
                    process_hello_packet(device_id, packet);
                    break;

                case MessageType::DATA:
                    logger_->debug("CALLING process_data_packet", core::LogContext().add("packet_id", packet_id));
                    process_data_packet(device_id, packet, transport_type, packet_id);
                    logger_->debug("RETURNED from process_data_packet", core::LogContext().add("packet_id", packet_id));
                    break;

                case MessageType::CONTROL:
                    process_control_packet(device_id, packet);
                    break;

                case MessageType::HEARTBEAT:
                    // Heartbeat rate limiting to prevent flood attacks
                    {
                        std::unique_lock<std::shared_mutex> lock(devices_mutex_);
                        auto *device = find_device(device_id);
                        if (device)
                        {
                            auto now = std::chrono::steady_clock::now();
                            auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
                                now - device->last_heartbeat_time);

                            // Reset counter if window expired
                            if (time_since_last >= ManagedDevice::HEARTBEAT_WINDOW)
                            {
                                device->heartbeat_count = 0;
                                device->last_heartbeat_time = now;
                            }

                            device->heartbeat_count++;

                            // Check rate limit
                            if (device->heartbeat_count > ManagedDevice::MAX_HEARTBEATS_PER_WINDOW)
                            {
                                logger_->warning("SECURITY: Heartbeat flood detected - dropping packet",
                                                 core::LogContext()
                                                     .add("device_id", device_id)
                                                     .add("count", device->heartbeat_count));
                                statistics_service_.record_protocol_error();
                                return; // Drop excessive heartbeats
                            }

                            logger_->debug("Received HEARTBEAT packet",
                                           core::LogContext()
                                               .add("device_id", device_id)
                                               .add("count", device->heartbeat_count));
                        }
                    }
                    break;

                case MessageType::DISCONNECT:
                    process_disconnect_packet(device_id, packet, transport_type);
                    break;

                case MessageType::SESSION_REKEY_REQ:
                    process_session_rekey_packet(device_id, packet, transport_type);
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
                // Create data packet with sequence number
                protocol::ProtocolPacket packet(MessageType::DATA,
                                                0, // Router address
                                                device->assigned_address,
                                                message);

                // Set sequence number (simple incrementing counter)
                static std::atomic<uint16_t> router_sequence_counter{0};
                uint16_t seq = router_sequence_counter.fetch_add(1);
                packet.set_sequence_number(seq);

                // Encrypt with AAD if session crypto is available
                if (device->session_crypto)
                {
                    // Build AAD from packet header
                    std::vector<uint8_t> aad;
                    aad.push_back((packet.get_source_addr() >> 8) & 0xFF);
                    aad.push_back(packet.get_source_addr() & 0xFF);
                    aad.push_back((packet.get_dest_addr() >> 8) & 0xFF);
                    aad.push_back(packet.get_dest_addr() & 0xFF);
                    aad.push_back((seq >> 8) & 0xFF);
                    aad.push_back(seq & 0xFF);

                    auto encrypted_payload = device->session_crypto->encrypt_gcm(message, aad);
                    packet.set_payload(encrypted_payload);
                    packet.set_encrypted(true);
                }

                // Capture outbound packet for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(packet, "outbound", device->transport_type);
                    packet.set_encrypted(true);
                }

                // validate routee
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
                        catch (const std::exception &e)
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
            size_t count = 0;
            for (const auto &[id, device] : managed_devices_)
            {
                if (device.state == DeviceState::ACTIVE || device.state == DeviceState::AUTHENTICATED)
                {
                    count++;
                }
            }
            return count;
        }

        size_t DeviceManagementService::get_device_count_by_transport(core::TransportType transport) const
        {
            std::shared_lock<std::shared_mutex> lock(devices_mutex_);
            size_t count = 0;
            for (const auto &[id, device] : managed_devices_)
            {
                if (device.transport_type == transport &&
                    (device.state == DeviceState::ACTIVE || device.state == DeviceState::AUTHENTICATED))
                {
                    count++;
                }
            }
            return count;
        }

        RouterStatisticsSnapshot DeviceManagementService::get_statistics_snapshot() const
        {
            return statistics_service_.get_statistics();
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

            // Check for expired sessions and force re-authentication
            std::vector<std::string> expired_devices;
            {
                std::shared_lock<std::shared_mutex> lock(devices_mutex_);
                for (const auto &[device_id, device] : managed_devices_)
                {
                    if (device.session_crypto && device.is_session_expired())
                    {
                        expired_devices.push_back(device_id);
                    }
                }
            }

            // Force re-authentication for expired sessions
            for (const std::string &device_id : expired_devices)
            {
                logger_->info("Session expired - forcing device to re-authenticate",
                              core::LogContext()
                                  .add("device_id", device_id)
                                  .add("session_lifetime_hours",
                                       ManagedDevice::SESSION_LIFETIME.count() / 3600));

                std::unique_lock<std::shared_mutex> lock(devices_mutex_);
                auto *device = find_device(device_id);
                if (device)
                {
                    device->state = DeviceState::CONNECTING;
                    device->session_crypto.reset();
                    device->sequence_initialized = false;
                }
            }
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
                                                          core::TransportType transport_type,
                                                          const std::string &packet_id)
        {
            // Get mutable device pointer for sequence tracking updates
            ManagedDevice *device = find_device(device_id);
            if (!device || (device->state != DeviceState::ACTIVE && device->state != DeviceState::AUTHENTICATED))
            {
                logger_->warning("Received data packet from inactive device",
                                 core::LogContext().add("device_id", device_id));
                return;
            }

            // Check session expiration - force re-authentication if expired
            if (device->is_session_expired())
            {
                logger_->warning("Session expired - forcing re-authentication",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("session_age_minutes",
                                          std::chrono::duration_cast<std::chrono::minutes>(
                                              std::chrono::steady_clock::now() - device->session_created)
                                              .count()));

                // Force device to re-authenticate
                device->state = DeviceState::CONNECTING;
                device->session_crypto.reset();
                statistics_service_.record_protocol_error();
                return;
            }

            // Validate timestamp freshness (max 60 seconds old)
            // Protects against replay attacks with old but valid sequence numbers
            if (!validate_packet_timestamp(packet.get_timestamp()))
            {
                logger_->warning("Packet rejected due to stale timestamp",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("timestamp", packet.get_timestamp()));
                statistics_service_.record_stale_packet();
                statistics_service_.record_protocol_error();

                // Flag packet as dropped in monitor
                if (packet_monitor_ && !packet_id.empty())
                {
                    packet_monitor_->update_packet_error(
                        packet_id,
                        "DROPPED: Stale timestamp - possible replay attack",
                        false // is_valid = false
                    );
                }

                // Send ERROR message to client
                send_error_packet(device_id, 0x02, packet.get_sequence_number(), transport_type); // STALE_TIMESTAMP

                return;
            }

            // Validate sequence number before processing packet
            // This protects against replay attacks, packet injection, and detects packet loss
            if (!validate_sequence_number(device, packet.get_sequence_number()))
            {
                logger_->warning("Packet rejected due to invalid sequence number",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("sequence", packet.get_sequence_number()));
                statistics_service_.record_protocol_error();

                // Flag packet as dropped in monitor
                if (packet_monitor_ && !packet_id.empty())
                {
                    packet_monitor_->update_packet_error(
                        packet_id,
                        "DROPPED: Invalid/duplicate sequence number",
                        false // is_valid = false
                    );
                }

                // Send ERROR message to client
                send_error_packet(device_id, 0x01, packet.get_sequence_number(), transport_type); // INVALID_SEQUENCE

                // Don't send ACK for invalid sequence
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
                    // Build AAD from packet header for authenticated encryption
                    // This prevents header manipulation attacks
                    std::vector<uint8_t> aad;
                    aad.push_back((packet.get_source_addr() >> 8) & 0xFF);
                    aad.push_back(packet.get_source_addr() & 0xFF);
                    aad.push_back((packet.get_dest_addr() >> 8) & 0xFF);
                    aad.push_back(packet.get_dest_addr() & 0xFF);
                    aad.push_back((packet.get_sequence_number() >> 8) & 0xFF);
                    aad.push_back(packet.get_sequence_number() & 0xFF);

                    // Use AES-GCM for authenticated encryption
                    // GCM provides both confidentiality and authenticity in one operation
                    payload = device->session_crypto->decrypt_gcm(payload, aad);
                    decrypted = true;

                    logger_->debug("GCM decryption successful with AAD verification",
                                   core::LogContext()
                                       .add("device_id", device_id)
                                       .add("decrypted_size", payload.size()));

                    // Store decrypted payload in packet monitor
                    if (packet_monitor_ && !packet_id.empty())
                    {
                        // Convert decrypted payload to string for storage
                        std::string decrypted_str(payload.begin(), payload.end());
                        packet_monitor_->update_packet_decrypted(packet_id, decrypted_str);
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->error("GCM authentication/decryption failed - possible tampering or header modification",
                                   core::LogContext().add("device_id", device_id).add("error", e.what()));
                    statistics_service_.record_protocol_error();

                    // Flag the existing packet with GCM authentication failure
                    if (packet_monitor_ && !packet_id.empty())
                    {
                        packet_monitor_->update_packet_error(
                            packet_id,
                            "GCM_AUTH_FAIL: Authentication tag verification failed - possible tampering or key mismatch",
                            false // is_valid = false
                        );

                        logger_->warning("Flagged packet with GCM authentication failure",
                                         core::LogContext()
                                             .add("packet_id", packet_id)
                                             .add("device_id", device_id));
                    }

                    return; // Reject packet if GCM verification fails
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

            // Forwarding case - check TTL to prevent routing loops
            uint16_t dest_addr = packet.get_dest_addr();
            if (dest_addr != 0 && dest_addr != 0xFFFF && dest_addr != device->assigned_address)
            {
                // Check TTL before forwarding
                if (packet.get_ttl() == 0)
                {
                    logger_->warning("Packet TTL expired - dropping",
                                     core::LogContext()
                                         .add("from_device", device_id)
                                         .add("dest_addr", dest_addr));
                    statistics_service_.record_protocol_error();
                    return;
                }

                // Create mutable copy of packet to decrement TTL
                protocol::ProtocolPacket forward_packet = packet;
                forward_packet.decrement_ttl();

                // Check if TTL reached zero after decrement
                if (forward_packet.get_ttl() == 0)
                {
                    logger_->warning("Packet TTL will expire after hop - dropping",
                                     core::LogContext()
                                         .add("from_device", device_id)
                                         .add("dest_addr", dest_addr));
                    // TODO: Send ICMP-like TTL exceeded message back to source
                    statistics_service_.record_protocol_error();
                    return;
                }

                const auto *route = routing_service_.get_route(dest_addr);
                bool forward_success = false;

                if (route)
                {
                    if (send_message_to_device(route->device_id, payload))
                    {
                        logger_->debug("Packet forwarded successfully",
                                       core::LogContext()
                                           .add("from_device", device_id)
                                           .add("to_device", route->device_id)
                                           .add("ttl", forward_packet.get_ttl()));
                        forward_success = true;
                    }
                    else
                    {
                        logger_->warning("Failed to forward packet - destination unreachable",
                                         core::LogContext()
                                             .add("from_device", device_id)
                                             .add("to_device", route->device_id));
                        statistics_service_.record_protocol_error();

                        // Send ERROR: destination exists in routing table but unreachable
                        send_error_packet(device_id, 0x04, packet.get_sequence_number(), transport_type); // INVALID_DESTINATION
                        return;
                    }
                }
                else
                {
                    logger_->warning("No route found for destination",
                                     core::LogContext()
                                         .add("dest_addr", dest_addr)
                                         .add("source_device", device_id));
                    statistics_service_.record_protocol_error();

                    // Send ERROR: destination address unknown
                    send_error_packet(device_id, 0x04, packet.get_sequence_number(), transport_type); // INVALID_DESTINATION
                    return;
                }

                // Hub-and-spoke hop-by-hop ACK: Router ACKs after successful forward
                // This provides transport-layer reliability - application can add its own ACKs if needed
                uint8_t priority_flags = packet.get_priority_flags();
                bool requires_ack = (priority_flags & 0x20) != 0; // FLAG_QOS_RELIABLE
                bool no_ack = (priority_flags & 0x10) != 0;       // FLAG_QOS_NO_ACK

                if (forward_success && (requires_ack || (!no_ack && !requires_ack)))
                {
                    logger_->info("Sending hop-by-hop ACK after successful forward",
                                  core::LogContext()
                                      .add("device_id", device_id)
                                      .add("sequence", packet.get_sequence_number())
                                      .add("dest_addr", dest_addr));
                    send_ack_packet(device_id, packet.get_sequence_number(), transport_type);
                }

                return;
            }

            // Packet addressed to router (dest=0x0000) - process locally, don't forward
            // Application logic can be added here to handle different payload types
            logger_->debug("DATA packet received for router processing",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("payload_size", payload.size()));

            statistics_service_.record_packet_routed(payload.size());

            // Send ACK packet back to device if QoS requires it
            uint8_t priority_flags = packet.get_priority_flags();
            bool requires_ack = (priority_flags & 0x20) != 0; // FLAG_QOS_RELIABLE
            bool no_ack = (priority_flags & 0x10) != 0;       // FLAG_QOS_NO_ACK

            if (requires_ack || (!no_ack && !requires_ack)) // Default to ACK if no QoS flag set
            {
                logger_->info("Sending ACK for DATA packet",
                              core::LogContext()
                                  .add("device_id", device_id)
                                  .add("sequence", packet.get_sequence_number())
                                  .add("qos", requires_ack ? "RELIABLE" : "DEFAULT")
                                  .add("transport", transport_type == core::TransportType::WIFI ? "wifi" : "ble"));
                send_ack_packet(device_id, packet.get_sequence_number(), transport_type);
            }
            else
            {
                logger_->debug("Skipping ACK for NO_QOS DATA packet",
                               core::LogContext()
                                   .add("device_id", device_id)
                                   .add("sequence", packet.get_sequence_number()));
            }
        }

        void DeviceManagementService::process_control_packet(const std::string &device_id,
                                                             const protocol::ProtocolPacket &packet)
        {
            logger_->debug("Processing CONTROL packet",
                           core::LogContext().add("device_id", device_id));

            const ManagedDevice *device = get_device_info(device_id);
            if (!device)
            {
                return;
            }

            // Parse control type from payload
            if (packet.get_payload().size() < 1)
            {
                return;
            }

            uint8_t control_type = packet.get_payload()[0];

            if (control_type == 0x00) // ControlType::PING
            {
                // Respond with PONG - echo back the timestamp
                try
                {
                    std::vector<uint8_t> pong_payload;
                    pong_payload.push_back(0x01); // ControlType::PONG

                    // Echo back the timestamp (bytes 1-4)
                    if (packet.get_payload().size() >= 5)
                    {
                        for (size_t i = 1; i < 5; i++)
                        {
                            pong_payload.push_back(packet.get_payload()[i]);
                        }
                    }

                    protocol::ProtocolPacket pong_packet(
                        MessageType::CONTROL,
                        ROUTER_ADDRESS,
                        device->assigned_address,
                        pong_payload);

                    // Capture outbound PONG for monitoring
                    if (packet_monitor_)
                    {
                        packet_monitor_->capture_packet(pong_packet, "outbound", device->transport_type);
                    }

                    if (routing_service_.forward_to_device(device->assigned_address, pong_packet))
                    {
                        logger_->debug("Sent PONG response",
                                       core::LogContext().add("device_id", device_id));
                    }
                }
                catch (const std::exception &e)
                {
                    logger_->warning("Failed to send PONG response",
                                     core::LogContext()
                                         .add("device_id", device_id)
                                         .add("error", e.what()));
                }
            }
            // TODO: Handle other control types (TIME_SYNC, CONFIG_UPDATE, etc.)
        }

        void DeviceManagementService::process_disconnect_packet(const std::string &device_id,
                                                                const protocol::ProtocolPacket &packet,
                                                                core::TransportType transport_type)
        {
            const ManagedDevice *device = get_device_info(device_id);
            if (!device)
            {
                return;
            }

            // Parse disconnect reason from payload
            uint8_t reason_code = 0xFF; // Unknown reason
            if (packet.get_payload().size() >= 1)
            {
                reason_code = packet.get_payload()[0];
            }

            const char *reason_str = "UNKNOWN";
            switch (reason_code)
            {
            case 0x00:
                reason_str = "NORMAL_SHUTDOWN";
                break;
            case 0x01:
                reason_str = "GOING_TO_SLEEP";
                break;
            case 0x02:
                reason_str = "LOW_BATTERY";
                break;
            case 0x03:
                reason_str = "NETWORK_SWITCH";
                break;
            case 0x04:
                reason_str = "FIRMWARE_UPDATE";
                break;
            case 0x05:
                reason_str = "USER_REQUEST";
                break;
            case 0xFF:
                reason_str = "ERROR";
                break;
            }

            logger_->info("Received DISCONNECT from device",
                          core::LogContext()
                              .add("device_id", device_id)
                              .add("reason_code", reason_code)
                              .add("reason", reason_str));

            // Send DISCONNECT_ACK
            try
            {
                protocol::ProtocolPacket disconnect_ack(
                    MessageType::DISCONNECT_ACK,
                    ROUTER_ADDRESS,
                    device->assigned_address,
                    {} // No payload needed
                );

                // Capture outbound DISCONNECT_ACK for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(disconnect_ack, "outbound", transport_type);
                }

                if (routing_service_.forward_to_device(device->assigned_address, disconnect_ack))
                {
                    logger_->debug("Sent DISCONNECT_ACK",
                                   core::LogContext().add("device_id", device_id));
                }
            }
            catch (const std::exception &e)
            {
                logger_->warning("Failed to send DISCONNECT_ACK",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("error", e.what()));
            }

            // TODO: Keep session cached for fast reconnect (5 minutes)
            // For now, just mark as graceful disconnect and let normal cleanup handle it
            logger_->info("Device gracefully disconnected",
                          core::LogContext()
                              .add("device_id", device_id)
                              .add("reason", reason_str));

            // Notify disconnection (will trigger cleanup)
            notify_device_disconnected(device_id);
        }

        void DeviceManagementService::process_session_rekey_packet(const std::string &device_id,
                                                                   const protocol::ProtocolPacket &packet,
                                                                   core::TransportType transport_type)
        {
            logger_->info("Processing SESSION_REKEY_REQ",
                          core::LogContext().add("device_id", device_id));

            const ManagedDevice *device = get_device_info(device_id);
            if (!device)
            {
                logger_->warning("Received SESSION_REKEY_REQ from unregistered device",
                                 core::LogContext().add("device_id", device_id));
                return;
            }

            try
            {
                // Parse payload: [packets_sent(4 bytes)] + [new_client_nonce(16 bytes)]
                auto payload = packet.get_payload();
                if (payload.size() < 20)
                {
                    logger_->warning("SESSION_REKEY_REQ payload too short",
                                     core::LogContext()
                                         .add("device_id", device_id)
                                         .add("size", payload.size()));
                    return;
                }

                // Extract packets_sent counter
                uint32_t packets_sent = (static_cast<uint32_t>(payload[0]) << 24) |
                                        (static_cast<uint32_t>(payload[1]) << 16) |
                                        (static_cast<uint32_t>(payload[2]) << 8) |
                                        static_cast<uint32_t>(payload[3]);

                // Extract new client nonce (nonce3)
                std::vector<uint8_t> new_client_nonce(payload.begin() + 4, payload.begin() + 20);

                logger_->info("Session rekey request received",
                              core::LogContext()
                                  .add("device_id", device_id)
                                  .add("packets_sent", std::to_string(packets_sent)));

                // Generate new router nonce (nonce4) using secure random
                std::vector<uint8_t> new_router_nonce(16);
                RAND_bytes(new_router_nonce.data(), 16);

                // Derive new session key from old key + both nonces
                {
                    std::unique_lock<std::shared_mutex> lock(devices_mutex_);
                    auto *device_mut = find_device(device_id);
                    if (device_mut && device_mut->session_crypto)
                    {
                        try
                        {
                            // Rekey the session crypto
                            device_mut->session_crypto->rekey(new_client_nonce, new_router_nonce);

                            // Update session expiry (extend by another hour)
                            device_mut->session_expires = std::chrono::steady_clock::now() + ManagedDevice::SESSION_LIFETIME;

                            logger_->info("Session key rotated successfully",
                                          core::LogContext()
                                              .add("device_id", device_id)
                                              .add("packets_sent", std::to_string(packets_sent)));

                            // Record successful session rekey in statistics
                            statistics_service_.record_session_rekey();
                        }
                        catch (const std::exception &e)
                        {
                            logger_->error("Failed to rekey session",
                                           core::LogContext()
                                               .add("device_id", device_id)
                                               .add("error", e.what()));
                            return; // Don't send ACK if rekey failed
                        }
                    }
                    else
                    {
                        logger_->warning("No session crypto available for rekey",
                                         core::LogContext().add("device_id", device_id));
                        return;
                    }
                }

                // Create SESSION_REKEY_ACK packet with new router nonce
                protocol::ProtocolPacket rekey_ack(
                    MessageType::SESSION_REKEY_ACK,
                    ROUTER_ADDRESS,
                    device->assigned_address,
                    new_router_nonce // Payload is the new router nonce
                );

                // Capture outbound SESSION_REKEY_ACK for monitoring
                if (packet_monitor_)
                {
                    packet_monitor_->capture_packet(rekey_ack, "outbound", transport_type);
                }

                // Send SESSION_REKEY_ACK
                if (routing_service_.forward_to_device(device->assigned_address, rekey_ack))
                {
                    logger_->info("Sent SESSION_REKEY_ACK",
                                  core::LogContext().add("device_id", device_id));

                    // TODO: Update session key in device state after deriving new key
                    // This would require updating the ManagedDevice struct to store
                    // session keys and integrating with CryptoService
                }
                else
                {
                    logger_->warning("Failed to send SESSION_REKEY_ACK",
                                     core::LogContext().add("device_id", device_id));
                }
            }
            catch (const std::exception &e)
            {
                logger_->error("Error processing SESSION_REKEY_REQ",
                               core::LogContext()
                                   .add("device_id", device_id)
                                   .add("error", e.what()));
            }
        }

        void DeviceManagementService::send_error_packet(const std::string &device_id,
                                                        uint8_t error_code,
                                                        uint16_t failed_sequence,
                                                        core::TransportType transport_type)
        {
            const ManagedDevice *device = get_device_info(device_id);
            if (!device)
            {
                return;
            }

            try
            {
                // Create ERROR packet with error code and failed sequence
                std::vector<uint8_t> payload;
                payload.push_back(error_code);                    // Error code
                payload.push_back((failed_sequence >> 8) & 0xFF); // Sequence high byte
                payload.push_back(failed_sequence & 0xFF);        // Sequence low byte

                protocol::ProtocolPacket error_packet(
                    MessageType::ERROR,
                    ROUTER_ADDRESS,
                    device->assigned_address,
                    payload);

                // Validate route
                if (!routing_service_.forward_to_device(device->assigned_address, error_packet))
                {
                    logger_->warning("Failed to validate route for ERROR packet",
                                     core::LogContext()
                                         .add("device_id", device_id)
                                         .add("error_code", error_code));
                    return;
                }

                // Actually send via transport handler
                std::string handler_name = (transport_type == core::TransportType::WIFI) ? "wifi" : "ble";
                bool sent = false;
                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    auto handler_it = message_handlers_.find(handler_name);
                    if (handler_it != message_handlers_.end())
                    {
                        try
                        {
                            handler_it->second(device_id, error_packet);
                            sent = true;
                        }
                        catch (const std::exception &e)
                        {
                            logger_->error("Transport handler failed for ERROR",
                                           core::LogContext()
                                               .add("device_id", device_id)
                                               .add("error", e.what()));
                        }
                    }
                    else
                    {
                        logger_->warning("Transport handler not found for ERROR",
                                         core::LogContext().add("handler_name", handler_name));
                    }
                }

                if (sent)
                {
                    const char *error_str = "UNKNOWN";
                    switch (error_code)
                    {
                    case 0x01:
                        error_str = "INVALID_SEQUENCE";
                        break;
                    case 0x02:
                        error_str = "STALE_TIMESTAMP";
                        break;
                    case 0x03:
                        error_str = "DECRYPTION_FAILED";
                        break;
                    case 0x04:
                        error_str = "INVALID_DESTINATION";
                        break;
                    case 0x05:
                        error_str = "TTL_EXPIRED";
                        break;
                    case 0x06:
                        error_str = "RATE_LIMIT_EXCEEDED";
                        break;
                    case 0x07:
                        error_str = "SESSION_EXPIRED";
                        break;
                    case 0x08:
                        error_str = "MALFORMED_PACKET";
                        break;
                    case 0x09:
                        error_str = "UNSUPPORTED_VERSION";
                        break;
                    case 0x0A:
                        error_str = "AUTHENTICATION_FAILED";
                        break;
                    }

                    logger_->debug("Sent ERROR packet",
                                   core::LogContext()
                                       .add("device_id", device_id)
                                       .add("error_code", static_cast<int>(error_code))
                                       .add("error", error_str)
                                       .add("failed_sequence", failed_sequence));
                }
                else
                {
                    logger_->warning("Failed to send ERROR packet via transport",
                                     core::LogContext()
                                         .add("device_id", device_id)
                                         .add("error_code", error_code));
                }
            }
            catch (const std::exception &e)
            {
                logger_->warning("Failed to send ERROR packet",
                                 core::LogContext()
                                     .add("device_id", device_id)
                                     .add("error", e.what()));
            }
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
                    ROUTER_ADDRESS,           // source is router
                    device->assigned_address, // destination is the device
                    payload);

                // Validate route
                if (!routing_service_.forward_to_device(device->assigned_address, ack_packet))
                {
                    logger_->warning("Failed to validate route for ACK packet",
                                     core::LogContext()
                                         .add("device_id", device_id)
                                         .add("sequence", sequence_number));
                    return;
                }

                // Actually send via transport handler
                std::string handler_name = (transport_type == core::TransportType::WIFI) ? "wifi" : "ble";
                bool sent = false;

                logger_->debug("Attempting to send ACK via transport",
                               core::LogContext()
                                   .add("device_id", device_id)
                                   .add("handler_name", handler_name)
                                   .add("sequence", sequence_number));

                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    auto handler_it = message_handlers_.find(handler_name);
                    if (handler_it != message_handlers_.end())
                    {
                        logger_->debug("Found transport handler, calling it",
                                       core::LogContext().add("handler_name", handler_name));
                        try
                        {
                            handler_it->second(device_id, ack_packet);
                            sent = true;
                            logger_->debug("Transport handler executed successfully",
                                           core::LogContext().add("handler_name", handler_name));
                        }
                        catch (const std::exception &e)
                        {
                            logger_->error("Transport handler failed for ACK",
                                           core::LogContext()
                                               .add("device_id", device_id)
                                               .add("error", e.what()));
                        }
                    }
                    else
                    {
                        logger_->warning("Transport handler not found for ACK",
                                         core::LogContext().add("handler_name", handler_name));
                    }
                }

                if (sent)
                {
                    logger_->info("ACK packet sent successfully",
                                  core::LogContext()
                                      .add("device_id", device_id)
                                      .add("sequence", sequence_number)
                                      .add("transport", handler_name)
                                      .add("dest_addr", device->assigned_address));
                }
                else
                {
                    logger_->warning("Failed to send ACK packet via transport",
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

        // Validates sequence numbers to prevent replay attacks
        // Uses sliding window approach to track recent packets
        bool DeviceManagementService::validate_sequence_number(ManagedDevice *device, uint16_t seq)
        {
            if (!device)
            {
                return false;
            }

            // First packet after auth - initialize sequence tracking
            if (!device->sequence_initialized)
            {
                // SECURITY: Require first sequence to be in reasonable range (0-100)
                // This prevents attackers from starting with high sequence numbers
                // which could manipulate the sequence window
                if (seq > 100)
                {
                    logger_->warning("SECURITY: Suspicious initial sequence number - rejecting",
                                     core::LogContext()
                                         .add("device_id", device->device_id)
                                         .add("sequence", seq));
                    statistics_service_.record_protocol_error();
                    return false;
                }

                device->last_valid_sequence = seq;
                device->expected_next_sequence = (seq + 1) % 65536;
                device->sequence_initialized = true;
                device->last_sequence_time = std::chrono::steady_clock::now();
                device->recent_sequences.push_back(seq);

                logger_->debug("Sequence tracking initialized",
                               core::LogContext()
                                   .add("device_id", device->device_id)
                                   .add("initial_sequence", seq));
                return true;
            }

            // Check for exact duplicate (replay attack detection)
            // This prevents retransmission of captured packets
            if (std::find(device->recent_sequences.begin(),
                          device->recent_sequences.end(),
                          seq) != device->recent_sequences.end())
            {
                logger_->warning("SECURITY: Duplicate sequence detected - possible replay attack",
                                 core::LogContext()
                                     .add("device_id", device->device_id)
                                     .add("sequence", seq)
                                     .add("last_valid", device->last_valid_sequence));
                statistics_service_.record_replay_attempt();
                statistics_service_.record_protocol_error();
                return false; // REJECT duplicate
            }

            // Handle wrap-around (65535 → 0)
            // Consider it a wrap if last sequence > 60000 and new sequence < 5000
            bool is_wrap = (device->last_valid_sequence > 60000 && seq < 5000);

            // Calculate sequence difference
            int32_t seq_diff;
            if (is_wrap)
            {
                seq_diff = (65536 + seq) - device->last_valid_sequence;
            }
            else
            {
                seq_diff = static_cast<int32_t>(seq) - static_cast<int32_t>(device->last_valid_sequence);
            }

            // Accept only if within reasonable window (1-32 ahead)
            // Tighter window (32 instead of 100) provides better replay protection
            if (seq_diff > 0 && seq_diff <= static_cast<int32_t>(ManagedDevice::SEQUENCE_WINDOW_SIZE))
            {
                // Reject gaps larger than 3 packets to prevent attack (reduced from 5 for stricter security)
                const int MAX_ACCEPTABLE_GAP = 3;
                if (seq_diff > MAX_ACCEPTABLE_GAP)
                {
                    logger_->warning("SECURITY: Sequence gap too large - possible attack",
                                     core::LogContext()
                                         .add("device_id", device->device_id)
                                         .add("expected", device->expected_next_sequence)
                                         .add("received", seq)
                                         .add("gap_size", seq_diff));
                    statistics_service_.record_protocol_error();
                    return false; // REJECT large gaps
                }

                // Valid new sequence
                if (seq_diff > 1)
                {
                    logger_->warning("Sequence gap detected - possible packet loss",
                                     core::LogContext()
                                         .add("device_id", device->device_id)
                                         .add("expected", device->expected_next_sequence)
                                         .add("received", seq)
                                         .add("gap_size", seq_diff - 1));
                    statistics_service_.record_sequence_gap();
                }

                // Update sliding window tracking
                device->recent_sequences.push_back(seq);
                if (device->recent_sequences.size() > ManagedDevice::SEQUENCE_WINDOW_SIZE)
                {
                    device->recent_sequences.pop_front();
                }
                device->last_valid_sequence = seq;
                device->expected_next_sequence = (seq + 1) % 65536;
                device->last_sequence_time = std::chrono::steady_clock::now();

                return true;
            }

            // Sequence too old or too far ahead - reject
            // Prevents replay of old packets and random sequence injection
            logger_->warning("SECURITY: Sequence number out of acceptable range - possible attack",
                             core::LogContext()
                                 .add("device_id", device->device_id)
                                 .add("last_valid", device->last_valid_sequence)
                                 .add("received", seq)
                                 .add("difference", seq_diff)
                                 .add("is_wrap", is_wrap));
            statistics_service_.record_protocol_error();
            return false; // REJECT
        }

        bool DeviceManagementService::validate_packet_timestamp(uint32_t timestamp)
        {
            // This validates relative time freshness, NOT absolute time
            // Works without RTC - both router and client use millis() since boot
            // The 32-bit timestamp wraps every ~49 days (much better than 16-bit's 65 seconds)

            // Get current time in milliseconds using the same origin as protocol packets
            uint64_t now_ms = protocol::utils::get_current_timestamp_ms();
            uint32_t current_time = static_cast<uint32_t>(now_ms);

            // Calculate age with wrap-around handling
            uint32_t age;
            if (current_time >= timestamp)
            {
                age = current_time - timestamp;
            }
            else
            {
                // Wrapped around (timestamp is from before the wrap)
                age = (UINT32_MAX - timestamp) + current_time + 1;
            }

            // Being lenient, reject only if EXTREMELY old (> 60 seconds)
            // This protects against replay attacks with very old packets
            // But won't reject packets due to minor clock drift between devices
            const uint32_t MAX_PACKET_AGE_MS = 60000; // 60 seconds

            // Accept if age is reasonable (< 60 seconds)
            // For 32-bit, we don't need the complex wrap-around logic from 16-bit version
            if (age > MAX_PACKET_AGE_MS && age < (UINT32_MAX - MAX_PACKET_AGE_MS))
            {
                // Only reject if timestamp is genuinely old (not a clock offset issue)
                return false;
            }

            return true;
        }

        void DeviceManagementService::reset_sequence_tracking(ManagedDevice *device)
        {
            if (!device)
            {
                return;
            }

            device->sequence_initialized = false;
            device->recent_sequences.clear();
            device->last_valid_sequence = 0;
            device->expected_next_sequence = 0;

            logger_->info("Sequence tracking reset",
                          core::LogContext().add("device_id", device->device_id));
        }

        void DeviceManagementService::set_transport_fingerprint(
            const std::string &device_id,
            const std::string &fingerprint)
        {
            std::unique_lock<std::shared_mutex> lock(devices_mutex_);

            auto *device = find_device(device_id);
            if (!device)
            {
                return;
            }

            device->transport_fingerprint = fingerprint;

            logger_->debug("Transport fingerprint set",
                           core::LogContext()
                               .add("device_id", device_id)
                               .add("fingerprint", fingerprint));
        }

        std::string DeviceManagementService::generate_transport_fingerprint(
            const std::string &device_id,
            core::TransportType transport_type) const
        {
            // For now, return device_id as fingerprint
            // This will be enhanced by transport handlers to include IP:port or MAC
            // Transport handlers should call a setter to update the fingerprint
            return device_id + ":" + (transport_type == core::TransportType::WIFI ? "wifi" : "ble");
        }

        bool DeviceManagementService::validate_transport_fingerprint(
            const ManagedDevice *device,
            const std::string &current_fingerprint) const
        {
            if (!device)
            {
                return false;
            }

            // If no fingerprint is set yet, allow (first connection)
            if (device->transport_fingerprint.empty())
            {
                return true;
            }

            // Validate that the fingerprint matches
            if (device->transport_fingerprint != current_fingerprint)
            {
                logger_->warning("Transport fingerprint mismatch - possible session hijacking attempt",
                                 core::LogContext()
                                     .add("device_id", device->device_id)
                                     .add("expected", device->transport_fingerprint)
                                     .add("received", current_fingerprint));
                return false;
            }

            return true;
        }

    } // namespace services
} // namespace mita