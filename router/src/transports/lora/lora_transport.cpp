#include "transports/lora/lora_transport.hpp"
#include "transports/lora/lora_radio.hpp"
#include "transports/lora/lora_client_handler.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "services/routing_service.hpp"
#include "services/device_management_service.hpp"
#include "services/statistics_service.hpp"
#include "services/packet_monitor_service.hpp"

#include <thread>
#include <chrono>

namespace mita
{
    namespace transports
    {
        namespace lora
        {
            LoRaTransport::LoRaTransport(const core::RouterConfig &config,
                                         services::RoutingService &routing_service,
                                         services::DeviceManagementService &device_management,
                                         services::StatisticsService &statistics_service,
                                         std::shared_ptr<services::PacketMonitorService> packet_monitor)
                : core::BaseTransport(config, routing_service, device_management, statistics_service),
                  next_address_(1),
                  running_(false),
                  packet_monitor_(packet_monitor),
                  logger_(core::get_logger("LoRaTransport"))
            {
                logger_->info("LoRa transport created");
            }

            LoRaTransport::~LoRaTransport()
            {
                stop();
            }

            bool LoRaTransport::start()
            {
                if (running_.exchange(true))
                {
                    return true; 
                }

                try
                {
                    logger_->info("Starting LoRa transport");

                    radio_ = std::make_unique<LoRaRadio>(config_);
                    if (!radio_->initialize())
                    {
                        logger_->error("Failed to initialize LoRa radio");
                        running_ = false;
                        return false;
                    }
                    receive_thread_ = std::make_unique<std::thread>(&LoRaTransport::receive_loop, this);

                    logger_->info("LoRa transport started successfully");
                    return true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error starting LoRa transport",
                                   core::LogContext().add("error", e.what()));
                    running_ = false;
                    return false;
                }
            }

            void LoRaTransport::stop()
            {
                if (!running_.exchange(false))
                {
                    return; 
                }

                logger_->info("Stopping LoRa transport");

                if (receive_thread_ && receive_thread_->joinable())
                {
                    receive_thread_->join();
                }

                {
                    std::lock_guard<std::mutex> lock(handlers_mutex_);
                    client_handlers_.clear();
                }

                if (radio_)
                {
                    radio_->shutdown();
                    radio_.reset();
                }

                logger_->info("LoRa transport stopped");
            }

            bool LoRaTransport::send_packet(const std::string &device_id, const protocol::ProtocolPacket &packet)
            {
                if (!running_ || !radio_)
                {
                    logger_->warning("Cannot send packet - transport not running");
                    return false;
                }

                std::lock_guard<std::mutex> lock(handlers_mutex_);

                // Find client handler
                LoRaClientHandler *handler = find_client_by_device_id(device_id);
                if (!handler)
                {
                    logger_->warning("No handler found for device",
                                     core::LogContext().add("device_id", device_id));
                    return false;
                }

                uint8_t lora_addr = handler->get_lora_address();

                // Serialize packet
                std::vector<uint8_t> data = packet.to_bytes();

                // send packet
                bool success = radio_->send(lora_addr, data.data(), data.size());

                if (success)
                {
                    logger_->debug("Packet sent",
                                   core::LogContext()
                                       .add("device_id", device_id)
                                       .add("lora_addr", static_cast<int>(lora_addr))
                                       .add("size", data.size()));
                }
                else
                {
                    logger_->error("Failed to send packet",
                                   core::LogContext()
                                       .add("device_id", device_id)
                                       .add("lora_addr", static_cast<int>(lora_addr)));
                }

                return success;
            }

            int LoRaTransport::broadcast_packet(const protocol::ProtocolPacket &packet)
            {
                if (!running_ || !radio_)
                {
                    logger_->warning("Cannot broadcast - transport not running");
                    return 0;
                }

                int sent_count = 0;
                std::vector<uint8_t> data = packet.to_bytes();

                std::lock_guard<std::mutex> lock(handlers_mutex_);

                for (const auto &[device_id, handler] : client_handlers_)
                {
                    if (handler && handler->is_running())
                    {
                        uint8_t lora_addr = handler->get_lora_address();
                        if (radio_->send(lora_addr, data.data(), data.size()))
                        {
                            sent_count++;
                        }
                    }
                }

                logger_->debug("Broadcast sent",
                               core::LogContext()
                                   .add("clients", sent_count)
                                   .add("size", data.size()));

                return sent_count;
            }

            std::string LoRaTransport::get_connection_info() const
            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);
                return "LoRa [" + std::to_string(client_handlers_.size()) + " devices]";
            }

            std::vector<std::pair<std::string, uint8_t>> LoRaTransport::get_all_device_handlers() const
            {
                std::vector<std::pair<std::string, uint8_t>> result;
                std::lock_guard<std::mutex> lock(handlers_mutex_);

                for (const auto &[device_id, handler] : client_handlers_)
                {
                    if (handler)
                    {
                        result.emplace_back(device_id, handler->get_lora_address());
                    }
                }

                return result;
            }

            void LoRaTransport::receive_loop()
            {
                logger_->info("LoRa receive loop started");

                std::vector<uint8_t> buffer(256); 
                uint8_t src_addr = 0;
                uint8_t dest_addr = 0;

                while (running_)
                {
                    try
                    {

                        int bytes_received = radio_->receive(buffer.data(), buffer.size(), src_addr, dest_addr);

                        if (bytes_received > 0)
                        {

                            logger_->info("LoRa packet received",
                                          core::LogContext()
                                              .add("bytes", bytes_received)
                                              .add("src_addr", static_cast<int>(src_addr))
                                              .add("dest_addr", static_cast<int>(dest_addr))
                                              .add("rssi", radio_->get_rssi())
                                              .add("snr", radio_->get_snr()));

                            if (dest_addr != 0)
                            {
                                logger_->warning("Packet not for router (wrong dest_addr)",
                                                 core::LogContext()
                                                     .add("expected", 0)
                                                     .add("received", static_cast<int>(dest_addr))
                                                     .add("src_addr", static_cast<int>(src_addr)));
                                continue;
                            }

                            // Parse protocol packet
                            try
                            {
                                auto packet = protocol::ProtocolPacket::from_bytes(buffer.data(), bytes_received);

                                handle_incoming_packet(src_addr, *packet);
                            }   
                            catch (const std::exception &e)
                            {
                                logger_->error("Failed to parse received packet",
                                               core::LogContext()
                                                   .add("error", e.what())
                                                   .add("src_addr", static_cast<int>(src_addr)));
                            }
                        }
                        else if (bytes_received == 0)
                        {
                            //
                        }
                        else
                        {
                            logger_->warning("LoRa receive error, retrying");
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Exception in receive loop",
                                       core::LogContext().add("error", e.what()));
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                logger_->info("LoRa receive loop stopped");
            }

            void LoRaTransport::handle_incoming_packet(uint8_t src_addr, const protocol::ProtocolPacket &packet)
            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);

                LoRaClientHandler *handler = find_client_by_lora_addr(src_addr);

                if (!handler)
                {
   
                    logger_->info("New LoRa device detected",
                                  core::LogContext().add("lora_addr", static_cast<int>(src_addr)));

                    SendPacketCallback send_callback = [this](uint8_t dest_addr, const protocol::ProtocolPacket &pkt) -> bool {
                        if (!running_ || !radio_)
                        {
                            return false;
                        }
                        std::vector<uint8_t> data = pkt.to_bytes();
                        bool success = radio_->send(dest_addr, data.data(), data.size());
                        if (success)
                        {
                            logger_->info("Sent packet to LoRa device",
                                          core::LogContext()
                                              .add("dest_addr", static_cast<int>(dest_addr))
                                              .add("msg_type", static_cast<int>(pkt.get_message_type()))
                                              .add("size", data.size()));
                        }
                        return success;
                    };

                    std::string temp_device_id = "lora_" + std::to_string(src_addr);
                    auto new_handler = std::make_unique<LoRaClientHandler>(
                        src_addr,
                        config_,
                        routing_service_,
                        device_management_,
                        statistics_service_,
                        send_callback,
                        packet_monitor_);

                    handler = new_handler.get();
                    client_handlers_[temp_device_id] = std::move(new_handler);

                    // Map LoRa address to device ID
                    std::lock_guard<std::mutex> addr_lock(address_map_mutex_);
                    lora_addr_to_device_[src_addr] = temp_device_id;

                    handler->start(packet);
                }
                else
                {
                    handler->handle_packet(packet);
                }
            }

            LoRaClientHandler *LoRaTransport::find_client_by_device_id(const std::string &device_id)
            {
                auto it = client_handlers_.find(device_id);
                return (it != client_handlers_.end()) ? it->second.get() : nullptr;
            }

            LoRaClientHandler *LoRaTransport::find_client_by_lora_addr(uint8_t lora_addr)
            {
                std::lock_guard<std::mutex> addr_lock(address_map_mutex_);

                auto it = lora_addr_to_device_.find(lora_addr);
                if (it != lora_addr_to_device_.end())
                {
                    return find_client_by_device_id(it->second);
                }

                return nullptr;
            }

            uint8_t LoRaTransport::allocate_lora_address()
            {
                std::lock_guard<std::mutex> addr_lock(address_map_mutex_);

                // find lora address to use
                while (allocated_addresses_.find(next_address_) != allocated_addresses_.end())
                {
                    next_address_++;
                    if (next_address_ == 0 || next_address_ >= 255)
                    {
                        next_address_ = 1;
                    }
                }

                uint8_t addr = next_address_;
                allocated_addresses_.insert(addr);

                logger_->debug("Allocated LoRa address",
                               core::LogContext().add("address", static_cast<int>(addr)));

                return addr;
            }

            void LoRaTransport::cleanup_inactive_clients()
            {
                std::lock_guard<std::mutex> lock(handlers_mutex_);

                auto now = std::chrono::steady_clock::now();
                auto timeout = std::chrono::seconds(config_.routing.device_timeout);

                for (auto it = client_handlers_.begin(); it != client_handlers_.end();)
                {
                    if (it->second && !it->second->is_running())
                    {
                        uint8_t lora_addr = it->second->get_lora_address();

                        logger_->info("Removing inactive LoRa client",
                                      core::LogContext()
                                          .add("device_id", it->first)
                                          .add("lora_addr", static_cast<int>(lora_addr)));


                        {
                            std::lock_guard<std::mutex> addr_lock(address_map_mutex_);
                            lora_addr_to_device_.erase(lora_addr);
                            allocated_addresses_.erase(lora_addr);
                        }

                        it = client_handlers_.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
            }

        } // namespace lora
    }     // namespace transports
} // namespace mita
