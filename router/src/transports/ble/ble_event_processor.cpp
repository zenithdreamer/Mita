#include "transports/ble/ble_event_processor.hpp"
#include "transports/ble/ble_device_handler.hpp"
#include "core/logger.hpp"

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            BLEEventProcessor::BLEEventProcessor(
                BLEEventQueue &event_queue,
                BLEDeviceRegistry &device_registry,
                services::RoutingService &routing_service,
                services::DeviceManagementService &device_management,
                services::StatisticsService &statistics_service)
                : event_queue_(event_queue),
                  device_registry_(device_registry),
                  routing_service_(routing_service),
                  device_management_(device_management),
                  statistics_service_(statistics_service),
                  logger_(core::get_logger("BLEEventProcessor"))
            {
                logger_->info("Event processor created");
            }

            BLEEventProcessor::~BLEEventProcessor()
            {
                stop();
                logger_->info("Event processor destroyed");
            }


            bool BLEEventProcessor::start()
            {
                if (running_)
                {
                    logger_->warning("Event processor already running");
                    return true;
                }

                logger_->info("Starting event processor...");
                running_ = true;

                // Create processor thread
                processor_thread_ = std::make_unique<std::thread>(
                    &BLEEventProcessor::processing_loop, this);

                logger_->info("Event processor started");
                return true;
            }

            void BLEEventProcessor::stop()
            {
                if (!running_)
                {
                    return;
                }

                logger_->info("Stopping event processor...");
                running_ = false;

                // wake up thread so it can exit
                event_queue_.stop();

                // wait for processor thread to finish
                if (processor_thread_ && processor_thread_->joinable())
                {
                    processor_thread_->join();
                }

                logger_->info("Event processor stopped");
            }


            void BLEEventProcessor::processing_loop()
            {
                logger_->info("Event processor thread started");

                while (running_)
                {
                    try
                    {
                        // dequeue next event
                        auto event_opt = event_queue_.dequeue();

                        // check is event is valide or not 
                        if (!event_opt.has_value())
                        {
    
                            break;
                        }

                        BLEEvent event = event_opt.value();

                        switch (event.type)
                        {
                        case BLEEventType::NOTIFICATION_RECEIVED:
                        {
                            auto &data = std::get<NotificationData>(event.data);
                            handle_notification(data);
                            break;
                        }
                        case BLEEventType::DEVICE_CONNECTED:
                        {
                            auto &data = std::get<DeviceConnectionData>(event.data);
                            handle_device_connected(data);
                            break;
                        }
                        case BLEEventType::DEVICE_DISCONNECTED:
                        {
                            auto &data = std::get<DeviceDisconnectionData>(event.data);
                            handle_device_disconnected(data);
                            break;
                        }
                        case BLEEventType::CONNECTION_FAILED:
                        case BLEEventType::BACKEND_ERROR:
                        {
                            auto &data = std::get<ErrorData>(event.data);
                            handle_error(data);
                            break;
                        }
                        case BLEEventType::SCAN_CYCLE_COMPLETE:
                        {
                            handle_scan_complete();
                            break;
                        }
                        default:
                            logger_->warning("Unknown event type",
                                            core::LogContext{}
                                                .add("type", static_cast<int>(event.type)));
                            events_failed_++;
                            break;
                        }
                    }
                    catch (const std::exception &e)
                    {
                        logger_->error("Error in event processing loop",
                                      core::LogContext{}.add("error", e.what()));
                        events_failed_++;
                    }
                }

                logger_->info("Event processor thread stopped");
            }

            void BLEEventProcessor::handle_notification(const NotificationData &data)
            {
                try
                {
                    logger_->debug("Handling notification event",
                                  core::LogContext{}.add("address", data.device_address)
                                      .add("data_size", data.data.size()));

                    // get device handler from registry
                    auto handler = device_registry_.get_device(data.device_address);
                    if (!handler)
                    {
                        logger_->warning("Notification for unknown device",
                                        core::LogContext{}.add("address", data.device_address));
                        events_failed_++;
                        return;
                    }

                    // process notification through handler
                    handler->process_notification(data.data);

                    events_processed_++;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error handling notification event",
                                  core::LogContext{}
                                      .add("address", data.device_address)
                                      .add("error", e.what()));
                    events_failed_++;
                }
            }

            void BLEEventProcessor::handle_device_connected(const DeviceConnectionData &data)
            {
                logger_->info("Handling device connected event",
                             core::LogContext{}.add("address", data.device_address));

                // transport do this part alr I put it here just in case the flow is change
                events_processed_++;
            }

            void BLEEventProcessor::handle_device_disconnected(const DeviceDisconnectionData &data)
            {
                try
                {
                    logger_->info("Handling device disconnected event",
                                 core::LogContext{}
                                     .add("address", data.device_address)
                                     .add("reason", data.reason));


                    auto handler = device_registry_.get_device(data.device_address);
                    if (handler)
                    {

                        handler->disconnect();
                    }

                    // remove from device registry
                    device_registry_.remove_device(data.device_address);

                    events_processed_++;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Error handling device disconnected event",
                                  core::LogContext{}
                                      .add("address", data.device_address)
                                      .add("error", e.what()));
                    events_failed_++;
                }
            }

            void BLEEventProcessor::handle_error(const ErrorData &data)
            {
                logger_->error("Handling error event",
                              core::LogContext{}
                                  .add("address", data.device_address)
                                  .add("message", data.error_message)
                                  .add("code", data.error_code));

                // not doing shit yet just log
                statistics_service_.record_packet_dropped();
                events_processed_++;
            }

            void BLEEventProcessor::handle_scan_complete()
            {
                logger_->debug("Handling scan complete event");

                // not doing shit yet too
                events_processed_++;
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
