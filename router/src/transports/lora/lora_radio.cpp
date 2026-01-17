#include "transports/lora/lora_radio.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include <cstring>
#include <chrono>



#define CHECK(call) do { \
    int _s = (call); \
    if (_s != RADIOLIB_ERR_NONE) { \
        std::cerr << "[LoRa ERROR] " << #call << " failed: " << _s << std::endl; \
        return false; \
    } \
} while(0)
namespace mita
{
    namespace transports
    {
        namespace lora
        {
            LoRaRadio::LoRaRadio(const core::RouterConfig &config)
                : config_(config),
                  logger_(core::get_logger("LoRaRadio")),
                  initialized_(false)
            {
                logger_->info("LoRaRadio created");
            }

            LoRaRadio::~LoRaRadio()
            {
                shutdown();
            }

            bool LoRaRadio::initialize()
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (initialized_)
                {
                    logger_->warning("LoRa radio already initialized");
                    return true;
                }

                try
                {
                    logger_->info("Initializing LoRa radio",
                                  core::LogContext()
                                      .add("frequency", config_.lora.frequency)
                                      .add("bandwidth", config_.lora.bandwidth)
                                      .add("sf", config_.lora.spreading_factor)
                                      .add("cs_pin", config_.lora.cs_pin)
                                      .add("rst_pin", config_.lora.rst_pin)
                                      .add("dio0_pin", config_.lora.dio0_pin));


                    int spi_channel = 0; 
                    if (config_.lora.spi_device.find("spidev0.1") != std::string::npos) {
                        spi_channel = 1;
                    }

                    logger_->debug("Creating PiHal for Raspberry Pi",
                                   core::LogContext().add("spi_channel", spi_channel));

                    hal_ = std::make_unique<PiHal>(spi_channel, 1000000);


                    lora_module_ = std::make_unique<Module>(
                        hal_.get(),              
                        config_.lora.cs_pin,    
                        config_.lora.dio0_pin,   
                        config_.lora.rst_pin,    
                        RADIOLIB_NC);           // DIO 1 not needed


                    lora_ = std::make_unique<SX1278>(lora_module_.get());

                    logger_->debug("Initializing SX1278 module");

                    int state = lora_->begin(
                        config_.lora.frequency,
                        config_.lora.bandwidth,
                        config_.lora.spreading_factor,
                        config_.lora.coding_rate,
                        config_.lora.sync_word,
                        config_.lora.tx_power,
                        config_.lora.preamble_length,
                        0  
                    );
                    if (state != RADIOLIB_ERR_NONE)
                    {
                        logger_->error("Failed to initialize SX1278",
                                       core::LogContext().add("error_code", state));
                        return false;
                    }
                    initialized_ = true;
                    logger_->info("LoRa radio initialized successfully");
                    return true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception during LoRa initialization",
                                   core::LogContext().add("error", e.what()));
                    return false;
                }
            }

            void LoRaRadio::shutdown()
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    return;
                }

                logger_->info("Shutting down LoRa radio");

                if (lora_)
                {
                    lora_->sleep();
                }

                lora_.reset();
                lora_module_.reset();
                hal_.reset(); 

                initialized_ = false;
                logger_->info("LoRa radio shutdown complete");
            }

            bool LoRaRadio::send(uint8_t dest_addr, const uint8_t *data, size_t length)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot send - radio not initialized");
                    return false;
                }

                if (!data || length == 0)
                {
                    logger_->error("Invalid send parameters");
                    return false;
                }

                try
                {
                    
                    
                    std::vector<uint8_t> packet;
                    packet.reserve(length + 1);
                    packet.push_back(dest_addr);
                    packet.insert(packet.end(), data, data + length);

                    int state = lora_->transmit(packet.data(), packet.size());
                    if (state != RADIOLIB_ERR_NONE)
                    {
                        logger_->error("Failed to transmit packet",
                                       core::LogContext()
                                           .add("error_code", state)
                                           .add("dest_addr", static_cast<int>(dest_addr))
                                           .add("length", length));
                        return false;
                    }

                    logger_->debug("Packet transmitted",
                                   core::LogContext()
                                       .add("dest_addr", static_cast<int>(dest_addr))
                                       .add("total_length", packet.size()));
                    return true;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception during send",
                                   core::LogContext().add("error", e.what()));
                    return false;
                }
            }

            int LoRaRadio::receive(uint8_t *buffer, size_t max_length, uint8_t &src_addr, uint8_t &dest_addr)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot receive - radio not initialized");
                    return -1;
                }

                if (!buffer || max_length == 0)
                {
                    logger_->error("Invalid receive parameters");
                    return -1;
                }

                try
                {

                    static auto last_log = std::chrono::steady_clock::now();
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_log).count() >= 10)
                    {
                        logger_->debug("LoRa radio listening for packets...");
                        last_log = now;
                    }

                    // max_length is 256 
                    int16_t state = lora_->receive(buffer, max_length);

                    if (state == RADIOLIB_ERR_RX_TIMEOUT)
                    {
                        return 0;
                    }


                    logger_->info("LoRa received packet!", core::LogContext().add("state", state));

                    if (state != RADIOLIB_ERR_NONE)
                    {
                        logger_->error("Failed to receive packet",
                                       core::LogContext().add("error_code", state));
                        return -1;
                    }


                    int bytes_received = lora_->getPacketLength();

                    logger_->info("getPacketLength returned", core::LogContext().add("bytes", bytes_received));


                    // if (bytes_received >= 7) {
                    //     logger_->debug("Raw packet header",
                    //         core::LogContext()
                    //             .add("ver_flags", static_cast<int>(buffer[0]))
                    //             .add("msg_type", static_cast<int>(buffer[1]))
                    //             .add("src_hi", static_cast<int>(buffer[2]))
                    //             .add("src_lo", static_cast<int>(buffer[3]))
                    //             .add("dst_hi", static_cast<int>(buffer[4]))
                    //             .add("dst_lo", static_cast<int>(buffer[5]))
                    //             .add("payload_len", static_cast<int>(buffer[6])));
                    // }

                    if (bytes_received < 6)
                    {
                        logger_->warning("Packet too short", core::LogContext().add("bytes", bytes_received));
                        return -1;
                    }


                    src_addr = buffer[3];
                    dest_addr = buffer[5];

                    logger_->info("Packet received",
                                   core::LogContext()
                                       .add("src_addr", static_cast<int>(src_addr))
                                       .add("dest_addr", static_cast<int>(dest_addr))
                                       .add("total_length", bytes_received)
                                       .add("rssi", lora_->getRSSI())
                                       .add("snr", lora_->getSNR()));

                    return bytes_received;
                }
                catch (const std::exception &e)
                {
                    logger_->error("Exception during receive",
                                   core::LogContext().add("error", e.what()));
                    return -1;
                }
            }

            bool LoRaRadio::set_frequency(float freq_mhz)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set frequency - radio not initialized");
                    return false;
                }

                int state = lora_->setFrequency(freq_mhz);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set frequency",
                                   core::LogContext().add("frequency", freq_mhz).add("error_code", state));
                    return false;
                }

                logger_->info("Frequency set", core::LogContext().add("frequency_mhz", freq_mhz));
                return true;
            }

            bool LoRaRadio::set_bandwidth(float bw_khz)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set bandwidth - radio not initialized");
                    return false;
                }

                int state = lora_->setBandwidth(bw_khz);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set bandwidth",
                                   core::LogContext().add("bandwidth", bw_khz).add("error_code", state));
                    return false;
                }

                logger_->info("Bandwidth set", core::LogContext().add("bandwidth_khz", bw_khz));
                return true;
            }

            bool LoRaRadio::set_spreading_factor(uint8_t sf)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set spreading factor - radio not initialized");
                    return false;
                }

                int state = lora_->setSpreadingFactor(sf);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set spreading factor",
                                   core::LogContext().add("sf", static_cast<int>(sf)).add("error_code", state));
                    return false;
                }

                logger_->info("Spreading factor set", core::LogContext().add("sf", static_cast<int>(sf)));
                return true;
            }

            bool LoRaRadio::set_coding_rate(uint8_t cr)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set coding rate - radio not initialized");
                    return false;
                }

                int state = lora_->setCodingRate(cr);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set coding rate",
                                   core::LogContext().add("cr", static_cast<int>(cr)).add("error_code", state));
                    return false;
                }

                logger_->info("Coding rate set", core::LogContext().add("cr", static_cast<int>(cr)));
                return true;
            }

            bool LoRaRadio::set_tx_power(int8_t power_dbm)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set TX power - radio not initialized");
                    return false;
                }

                int state = lora_->setOutputPower(power_dbm);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set TX power",
                                   core::LogContext().add("power_dbm", static_cast<int>(power_dbm)).add("error_code", state));
                    return false;
                }

                logger_->info("TX power set", core::LogContext().add("power_dbm", static_cast<int>(power_dbm)));
                return true;
            }

            bool LoRaRadio::set_sync_word(uint8_t sync_word)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set sync word - radio not initialized");
                    return false;
                }

                int state = lora_->setSyncWord(sync_word);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set sync word",
                                   core::LogContext().add("sync_word", static_cast<int>(sync_word)).add("error_code", state));
                    return false;
                }

                logger_->info("Sync word set", core::LogContext().add("sync_word", static_cast<int>(sync_word)));
                return true;
            }

            bool LoRaRadio::set_preamble_length(uint16_t length)
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_)
                {
                    logger_->error("Cannot set preamble length - radio not initialized");
                    return false;
                }

                int state = lora_->setPreambleLength(length);
                if (state != RADIOLIB_ERR_NONE)
                {
                    logger_->error("Failed to set preamble length",
                                   core::LogContext().add("length", length).add("error_code", state));
                    return false;
                }

                logger_->info("Preamble length set", core::LogContext().add("length", length));
                return true;
            }

            int LoRaRadio::get_rssi()
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_ || !lora_)
                {
                    return -999;
                }

                return lora_->getRSSI();
            }

            float LoRaRadio::get_snr()
            {
                std::lock_guard<std::mutex> lock(radio_mutex_);

                if (!initialized_ || !lora_)
                {
                    return -999.0f;
                }

                return lora_->getSNR();
            }

        } // namespace lora
    }     // namespace transports
} // namespace mita
