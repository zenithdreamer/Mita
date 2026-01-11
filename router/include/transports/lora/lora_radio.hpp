#ifndef MITA_ROUTER_LORA_RADIO_HPP
#define MITA_ROUTER_LORA_RADIO_HPP

#include "core/transport_interface.hpp"
#include "protocol/protocol.hpp"
#include "transports/lora/lora_client_handler.hpp"
#include <thread>
#include <atomic>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <RadioLib.h>


namespace mita {
    namespace transports {
        namespace lora {

          class LoRaRadio
            {
            public:
                LoRaRadio(const core::RouterConfig &config);
                ~LoRaRadio();

                bool initialize();
                void shutdown();
                bool is_initialized() const { return initialized_; }

    
                bool send(uint8_t dest_addr, const uint8_t *data, size_t length);
                int receive(uint8_t *buffer, size_t max_length, uint8_t &src_addr, uint8_t &dest_addr);


                bool set_frequency(float freq_mhz);
                bool set_bandwidth(float bw_khz);
                bool set_spreading_factor(uint8_t sf);
                bool set_coding_rate(uint8_t cr);
                bool set_tx_power(int8_t power_dbm);
                bool set_sync_word(uint8_t sync_word);


                int get_rssi();
                float get_snr();

            private:
                const core::RouterConfig &config_;
                std::shared_ptr<core::Logger> logger_;


                std::unique_ptr<Module> lora_module_;
                std::unique_ptr<SX1278> lora_;

                bool initialized_;
                std::mutex radio_mutex_;
            };
        }
    }
}


#endif