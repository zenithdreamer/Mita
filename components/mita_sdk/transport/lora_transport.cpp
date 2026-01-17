#include "../include/transport/lora_transport.h"
#include "../../shared/protocol/packet_utils.h"
#include "../../shared/config/mita_config.h"
#include "../../shared/transport/transport_constants.h"
#include <esp_log.h>
#include <string.h>
#include <RadioLib.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "../include/transport/EspHal.h"

static const char *TAG = "LORA_TRANSPORT";

LoRaTransport::LoRaTransport(const std::string& device_id, const std::string& router_id)
    : device_id(device_id), router_id(router_id),
      hal(nullptr), module(nullptr), lora(nullptr),
      lora_initialized(false), connected(false)
    {
        ESP_LOGI(TAG, "LoRaTransport created");
    }


LoRaTransport::~LoRaTransport()
{
    disconnect();
    if (lora) {
        delete lora;
        lora = nullptr;
    }
    if (module) {
        delete module;
        module = nullptr;
    }
    if (hal) {
        delete hal;
        hal = nullptr;
    }
    ESP_LOGI(TAG, "LoRaTransport destroyed");
}

bool LoRaTransport::initializeLoRa()
{
    ESP_LOGI(TAG, "Initializing LoRa module...");

    hal = new EspHal(LORA_PIN_SCK, LORA_PIN_MISO, LORA_PIN_MOSI);
    hal->init(); 
    ESP_LOGI(TAG, "LoRa HAL initialized");

    module = new Module(hal, LORA_PIN_CS, LORA_PIN_DIO0, LORA_PIN_RST, LORA_PIN_DIO1);
    ESP_LOGI(TAG, "LoRa Module initialized");

    lora = new SX1278(module);
    ESP_LOGI(TAG, "LoRa SX1278 instance created");

    int16_t state = lora->begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SPREADING_FACTOR, LORA_CODING_RATE, LORA_SYNC_WORD, LORA_OUTPUT_POWER, LORA_PREAMBLE_LENGTH, 0);
    if (state != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "LoRa begin failed, error code: %d", state);
        return false;
    }

    lora->setCRC(true);
    lora->explicitHeader();
    lora_initialized = true;

    ESP_LOGI(TAG, "LoRa module initialized successfully");

    return true;


}

bool LoRaTransport::connect() 
{
    if (!lora_initialized) {
        if (!initializeLoRa()) {
            ESP_LOGE(TAG, "Failed to initialize LoRa module during connect");
            return false;
        }
    }
    
    connected = true;
    ESP_LOGI(TAG, "LoRaTransport connected");

    return true; 
}

void LoRaTransport::disconnect()
{
    connected = false;
    ESP_LOGI(TAG, "LoRaTransport disconnected (radio still active)");
}

bool LoRaTransport::isConnected() const 
{ 
    return connected; 
}

bool LoRaTransport::sendPacket(const BasicProtocolPacket& packet)
{
    if (!connected || !lora) {
        ESP_LOGE(TAG, "Cannot send - LoRa not connected");
        return false;
    }

    uint8_t buffer[MITA_LORA_MAX_PACKET_SIZE];
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    ESP_LOGI(TAG, "Serialized MITA packet: %zu bytes", length);

    int16_t state = lora->transmit(buffer, length);
    ESP_LOGI(TAG, "Transmitting %zu bytes...", length);

    if (state == RADIOLIB_ERR_NONE) {
        ESP_LOGI(TAG, "✓ Packet transmitted successfully!");
        return true;
    } else {
        ESP_LOGE(TAG, "✗ Transmission failed, code: %d", state);
        return false;
    }
}

bool LoRaTransport::receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms)
{
    if (!connected || !lora) {
        ESP_LOGE(TAG, "Cannot receive - LoRa not connected");
        return false;
    }

    uint8_t rx_buffer[MITA_LORA_MAX_PACKET_SIZE];

    ESP_LOGI(TAG, "Listening for packets (timeout: %lu ms)...", timeout_ms);


    unsigned long start_time = (unsigned long)(esp_timer_get_time() / 1000ULL);
    int16_t state = RADIOLIB_ERR_RX_TIMEOUT;

    while ((unsigned long)(esp_timer_get_time() / 1000ULL) - start_time < timeout_ms) {

        state = lora->receive(rx_buffer, MITA_LORA_MAX_PACKET_SIZE);

        if (state != RADIOLIB_ERR_RX_TIMEOUT) {
            break;  
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (state > 0) {

        ESP_LOGI(TAG, "✓ Received %d bytes", state);

        float rssi = lora->getRSSI();
        float snr = lora->getSNR();
        ESP_LOGI(TAG, "RSSI: %.2f dBm, SNR: %.2f dB", rssi, snr);

        ESP_LOG_BUFFER_HEX(TAG, rx_buffer, state);


        if (PacketUtils::deserializePacket(rx_buffer, state, packet)) {
            ESP_LOGI(TAG, "✓ MITA packet deserialized: msg_type=0x%02X, src=0x%04X, dst=0x%04X, payload_len=%d",
                     packet.msg_type, packet.source_addr, packet.dest_addr, packet.payload_length);
            return true;
        } else {
            ESP_LOGE(TAG, "✗ Failed to deserialize MITA packet");
            return false;
        }

    } else if (state == RADIOLIB_ERR_RX_TIMEOUT) {
        ESP_LOGW(TAG, "Receive timeout");
        return false;

    } else {
        ESP_LOGE(TAG, "✗ Receive failed, code: %d", state);
        return false;
    }
}

TransportType LoRaTransport::getType() const 
{ 
    return TRANSPORT_LORA; 
}

std::string LoRaTransport::getConnectionInfo() const { return "LoRa"; }
