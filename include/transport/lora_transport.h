#ifndef loRA_TRANSPORT_H
#define loRA_TRANSPORT_H


#include <string>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include <RadioLib.h>
#include "EspHal.h"


#define LORA_PIN_MISO  19
#define LORA_PIN_MOSI  23
#define LORA_PIN_SCK   18
#define LORA_PIN_CS    5
#define LORA_PIN_RST   14
#define LORA_PIN_DIO0  26
// SX1278 RA01 dont have DIO1
#define LORA_PIN_DIO1  -1

//
#define LORA_FREQUENCY              433.0f
#define LORA_BANDWIDTH              125.0f  
#define LORA_SPREADING_FACTOR       10      
#define LORA_CODING_RATE            5
#define LORA_SYNC_WORD              0x34
#define LORA_OUTPUT_POWER           17
#define LORA_PREAMBLE_LENGTH        12   

class LoRaTransport : public ITransport {
private:
    std::string device_id;
    std::string router_id;
    uint8_t lora_address; 
    EspHal* hal;  
    Module* module;

    SX1278* lora;

    bool lora_initialized;
    bool connected;

public:
    LoRaTransport(const std::string& device_id, const std::string& router_id);
    ~LoRaTransport() override;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const BasicProtocolPacket& packet) override;
    bool receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    std::string getConnectionInfo() const override;

    bool initializeLoRa();
};


#endif // LORA_TRANSPORT_H