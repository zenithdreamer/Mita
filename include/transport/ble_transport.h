#ifndef BLE_TRANSPORT_H
#define BLE_TRANSPORT_H

#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "../common/transport_interface.h"
#include "../common/protocol_types.h"

// BLE Service and Characteristic UUIDs
#define MITA_SERVICE_UUID "12345678-1234-1234-1234-123456789abc"
#define MITA_CHARACTERISTIC_UUID "12345678-1234-1234-1234-123456789abd"

// Forward declarations
class BLETransport;

class MitaBLEServerCallbacks : public BLEServerCallbacks {
private:
    BLETransport* transport;

public:
    MitaBLEServerCallbacks(BLETransport* transport);
    void onConnect(BLEServer* server) override;
    void onDisconnect(BLEServer* server) override;
};

class MitaBLECharacteristicCallbacks : public BLECharacteristicCallbacks {
private:
    BLETransport* transport;

public:
    MitaBLECharacteristicCallbacks(BLETransport* transport);
    void onWrite(BLECharacteristic* characteristic) override;
};

class BLETransport : public ITransport {
private:
    BLEServer* server;
    BLECharacteristic* characteristic;
    String device_id;
    String router_id;

    bool ble_connected;
    bool client_connected;

    // Packet buffering
    uint8_t packet_buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t packet_length;
    bool packet_available;

    bool setupServer();
    bool startAdvertising();
    void serializePacket(const ProtocolPacket& packet, uint8_t* buffer, size_t& length);
    bool deserializePacket(const uint8_t* buffer, size_t length, ProtocolPacket& packet);

public:
    BLETransport(const String& device_id, const String& router_id);
    ~BLETransport() override;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const ProtocolPacket& packet) override;
    bool receivePacket(ProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    String getConnectionInfo() const override;

    // BLE callback handlers
    void onClientConnect();
    void onClientDisconnect();
    void onDataReceived(const uint8_t* data, size_t length);

    // BLE-specific methods
};

#endif // BLE_TRANSPORT_H