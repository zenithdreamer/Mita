#ifndef BLE_TRANSPORT_H
#define BLE_TRANSPORT_H

#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

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
    void onNotify(BLECharacteristic* characteristic) override;
};

class MitaBLEDescriptorCallbacks : public BLEDescriptorCallbacks {
private:
    BLETransport* transport;

public:
    MitaBLEDescriptorCallbacks(BLETransport* transport);
    void onWrite(BLEDescriptor* descriptor) override;
};

class BLETransport : public ITransport {
private:
    BLEServer* server;
    BLECharacteristic* characteristic;
    String device_id;
    String router_id;

    bool ble_connected;
    bool client_connected;
    bool notifications_enabled;

    // Packet buffering
    uint8_t packet_buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t packet_length;
    bool packet_available;

    bool setupServer();
    bool startAdvertising();

public:
    BLETransport(const String& device_id, const String& router_id);
    ~BLETransport() override;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const BasicProtocolPacket& packet) override;
    bool receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    String getConnectionInfo() const override;

    // BLE callback handlers
    void onClientConnect();
    void onClientDisconnect();
    void onDataReceived(const uint8_t* data, size_t length);
    void onNotificationsEnabled();
    void onNotificationsDisabled();

    // BLE-specific methods
};

#endif // BLE_TRANSPORT_H