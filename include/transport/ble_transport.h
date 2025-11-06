#ifndef BLE_TRANSPORT_H
#define BLE_TRANSPORT_H

#include <BLEDevice.h>
#include <BLEClient.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLE2902.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

// Forward declarations
class BLETransport;

// BLE Client Callbacks - handle connection/disconnection events
class MitaBLEClientCallbacks : public BLEClientCallbacks {
private:
    BLETransport* transport;

public:
    MitaBLEClientCallbacks(BLETransport* transport);
    void onConnect(BLEClient* pClient) override;
    void onDisconnect(BLEClient* pClient) override;
};

// BLE Transport - Client Mode (connects TO router)
class BLETransport : public ITransport {
private:
    BLEClient* client;
    BLERemoteCharacteristic* characteristic;
    BLEAdvertisedDevice* router_device;
    String device_id;
    String router_id;

    bool ble_connected;
    bool client_connected;

    // Packet buffering
    uint8_t packet_buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t packet_length;
    bool packet_available;

    // Client mode methods
    bool scanForRouter();
    bool connectToRouter();

    // Static instance pointer for notification callback
    static BLETransport* instance;

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
    void onServerConnect();
    void onServerDisconnect();
    void onDataReceived(const uint8_t* data, size_t length);

    // Static notification callback for BLE characteristic
    static void notifyCallback(BLERemoteCharacteristic* pChar, uint8_t* data, size_t length, bool isNotify);
};

#endif // BLE_TRANSPORT_H