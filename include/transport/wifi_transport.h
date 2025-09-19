#ifndef WIFI_TRANSPORT_H
#define WIFI_TRANSPORT_H

#include <WiFi.h>
#include "../common/transport_interface.h"
#include "../common/protocol_types.h"

class WiFiTransport : public ITransport {
private:
    WiFiClient client;
    bool connected;
    String discovered_ssid;
    String shared_secret;
    static const uint16_t MITA_PORT = 8000;

    bool scanForRouter();
    bool connectToAP();
    bool establishTCPConnection();
    void serializePacket(const ProtocolPacket& packet, uint8_t* buffer, size_t& length);
    bool deserializePacket(const uint8_t* buffer, size_t length, ProtocolPacket& packet);

public:
    WiFiTransport();
    WiFiTransport(const String& shared_secret);
    ~WiFiTransport() override = default;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const ProtocolPacket& packet) override;
    bool receivePacket(ProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    String getConnectionInfo() const override;

    // WiFi-specific methods
    int getSignalStrength() const;
};

#endif // WIFI_TRANSPORT_H