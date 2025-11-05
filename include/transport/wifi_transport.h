#ifndef WIFI_TRANSPORT_H
#define WIFI_TRANSPORT_H

#include <WiFi.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

class WiFiTransport : public ITransport {
private:
    mutable WiFiClient client;
    bool connected;
    String discovered_ssid;
    String shared_secret;

    bool scanForRouter();
    bool connectToAP();
    bool establishTCPConnection();

public:
    WiFiTransport();
    WiFiTransport(const String& shared_secret);
    ~WiFiTransport() override = default;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const BasicProtocolPacket& packet) override;
    bool receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    String getConnectionInfo() const override;

    // WiFi-specific methods
    int getSignalStrength() const;
};

#endif // WIFI_TRANSPORT_H