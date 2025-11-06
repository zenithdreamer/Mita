#ifndef WIFI_TRANSPORT_H
#define WIFI_TRANSPORT_H

#include <WiFi.h>
#include <lwip/sockets.h>
#include <lwip/ip.h>
#include <lwip/raw.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

class WiFiTransport : public ITransport {
private:
    int raw_socket;
    bool connected;
    String discovered_ssid;
    String shared_secret;
    IPAddress router_ip;

    bool scanForRouter();
    bool connectToAP();
    bool createRawSocket();

    // Raw IP packet handling
    bool sendRawPacket(const uint8_t *data, size_t length, const IPAddress &dest_ip);
    bool receiveRawPacket(uint8_t *buffer, size_t &length, IPAddress &source_ip, unsigned long timeout_ms);

public:
    WiFiTransport();
    WiFiTransport(const String& shared_secret);
    ~WiFiTransport() override;

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