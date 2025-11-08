#ifndef WIFI_TRANSPORT_H
#define WIFI_TRANSPORT_H

#include <string>
#include <esp_wifi.h>
#include <esp_netif.h>
#include <lwip/sockets.h>
#include <lwip/ip.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"
#include "../../shared/transport/transport_constants.h"

class WiFiTransport : public ITransport {
private:
    int raw_socket;
    bool connected;
    std::string discovered_ssid;
    std::string shared_secret;
    uint32_t router_ip;  // IP address as uint32_t
    uint32_t local_ip;   // Local IP address as uint32_t

    bool scanForRouter();
    bool connectToAP();
    bool createRawSocket();

    // Raw IP packet handling
    bool sendRawPacket(const uint8_t *data, size_t length, uint32_t dest_ip);
    bool receiveRawPacket(uint8_t *buffer, size_t &length, uint32_t &source_ip, unsigned long timeout_ms);

public:
    WiFiTransport();
    WiFiTransport(const std::string& shared_secret);
    ~WiFiTransport() override;

    bool connect() override;
    void disconnect() override;
    bool isConnected() const override;

    bool sendPacket(const BasicProtocolPacket& packet) override;
    bool receivePacket(BasicProtocolPacket& packet, unsigned long timeout_ms = 1000) override;

    TransportType getType() const override;
    std::string getConnectionInfo() const override;

    // WiFi-specific methods
    int getSignalStrength() const;
};

#endif // WIFI_TRANSPORT_H