#include "../include/transport/wifi_transport.h"
#include "../shared/protocol/packet_utils.h"
#include "../shared/config/mita_config.h"

WiFiTransport::WiFiTransport()
    : raw_socket(-1), connected(false), shared_secret("Mita_password")
{
}

WiFiTransport::WiFiTransport(const String &shared_secret)
    : raw_socket(-1), connected(false), shared_secret(shared_secret)
{
}

WiFiTransport::~WiFiTransport()
{
    disconnect();
}

bool WiFiTransport::connect()
{
    Serial.println("WiFiTransport: Attempting connection...");

    if (!scanForRouter())
    {
        Serial.println("WiFiTransport: Router AP not found");
        return false;
    }

    if (!connectToAP())
    {
        Serial.println("WiFiTransport: Failed to connect to AP");
        return false;
    }

    if (!createRawSocket())
    {
        Serial.println("WiFiTransport: Failed to create raw socket");
        WiFi.disconnect();
        return false;
    }

    connected = true;
    Serial.println("WiFiTransport: Connection successful");
    return true;
}

void WiFiTransport::disconnect()
{
    if (raw_socket >= 0)
    {
        close(raw_socket);
        raw_socket = -1;
    }
    WiFi.disconnect();
    connected = false;
    Serial.println("WiFiTransport: Disconnected");
}

bool WiFiTransport::isConnected() const
{
    return WiFi.status() == WL_CONNECTED && raw_socket >= 0;
}

bool WiFiTransport::sendPacket(const BasicProtocolPacket &packet)
{
    if (!isConnected())
    {
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    return sendRawPacket(buffer, length, router_ip);
}

bool WiFiTransport::receivePacket(BasicProtocolPacket &packet, unsigned long timeout_ms)
{
    if (!isConnected())
    {
        Serial.println("WiFiTransport: receivePacket called but not connected");
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t received = 0;
    IPAddress source_ip;

    if (receiveRawPacket(buffer, received, source_ip, timeout_ms))
    {
        if (received >= HEADER_SIZE)
        {
            return PacketUtils::deserializePacket(buffer, received, packet);
        }
    }

    return false;
}

TransportType WiFiTransport::getType() const
{
    return TRANSPORT_WIFI;
}

String WiFiTransport::getConnectionInfo() const
{
    if (!connected)
    {
        return "WiFi: Disconnected";
    }

    return String("WiFi: ") + WiFi.localIP().toString() +
           " (RSSI: " + String(WiFi.RSSI()) + " dBm)";
}

int WiFiTransport::getSignalStrength() const
{
    return WiFi.RSSI();
}

bool WiFiTransport::scanForRouter()
{
    Serial.println("WiFiTransport: Scanning for router AP...");

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    int networks = WiFi.scanNetworks(false, true);

    if (networks == -1)
    {
        Serial.println("WiFiTransport: WiFi scan failed");
        return false;
    }

    Serial.printf("WiFiTransport: Found %d networks\n", networks);

    String patterns[] = {
        MITA_DEFAULT_ROUTER_ID,
        MITA_NETWORK_SSID};

    for (int i = 0; i < networks; i++)
    {
        String foundSSID = WiFi.SSID(i);
        Serial.printf("  [%d] SSID: %s RSSI: %d dBm\n", i, foundSSID.c_str(), WiFi.RSSI(i));

        for (int p = 0; p < 2; p++)
        {
            if (foundSSID == patterns[p] || foundSSID == "Mita_Network")
            {
                Serial.printf("WiFiTransport: Found matching network: %s\n", foundSSID.c_str());
                discovered_ssid = foundSSID;
                WiFi.scanDelete();
                return true;
            }
        }
    }

    WiFi.scanDelete();
    return false;
}

bool WiFiTransport::connectToAP()
{
    Serial.printf("WiFiTransport: Connecting to AP: %s\n", discovered_ssid.c_str());

    WiFi.mode(WIFI_STA);
    delay(100);

    WiFi.begin(discovered_ssid.c_str(), shared_secret.c_str());

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30)
    {
        delay(500);
        Serial.print(".");
        attempts++;
    }

    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.printf("\nWiFiTransport: Connected to AP. IP: %s\n", WiFi.localIP().toString().c_str());
        return true;
    }
    else
    {
        Serial.println("\nWiFiTransport: Failed to connect to AP");
        return false;
    }
}

bool WiFiTransport::createRawSocket()
{
    router_ip = WiFi.gatewayIP();
    Serial.printf("WiFiTransport: Creating raw socket to router at %s\n",
                  router_ip.toString().c_str());

    // Create raw socket for custom IP protocol
    raw_socket = socket(AF_INET, SOCK_RAW, MITA_IP_PROTOCOL);
    if (raw_socket < 0)
    {
        Serial.printf("WiFiTransport: Failed to create raw socket: %d\n", errno);
        return false;
    }

    // Set socket to non-blocking mode
    int flags = fcntl(raw_socket, F_GETFL, 0);
    if (flags >= 0)
    {
        fcntl(raw_socket, F_SETFL, flags | O_NONBLOCK);
    }

    // Note: ESP32 lwIP doesn't support IP_HDRINCL, kernel will build IP headers

    Serial.println("WiFiTransport: Raw socket created successfully");
    return true;
}

bool WiFiTransport::sendRawPacket(const uint8_t *data, size_t length, const IPAddress &dest_ip)
{
    if (raw_socket < 0)
    {
        return false;
    }

    // Send data directly - kernel will add IP headers
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = (uint32_t)dest_ip;

    ssize_t sent = sendto(raw_socket, data, length, 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent < 0)
    {
        Serial.printf("WiFiTransport: sendto failed: %d\n", errno);
        return false;
    }

    return sent == (ssize_t)length;
}

bool WiFiTransport::receiveRawPacket(uint8_t *buffer, size_t &length, IPAddress &source_ip, unsigned long timeout_ms)
{
    if (raw_socket < 0)
    {
        return false;
    }

    unsigned long start_time = millis();
    const size_t ip_header_len = 20;
    uint8_t raw_buffer[ip_header_len + HEADER_SIZE + MAX_PAYLOAD_SIZE];

    while (millis() - start_time < timeout_ms)
    {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);

        ssize_t received = recvfrom(raw_socket, raw_buffer, sizeof(raw_buffer), 0,
                                    (struct sockaddr *)&src_addr, &addr_len);

        if (received > 0 && received > (ssize_t)ip_header_len)
        {
            // Extract IP header info
            uint8_t ihl = (raw_buffer[0] & 0x0F) * 4;
            uint8_t protocol = raw_buffer[9];

            Serial.printf("WiFiTransport: Received packet: size=%d, protocol=%d, ihl=%d\n",
                          received, protocol, ihl);

            // Verify it's our protocol
            if (protocol == MITA_IP_PROTOCOL)
            {
                // Extract source IP
                source_ip = IPAddress(raw_buffer[12], raw_buffer[13],
                                      raw_buffer[14], raw_buffer[15]);

                Serial.printf("WiFiTransport: MITA packet from %s, payload_size=%d\n",
                              source_ip.toString().c_str(), received - ihl);

                // Copy payload (skip IP header)
                size_t payload_len = received - ihl;
                memcpy(buffer, raw_buffer + ihl, payload_len);
                length = payload_len;

                return true;
            }
        }
        else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            Serial.printf("WiFiTransport: recvfrom error: %d\n", errno);
            break;
        }

        delay(1);
    }

    return false;
}
