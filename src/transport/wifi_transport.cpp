#include "../include/transport/wifi_transport.h"

WiFiTransport::WiFiTransport()
    : connected(false), shared_secret("Mita_password")
{
}

WiFiTransport::WiFiTransport(const String& shared_secret)
    : connected(false), shared_secret(shared_secret)
{
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

    if (!establishTCPConnection())
    {
        Serial.println("WiFiTransport: Failed to establish TCP connection");
        WiFi.disconnect();
        return false;
    }

    connected = true;
    Serial.println("WiFiTransport: Connection successful");
    return true;
}

void WiFiTransport::disconnect()
{
    if (client.connected())
    {
        client.stop();
    }
    WiFi.disconnect();
    connected = false;
    Serial.println("WiFiTransport: Disconnected");
}

bool WiFiTransport::isConnected() const
{
    return connected && WiFi.status() == WL_CONNECTED && const_cast<WiFiClient &>(client).connected();
}

bool WiFiTransport::sendPacket(const ProtocolPacket &packet)
{
    if (!isConnected())
    {
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    serializePacket(packet, buffer, length);

    size_t sent = client.write(buffer, length);
    return sent == length;
}

bool WiFiTransport::receivePacket(ProtocolPacket &packet, unsigned long timeout_ms)
{
    if (!isConnected())
    {
        return false;
    }

    unsigned long start_time = millis();
    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t received = 0;

    while (millis() - start_time < timeout_ms)
    {
        while (client.available() && received < sizeof(buffer))
        {
            buffer[received++] = client.read();

            if (received >= HEADER_SIZE)
            {
                uint8_t payload_length = buffer[6];
                if (received >= HEADER_SIZE + payload_length)
                {
                    return deserializePacket(buffer, HEADER_SIZE + payload_length, packet);
                }
            }
        }
        delay(1);
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
        "Mita_Router_1",
        "Mita_Network"};

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

bool WiFiTransport::establishTCPConnection()
{
    IPAddress gateway = WiFi.gatewayIP();
    Serial.printf("WiFiTransport: Connecting to router at %s:%d\n",
                  gateway.toString().c_str(), MITA_PORT);

    if (client.connect(gateway, MITA_PORT))
    {
        Serial.println("WiFiTransport: TCP connection established");
        return true;
    }
    else
    {
        Serial.println("WiFiTransport: TCP connection failed");
        return false;
    }
}

void WiFiTransport::serializePacket(const ProtocolPacket &packet, uint8_t *buffer, size_t &length)
{
    buffer[0] = packet.version_flags;
    buffer[1] = packet.msg_type;
    buffer[2] = (packet.source_addr >> 8) & 0xFF;
    buffer[3] = packet.source_addr & 0xFF;
    buffer[4] = (packet.dest_addr >> 8) & 0xFF;
    buffer[5] = packet.dest_addr & 0xFF;
    buffer[6] = packet.payload_length;
    buffer[7] = packet.reserved;

    if (packet.payload_length > 0)
    {
        memcpy(buffer + HEADER_SIZE, packet.payload, packet.payload_length);
    }

    length = HEADER_SIZE + packet.payload_length;
}

bool WiFiTransport::deserializePacket(const uint8_t *buffer, size_t length, ProtocolPacket &packet)
{
    if (length < HEADER_SIZE)
    {
        return false;
    }

    packet.version_flags = buffer[0];
    packet.msg_type = buffer[1];
    packet.source_addr = (buffer[2] << 8) | buffer[3];
    packet.dest_addr = (buffer[4] << 8) | buffer[5];
    packet.payload_length = buffer[6];
    packet.reserved = buffer[7];

    if (length < HEADER_SIZE + packet.payload_length)
    {
        return false;
    }

    if (packet.payload_length > 0)
    {
        memcpy(packet.payload, buffer + HEADER_SIZE, packet.payload_length);
    }

    return true;
}