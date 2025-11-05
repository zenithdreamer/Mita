#include "../include/transport/wifi_transport.h"
#include "../shared/protocol/packet_utils.h"
#include "../shared/config/mita_config.h"

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
    return WiFi.status() == WL_CONNECTED && client.connected();
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

    size_t sent = client.write(buffer, length);
    return sent;
}

bool WiFiTransport::receivePacket(BasicProtocolPacket &packet, unsigned long timeout_ms)
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
                    return PacketUtils::deserializePacket(buffer, HEADER_SIZE + payload_length, packet);
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

bool WiFiTransport::establishTCPConnection()
{
    IPAddress gateway = WiFi.gatewayIP();
    Serial.printf("WiFiTransport: Connecting to router at %s:%d\n",
                  gateway.toString().c_str(), MITA_WIFI_PORT);

    if (client.connect(gateway, MITA_WIFI_PORT))
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

