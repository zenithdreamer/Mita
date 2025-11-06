#include "../include/transport/ble_transport.h"
#include "../shared/protocol/packet_utils.h"
#include "../shared/config/mita_config.h"

// Static instance pointer for notification callback
BLETransport* BLETransport::instance = nullptr;

// BLE Client Callback implementations
MitaBLEClientCallbacks::MitaBLEClientCallbacks(BLETransport *transport) : transport(transport) {}

void MitaBLEClientCallbacks::onConnect(BLEClient *pClient)
{
    transport->onServerConnect();
}

void MitaBLEClientCallbacks::onDisconnect(BLEClient *pClient)
{
    transport->onServerDisconnect();
}

// BLETransport implementation
BLETransport::BLETransport(const String &device_id, const String &router_id)
    : device_id(device_id), router_id(router_id),
      client(nullptr), characteristic(nullptr), router_device(nullptr),
      ble_connected(false), client_connected(false),
      packet_length(0), packet_available(false)
{
    // Set static instance for notification callback
    instance = this;
}

BLETransport::~BLETransport()
{
    disconnect();
    if (instance == this) {
        instance = nullptr;
    }
}

bool BLETransport::connect()
{
    Serial.println("BLETransport: Scanning for router...");

    if (!scanForRouter())
    {
        Serial.println("BLETransport: Router not found");
        return false;
    }

    if (!connectToRouter())
    {
        Serial.println("BLETransport: Failed to connect to router");
        return false;
    }

    Serial.println("BLETransport: Connected to router");
    return true;
}

bool BLETransport::scanForRouter()
{
    // Initialize BLE if not already done
    if (!BLEDevice::getInitialized())
    {
        BLEDevice::init(device_id.c_str());
    }

    BLEScan *pBLEScan = BLEDevice::getScan();
    pBLEScan->setActiveScan(true);  // Active scan to get scan response
    pBLEScan->setInterval(1349);    // Longer interval for reliable scan response (1.349s)
    pBLEScan->setWindow(449);       // 449ms window

    // Scan for 8 seconds to ensure we get scan response packets
    Serial.println("BLETransport: Starting 8-second active scan (waiting for scan responses)...");
    BLEScanResults results = pBLEScan->start(8, false);

    Serial.printf("BLETransport: Found %d devices\n", results.getCount());

    // Look for router by name OR by service UUID
    for (int i = 0; i < results.getCount(); i++)
    {
        BLEAdvertisedDevice device = results.getDevice(i);
        String name = String(device.getName().c_str());
        String addr = String(device.getAddress().toString().c_str());

        // Check if device advertises our service UUID
        bool has_service = false;
        if (device.haveServiceUUID())
        {
            // Check if it's advertising our specific service
            has_service = device.isAdvertisingService(BLEUUID(MITA_SERVICE_UUID));
            
            // Debug: print all advertised service UUIDs
            if (!has_service && device.getServiceUUIDCount() > 0)
            {
                Serial.printf("  Services: ");
                for (int j = 0; j < device.getServiceUUIDCount(); j++)
                {
                    Serial.printf("%s ", device.getServiceUUID(j).toString().c_str());
                }
                Serial.println();
            }
        }

        Serial.printf("BLETransport:   Device %d: '%s' addr=%s (RSSI: %d) service=%d\n", 
                     i, name.c_str(), addr.c_str(), device.getRSSI(), has_service);

        // Match by service UUID (most reliable)
        if (has_service)
        {
            Serial.printf("BLETransport: Found router by service UUID: %s\n", addr.c_str());
            router_device = new BLEAdvertisedDevice(device);
            pBLEScan->clearResults();
            return true;
        }
        
        // Also try matching by name (if available) - case insensitive
        String name_lower = name;
        name_lower.toLowerCase();
        String router_lower = String(router_id);
        router_lower.toLowerCase();
        if (name.length() > 0 && 
            (name_lower.indexOf("mita") >= 0 ||
             name_lower.indexOf(router_lower) >= 0))
        {
            Serial.printf("BLETransport: Found router by name: %s\n", name.c_str());
            router_device = new BLEAdvertisedDevice(device);
            pBLEScan->clearResults();
            return true;
        }
    }

    pBLEScan->clearResults();
    Serial.println("BLETransport: No matching router found");
    return false;
}

bool BLETransport::connectToRouter()
{
    if (!router_device)
    {
        Serial.println("BLETransport: No router device to connect to");
        return false;
    }

    // Create client
    client = BLEDevice::createClient();
    client->setClientCallbacks(new MitaBLEClientCallbacks(this));

    // Connect to router
    Serial.println("BLETransport: Connecting to router...");
    if (!client->connect(router_device))
    {
        Serial.println("BLETransport: Connection failed");
        return false;
    }

    Serial.println("BLETransport: Connected! Getting service...");

    // Get the Mita service
    BLERemoteService *pService = client->getService(MITA_SERVICE_UUID);
    if (!pService)
    {
        Serial.println("BLETransport: Mita service not found");
        client->disconnect();
        return false;
    }

    Serial.println("BLETransport: Service found! Getting characteristic...");

    // Get the Mita characteristic
    characteristic = pService->getCharacteristic(MITA_CHARACTERISTIC_UUID);
    if (!characteristic)
    {
        Serial.println("BLETransport: Mita characteristic not found");
        client->disconnect();
        return false;
    }

    Serial.println("BLETransport: Characteristic found!");

    // Register for notifications if supported
    if (characteristic->canNotify())
    {
        Serial.println("BLETransport: Registering for notifications...");
        characteristic->registerForNotify(notifyCallback);
        Serial.println("BLETransport: Notifications registered");
    }
    else
    {
        Serial.println("BLETransport: Warning - characteristic does not support notifications");
    }

    ble_connected = true;
    client_connected = true;

    Serial.println("BLETransport: Connection setup complete");
    return true;
}

void BLETransport::disconnect()
{
    if (client && client->isConnected())
    {
        client->disconnect();
    }
    
    if (router_device)
    {
        delete router_device;
        router_device = nullptr;
    }
    
    client = nullptr;
    characteristic = nullptr;
    ble_connected = false;
    client_connected = false;
    
    Serial.println("BLETransport: Disconnected");
}

bool BLETransport::isConnected() const
{
    return ble_connected && client_connected && client && client->isConnected();
}

bool BLETransport::sendPacket(const BasicProtocolPacket &packet)
{
    if (!isConnected() || !characteristic)
    {
        Serial.println("BLETransport: Cannot send - not connected");
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    try
    {
        // Write value to characteristic (without response for speed)
        characteristic->writeValue(buffer, length, false);
        return true;
    }
    catch (...)
    {
        Serial.println("BLETransport: Exception during packet send");
        return false;
    }
}

bool BLETransport::receivePacket(BasicProtocolPacket &packet, unsigned long timeout_ms)
{
    unsigned long start_time = millis();

    while (millis() - start_time < timeout_ms)
    {
        if (packet_available)
        {
            if (PacketUtils::deserializePacket(packet_buffer, packet_length, packet))
            {
                packet_available = false;
                packet_length = 0;
                return true;
            }
            else
            {
                Serial.println("BLETransport: Failed to deserialize packet");
                packet_available = false;
                packet_length = 0;
            }
        }
        delay(10);
    }

    return false;
}

TransportType BLETransport::getType() const
{
    return TRANSPORT_BLE;
}

String BLETransport::getConnectionInfo() const
{
    if (!ble_connected)
    {
        return "BLE: Disconnected";
    }
    return String("BLE: Connected to router (") + device_id + ")";
}

void BLETransport::onServerConnect()
{
    client_connected = true;
    Serial.println("BLETransport: Server connection established");
}

void BLETransport::onServerDisconnect()
{
    client_connected = false;
    ble_connected = false;
    Serial.println("BLETransport: Server disconnected");
}

void BLETransport::onDataReceived(const uint8_t *data, size_t length)
{
    if (length <= sizeof(packet_buffer))
    {
        memcpy(packet_buffer, data, length);
        packet_length = length;
        packet_available = true;
        Serial.printf("BLETransport: Received %d bytes\n", length);
    }
    else
    {
        Serial.printf("BLETransport: Received packet too large (%d bytes)\n", length);
    }
}

// Static notification callback
void BLETransport::notifyCallback(BLERemoteCharacteristic *pChar,
                                   uint8_t *data, size_t length, bool isNotify)
{
    if (instance)
    {
        instance->onDataReceived(data, length);
    }
}
