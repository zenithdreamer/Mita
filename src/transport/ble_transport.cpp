#include "../include/transport/ble_transport.h"
#include "../shared/protocol/packet_utils.h"
#include "../shared/config/mita_config.h"

// BLE Callback implementations
MitaBLEServerCallbacks::MitaBLEServerCallbacks(BLETransport *transport) : transport(transport) {}

void MitaBLEServerCallbacks::onConnect(BLEServer *server)
{
    transport->onClientConnect();
}

void MitaBLEServerCallbacks::onDisconnect(BLEServer *server)
{
    transport->onClientDisconnect();
}

MitaBLECharacteristicCallbacks::MitaBLECharacteristicCallbacks(BLETransport *transport) : transport(transport) {}

void MitaBLECharacteristicCallbacks::onWrite(BLECharacteristic *characteristic)
{
    std::string value = characteristic->getValue();
    if (value.length() > 0)
    {
        transport->onDataReceived((const uint8_t *)value.data(), value.length());
    }
}

void MitaBLECharacteristicCallbacks::onNotify(BLECharacteristic *characteristic)
{
    // This gets called when notifications are sent
}

MitaBLEDescriptorCallbacks::MitaBLEDescriptorCallbacks(BLETransport *transport) : transport(transport) {}

void MitaBLEDescriptorCallbacks::onWrite(BLEDescriptor *descriptor)
{
    uint8_t* value = descriptor->getValue();
    if (value != nullptr)
    {
        // BLE2902 descriptor: 0x01 = notifications enabled, 0x00 = disabled
        if (value[0] == 0x01)
        {
            transport->onNotificationsEnabled();
        }
        else if (value[0] == 0x00)
        {
            transport->onNotificationsDisabled();
        }
    }
}

// BLETransport implementation
BLETransport::BLETransport(const String &device_id, const String &router_id)
    : device_id(device_id), router_id(router_id),
      server(nullptr), characteristic(nullptr),
      ble_connected(false), client_connected(false), notifications_enabled(false),
      packet_length(0), packet_available(false)
{
}

BLETransport::~BLETransport()
{
    disconnect();
}

bool BLETransport::connect()
{
    Serial.println("BLETransport: Attempting connection...");

    if (!setupServer())
    {
        Serial.println("BLETransport: Failed to setup server");
        return false;
    }

    if (!startAdvertising())
    {
        Serial.println("BLETransport: Failed to start advertising");
        return false;
    }

    Serial.println("BLETransport: Waiting for router connection...");

    unsigned long start_time = millis();
    while (!client_connected && (millis() - start_time) < 30000)
    {
        delay(100);
    }

    if (!client_connected)
    {
        Serial.println("BLETransport: Router did not connect");
        return false;
    }

    Serial.println("BLETransport: Client connected");

    // Wait for router to enable notifications before considering connection ready
    Serial.println("BLETransport: Waiting for notifications to be enabled...");
    start_time = millis();
    while (!notifications_enabled && (millis() - start_time) < 15000)
    {
        delay(100);
    }

    if (!notifications_enabled)
    {
        Serial.println("BLETransport: Router did not enable notifications");
        return false;
    }

    ble_connected = true;
    Serial.println("BLETransport: Connection successful");
    return true;
}

void BLETransport::disconnect()
{
    if (server)
    {
        server->getAdvertising()->stop();
        BLEDevice::deinit(true);
        server = nullptr;
        characteristic = nullptr;
    }
    ble_connected = false;
    client_connected = false;
    notifications_enabled = false;
    Serial.println("BLETransport: Disconnected");
}

bool BLETransport::isConnected() const
{
    return ble_connected && client_connected;
}

bool BLETransport::sendPacket(const BasicProtocolPacket &packet)
{
    if (!isConnected() || !characteristic)
    {
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    PacketUtils::serializePacket(packet, buffer, length);

    try
    {
        characteristic->setValue(buffer, length);
        characteristic->notify();
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
    return String("BLE: Connected (") + device_id + ")";
}

void BLETransport::onClientConnect()
{
    client_connected = true;
    Serial.println("BLETransport: Client connected");
}

void BLETransport::onClientDisconnect()
{
    client_connected = false;
    notifications_enabled = false;
    Serial.println("BLETransport: Client disconnected");
}

void BLETransport::onNotificationsEnabled()
{
    notifications_enabled = true;
    Serial.println("BLETransport: Notifications enabled by router");
}

void BLETransport::onNotificationsDisabled()
{
    notifications_enabled = false;
    Serial.println("BLETransport: Notifications disabled by router");
}

void BLETransport::onDataReceived(const uint8_t *data, size_t length)
{
    if (length <= sizeof(packet_buffer))
    {
        memcpy(packet_buffer, data, length);
        packet_length = length;
        packet_available = true;
    }
}

bool BLETransport::setupServer()
{
    BLEDevice::init(device_id.c_str());

    server = BLEDevice::createServer();
    server->setCallbacks(new MitaBLEServerCallbacks(this));

    BLEService *service = server->createService(MITA_SERVICE_UUID);

    characteristic = service->createCharacteristic(
        MITA_CHARACTERISTIC_UUID,
        BLECharacteristic::PROPERTY_READ |
            BLECharacteristic::PROPERTY_WRITE |
            BLECharacteristic::PROPERTY_WRITE_NR |
            BLECharacteristic::PROPERTY_NOTIFY);

    characteristic->setCallbacks(new MitaBLECharacteristicCallbacks(this));

    BLE2902* descriptor = new BLE2902();
    descriptor->setCallbacks(new MitaBLEDescriptorCallbacks(this));
    characteristic->addDescriptor(descriptor);

    service->start();
    return true;
}

bool BLETransport::startAdvertising()
{
    BLEAdvertising *advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(MITA_SERVICE_UUID);

    String ble_name = router_id + "_" + device_id;
    esp_ble_gap_set_device_name(ble_name.c_str());

    advertising->setScanResponse(true);
    advertising->setMinPreferred(MITA_BLE_MIN_INTERVAL);
    advertising->setMinPreferred(MITA_BLE_MAX_INTERVAL);

    BLEDevice::startAdvertising();

    Serial.printf("BLETransport: Advertising started with name: %s\n", ble_name.c_str());
    return true;
}

