#include "../include/transport/ble_transport.h"

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

// BLETransport implementation
BLETransport::BLETransport(const String &device_id, const String &router_id)
    : device_id(device_id), router_id(router_id),
      server(nullptr), characteristic(nullptr),
      ble_connected(false), client_connected(false),
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

    delay(3000); // Wait for GATT setup
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
    Serial.println("BLETransport: Disconnected");
}

bool BLETransport::isConnected() const
{
    return ble_connected && client_connected;
}

bool BLETransport::sendPacket(const ProtocolPacket &packet)
{
    if (!isConnected() || !characteristic)
    {
        return false;
    }

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;
    serializePacket(packet, buffer, length);

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

bool BLETransport::receivePacket(ProtocolPacket &packet, unsigned long timeout_ms)
{
    unsigned long start_time = millis();

    while (millis() - start_time < timeout_ms)
    {
        if (packet_available)
        {
            if (deserializePacket(packet_buffer, packet_length, packet))
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
    Serial.println("BLETransport: Client disconnected");
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
    characteristic->addDescriptor(new BLE2902());

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
    advertising->setMinPreferred(0x06);
    advertising->setMinPreferred(0x12);

    BLEDevice::startAdvertising();

    Serial.printf("BLETransport: Advertising started with name: %s\n", ble_name.c_str());
    return true;
}

void BLETransport::serializePacket(const ProtocolPacket &packet, uint8_t *buffer, size_t &length)
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

bool BLETransport::deserializePacket(const uint8_t *buffer, size_t length, ProtocolPacket &packet)
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