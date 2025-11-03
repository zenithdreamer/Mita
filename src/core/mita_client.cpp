#include "../include/core/mita_client.h"
#include "../include/transport/wifi_transport.h"
#include "../include/transport/ble_transport.h"

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

MitaClient::MitaClient(const NetworkConfig &config)
    : transport(nullptr), network_config(config),
      assigned_address(UNASSIGNED_ADDRESS), handshake_completed(false),
      nonce1(0), nonce2(0), last_heartbeat(0), last_sensor_reading(0)
{
}

MitaClient::~MitaClient()
{
    disconnect();
}

bool MitaClient::initialize()
{
    Serial.println("MitaClient: Initializing...");

    // Initialize LED pin
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, LOW);

    Serial.printf("MitaClient: Device ID: %s\n", network_config.device_id.c_str());
    Serial.printf("MitaClient: Router ID: %s\n", network_config.router_id.c_str());

    return true;
}

bool MitaClient::connectToNetwork(ITransport *transport_impl)
{
    if (!transport_impl)
    {
        Serial.println("MitaClient: No transport provided");
        return false;
    }

    transport = transport_impl;
    Serial.printf("MitaClient: Attempting to connect via %s\n",
                  transport->getType() == TRANSPORT_WIFI ? "WiFi" : "BLE");

    if (!transport->connect())
    {
        Serial.println("MitaClient: Transport connection failed");
        return false;
    }

    if (!performHandshake())
    {
        Serial.println("MitaClient: Handshake failed");
        transport->disconnect();
        return false;
    }

    Serial.println("MitaClient: Successfully connected to network");
    Serial.printf("MitaClient: Assigned address: 0x%04X\n", assigned_address);
    Serial.printf("MitaClient: Transport: %s\n", transport->getConnectionInfo().c_str());

    return true;
}

void MitaClient::disconnect()
{
    if (transport)
    {
        transport->disconnect();
        transport = nullptr;
    }

    handshake_completed = false;
    assigned_address = UNASSIGNED_ADDRESS;
    crypto_service.clearSessionKey();

    Serial.println("MitaClient: Disconnected");
}

void MitaClient::update()
{
    if (!isConnected())
    {
        return;
    }

    unsigned long current_time = millis();

    // Handle incoming messages
    handleIncomingMessages();

    // Send periodic heartbeat
    if (current_time - last_heartbeat >= HEARTBEAT_INTERVAL)
    {
        sendHeartbeat();
        last_heartbeat = current_time;
    }

    // Send sensor data
    if (current_time - last_sensor_reading >= SENSOR_INTERVAL)
    {
        sendSensorData();
        last_sensor_reading = current_time;
    }
}

bool MitaClient::isConnected() const
{
    return transport && transport->isConnected() && handshake_completed;
}

TransportType MitaClient::getTransportType() const
{
    return transport ? transport->getType() : TRANSPORT_WIFI;
}

uint16_t MitaClient::getAssignedAddress() const
{
    return assigned_address;
}

String MitaClient::getDeviceId() const
{
    return network_config.device_id;
}

bool MitaClient::sendHeartbeat()
{
    DynamicJsonDocument doc(256);
    doc["type"] = "heartbeat";
    doc["device_id"] = network_config.device_id;
    doc["timestamp"] = millis();
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["transport"] = transport->getType() == TRANSPORT_WIFI ? "wifi" : "ble";

    String message;
    serializeJson(doc, message);

    Serial.printf("MitaClient: Sending heartbeat (%d bytes)\n", message.length());
    return sendEncryptedMessage(ROUTER_ADDRESS, message);
}

//send data to router
bool MitaClient::sendSensorData()
{
    String sensor_data = generateSensorData();

    Serial.printf("MitaClient: Sending sensor data (%d bytes)\n", sensor_data.length());
    return sendEncryptedMessage(ROUTER_ADDRESS, sensor_data);
}

//test send data to another esp via router
// bool MitaClient::sendSensorData()
// {
//     if (network_config.device_id != "ESP32_Sensor_001")
//     {
//         Serial.println("MitaClient: This device doesn't send sensor data");
//         return true;
//     }

//     String sensor_data = generateSensorData();


//     uint16_t target_address = 2;

//     Serial.printf("MitaClient: Sending sensor data to ESP32_Sensor_002 (address 0x%04X) (%d bytes)\n", target_address, sensor_data.length());
//     return sendEncryptedMessage(target_address, sensor_data);
// }

void MitaClient::setNetworkConfig(const NetworkConfig &config)
{
    network_config = config;
}

bool MitaClient::addMessageHandler(IMessageHandler *handler)
{
    return message_dispatcher.addHandler(handler);
}

bool MitaClient::performHandshake()
{
    Serial.println("MitaClient: Starting handshake...");

    if (!sendHello())
    {
        Serial.println("MitaClient: Failed to send HELLO");
        return false;
    }

    if (!receiveChallenge())
    {
        Serial.println("MitaClient: Failed to receive CHALLENGE");
        return false;
    }

    if (!sendAuth())
    {
        Serial.println("MitaClient: Failed to send AUTH");
        return false;
    }

    if (!receiveAuthAck())
    {
        Serial.println("MitaClient: Failed to receive AUTH_ACK");
        return false;
    }

    handshake_completed = true;
    Serial.println("MitaClient: Handshake completed successfully");
    return true;
}

bool MitaClient::sendHello()
{
    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_HELLO;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0; // Will be computed automatically
    packet.sequence_number = 0; // Handshake packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // Handshake is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint16_t)(millis() & 0xFFFF);

    nonce1 = crypto_service.generateNonce();

    uint8_t *payload = packet.payload;
    size_t offset = 0;

    uint8_t rid_len = network_config.router_id.length();
    payload[offset++] = rid_len;
    memcpy(payload + offset, network_config.router_id.c_str(), rid_len);
    offset += rid_len;

    uint8_t device_len = network_config.device_id.length();
    payload[offset++] = device_len;
    memcpy(payload + offset, network_config.device_id.c_str(), device_len);
    offset += device_len;

    payload[offset++] = (nonce1 >> 24) & 0xFF;
    payload[offset++] = (nonce1 >> 16) & 0xFF;
    payload[offset++] = (nonce1 >> 8) & 0xFF;
    payload[offset++] = nonce1 & 0xFF;

    packet.payload_length = offset;

    Serial.printf("MitaClient: Sending HELLO (nonce1: 0x%08X)\n", nonce1);
    return transport->sendPacket(packet);
}

bool MitaClient::receiveChallenge()
{
    ProtocolPacket packet;
    if (!transport->receivePacket(packet, 5000) || packet.msg_type != MSG_CHALLENGE)
    {
        return false;
    }

    if (packet.payload_length < 4)
    {
        return false;
    }

    nonce2 = (packet.payload[0] << 24) |
             (packet.payload[1] << 16) |
             (packet.payload[2] << 8) |
             packet.payload[3];

    Serial.printf("MitaClient: Received CHALLENGE (nonce2: 0x%08X)\n", nonce2);
    return true;
}

bool MitaClient::sendAuth()
{
    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_AUTH;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0; // Will be computed automatically
    packet.sequence_number = 0; // Handshake packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // Handshake is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint16_t)(millis() & 0xFFFF);

    size_t data_len = 4 + network_config.device_id.length() + network_config.router_id.length();
    uint8_t *auth_data = new uint8_t[data_len];

    auth_data[0] = (nonce2 >> 24) & 0xFF;
    auth_data[1] = (nonce2 >> 16) & 0xFF;
    auth_data[2] = (nonce2 >> 8) & 0xFF;
    auth_data[3] = nonce2 & 0xFF;

    memcpy(auth_data + 4, network_config.device_id.c_str(), network_config.device_id.length());
    memcpy(auth_data + 4 + network_config.device_id.length(),
           network_config.router_id.c_str(), network_config.router_id.length());

    uint8_t auth_hmac[HMAC_SIZE];
    bool hmac_result = crypto_service.computeHMAC(
        (uint8_t *)network_config.shared_secret.c_str(), network_config.shared_secret.length(),
        auth_data, data_len, auth_hmac);

    delete[] auth_data;

    if (!hmac_result)
    {
        Serial.println("MitaClient: Failed to compute AUTH HMAC");
        return false;
    }

    memcpy(packet.payload, auth_hmac, 16);
    packet.payload[16] = (nonce1 >> 24) & 0xFF;
    packet.payload[17] = (nonce1 >> 16) & 0xFF;
    packet.payload[18] = (nonce1 >> 8) & 0xFF;
    packet.payload[19] = nonce1 & 0xFF;

    packet.payload_length = 20;

    Serial.println("MitaClient: Sending AUTH");
    return transport->sendPacket(packet);
}

bool MitaClient::receiveAuthAck()
{
    ProtocolPacket packet;
    if (!transport->receivePacket(packet, 5000) || packet.msg_type != MSG_AUTH_ACK)
    {
        return false;
    }

    if (packet.payload_length < 18)
    {
        return false;
    }

    uint8_t verify_data[4];
    verify_data[0] = (nonce1 >> 24) & 0xFF;
    verify_data[1] = (nonce1 >> 16) & 0xFF;
    verify_data[2] = (nonce1 >> 8) & 0xFF;
    verify_data[3] = nonce1 & 0xFF;

    uint8_t expected_hmac[HMAC_SIZE];
    if (!crypto_service.computeHMAC(
            (uint8_t *)network_config.shared_secret.c_str(), network_config.shared_secret.length(),
            verify_data, 4, expected_hmac))
    {
        return false;
    }

    if (memcmp(packet.payload, expected_hmac, 16) != 0)
    {
        Serial.println("MitaClient: Router authentication failed");
        return false;
    }

    assigned_address = (packet.payload[16] << 8) | packet.payload[17];

    if (!crypto_service.deriveSessionKey(network_config.shared_secret, nonce1, nonce2))
    {
        return false;
    }

    // Log session key for debugging/decryption purposes
    uint8_t session_key_bytes[SESSION_KEY_SIZE];
    crypto_service.getSessionKey(session_key_bytes);
    
    Serial.println("MitaClient: ========================================");
    Serial.println("MitaClient: SESSION KEY");
    Serial.print("MitaClient: ");
    for (int i = 0; i < SESSION_KEY_SIZE; i++)
    {
        if (session_key_bytes[i] < 0x10) Serial.print("0");
        Serial.print(session_key_bytes[i], HEX);
    }
    Serial.println();
    Serial.println("MitaClient: ========================================");

    Serial.printf("MitaClient: AUTH_ACK received, assigned address: 0x%04X\n", assigned_address);
    return true;
}

void MitaClient::handleIncomingMessages()
{
    ProtocolPacket packet;

    if (transport->receivePacket(packet, 10))
    {
        if (packet.msg_type == MSG_DATA)
        {
            uint8_t decrypted[MAX_PAYLOAD_SIZE];
            unsigned int decrypted_length;

            if (crypto_service.decryptPayload(packet.payload, packet.payload_length,
                                              decrypted, decrypted_length))
            {
                String message = String((char *)decrypted, decrypted_length);
                Serial.printf("MitaClient: Received message: %s\n", message.c_str());

                String response;
                if (message_dispatcher.processMessage(message, response))
                {
                    sendEncryptedMessage(packet.source_addr, response);

                    // Special handling for restart command
                    DynamicJsonDocument doc(256);
                    if (deserializeJson(doc, response) == DeserializationError::Ok)
                    {
                        if (doc["command"] == "restart" && doc["status"] == "restarting")
                        {
                            delay(1000);
                            ESP.restart();
                        }
                    }
                }
            }
        }
    }
}

bool MitaClient::sendEncryptedMessage(uint16_t dest_addr, const String &message)
{
    if (!crypto_service.hasValidSessionKey())
    {
        return false;
    }

    // Simple sequence number using milliseconds (wraps every 65 seconds)
    static uint16_t sequence_counter = 0;
    sequence_counter++;

    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4) | FLAG_ENCRYPTED;
    packet.msg_type = MSG_DATA;
    packet.source_addr = assigned_address;
    packet.dest_addr = dest_addr;
    packet.checksum = 0; // Will be computed automatically
    packet.sequence_number = sequence_counter;
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_NORMAL; // Normal priority for data
    packet.fragment_id = 0;
    packet.timestamp = (uint16_t)(millis() & 0xFFFF);

    size_t encrypted_len;
    if (!crypto_service.encryptPayload((uint8_t *)message.c_str(), message.length(),
                                       packet.payload, encrypted_len))
    {
        return false;
    }

    packet.payload_length = encrypted_len;
    return transport->sendPacket(packet);
}

String MitaClient::generateSensorData()
{
    DynamicJsonDocument doc(256);
    doc["type"] = "sensor_data";
    doc["device_id"] = network_config.device_id;
    doc["timestamp"] = millis();

    doc["temperature"] = 20.0 + (random(0, 200) / 10.0);
    doc["humidity"] = 40.0 + (random(0, 400) / 10.0);
    doc["pressure"] = 1000.0 + (random(0, 100) / 10.0);
    doc["light"] = random(0, 1024);

    String result;
    serializeJson(doc, result);
    return result;
}