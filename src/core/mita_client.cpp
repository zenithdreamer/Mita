#include "../include/core/mita_client.h"
#include "../include/transport/wifi_transport.h"
#include "../include/transport/ble_transport.h"

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

MitaClient::MitaClient(const NetworkConfig &config)
    : transport(nullptr), network_config(config),
      assigned_address(UNASSIGNED_ADDRESS), handshake_completed(false),
      last_heartbeat(0), last_sensor_reading(0)
{
    // Initialize nonce arrays to zero
    memset(nonce1, 0, NONCE_SIZE);
    memset(nonce2, 0, NONCE_SIZE);
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

    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_HEARTBEAT;
    packet.source_addr = assigned_address;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;
    packet.sequence_number = 0; 
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_LOW;
    packet.fragment_id = 0;
    packet.timestamp = (uint16_t)(millis() & 0xFFFF);
    packet.payload_length = 0;

    Serial.println("MitaClient: Sending heartbeat");
    return transport->sendPacket(packet);
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
    BasicProtocolPacket packet;
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

    crypto_service.generateNonce(nonce1);

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

    // Copy 16-byte nonce1
    memcpy(payload + offset, nonce1, NONCE_SIZE);
    offset += NONCE_SIZE;

    packet.payload_length = offset;

    Serial.print("MitaClient: Sending HELLO (nonce1: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce1[i] < 0x10)
            Serial.print("0");
        Serial.print(nonce1[i], HEX);
    }
    Serial.println(")");

    // Debug: Print packet header for checksum debugging
    Serial.printf("MitaClient: HELLO packet header: ver_flags=0x%02X type=0x%02X src=0x%04X dst=0x%04X len=%d chk=0x%02X seq=%d\n",
                  packet.version_flags, packet.msg_type, packet.source_addr, packet.dest_addr,
                  packet.payload_length, packet.checksum, packet.sequence_number);

    return transport->sendPacket(packet);
}

bool MitaClient::receiveChallenge()
{
    BasicProtocolPacket packet;
    if (!transport->receivePacket(packet, 5000) || packet.msg_type != MSG_CHALLENGE)
    {
        return false;
    }

    // Expect 24 bytes: 16-byte nonce2 + 8-byte timestamp
    if (packet.payload_length < 24)
    {
        Serial.printf("MitaClient: CHALLENGE payload too small: %d bytes (expected 24)\n", packet.payload_length);
        return false;
    }

    // Extract 16-byte nonce2
    memcpy(nonce2, packet.payload, NONCE_SIZE);

    // Extract 8-byte timestamp (we don't need to use it, but we acknowledge its presence)
    uint64_t timestamp_ms = 0;
    for (int i = 0; i < 8; i++)
    {
        timestamp_ms = (timestamp_ms << 8) | packet.payload[NONCE_SIZE + i];
    }

    Serial.print("MitaClient: Received CHALLENGE (nonce2: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce2[i] < 0x10)
            Serial.print("0");
        Serial.print(nonce2[i], HEX);
    }
    Serial.printf(", timestamp: %llu)\n", timestamp_ms);

    return true;
}

bool MitaClient::sendAuth()
{
    BasicProtocolPacket packet;
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

    // Construct HMAC data: nonce2 (16 bytes) || device_id || router_id
    size_t data_len = NONCE_SIZE + network_config.device_id.length() + network_config.router_id.length();
    uint8_t *auth_data = new uint8_t[data_len];

    // Copy full 16-byte nonce2
    memcpy(auth_data, nonce2, NONCE_SIZE);

    memcpy(auth_data + NONCE_SIZE, network_config.device_id.c_str(), network_config.device_id.length());
    memcpy(auth_data + NONCE_SIZE + network_config.device_id.length(),
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

    // Payload: HMAC (16 bytes) || nonce1 (16 bytes) = 32 bytes total
    memcpy(packet.payload, auth_hmac, 16);
    memcpy(packet.payload + 16, nonce1, NONCE_SIZE);

    packet.payload_length = 32; // Changed from 20 to 32

    Serial.println("MitaClient: Sending AUTH (32 bytes)");
    return transport->sendPacket(packet);
}

bool MitaClient::receiveAuthAck()
{
    BasicProtocolPacket packet;
    if (!transport->receivePacket(packet, 5000) || packet.msg_type != MSG_AUTH_ACK)
    {
        return false;
    }

    // Expect 18 bytes: HMAC (16) + address (2)
    if (packet.payload_length < 18)
    {
        Serial.printf("MitaClient: AUTH_ACK payload too small: %d bytes (expected 18)\n", packet.payload_length);
        return false;
    }

    // Verify HMAC computed over full 16-byte nonce1
    uint8_t expected_hmac[HMAC_SIZE];
    if (!crypto_service.computeHMAC(
            (uint8_t *)network_config.shared_secret.c_str(), network_config.shared_secret.length(),
            nonce1, NONCE_SIZE, expected_hmac))
    {
        Serial.println("MitaClient: Failed to compute expected HMAC");
        return false;
    }

    // Constant-time comparison (protect against timing attacks)
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++)
    {
        diff |= packet.payload[i] ^ expected_hmac[i];
    }

    if (diff != 0)
    {
        Serial.println("MitaClient: Router authentication failed - HMAC mismatch");
        return false;
    }

    assigned_address = (packet.payload[16] << 8) | packet.payload[17];

    // Derive session key from both 16-byte nonces
    if (!crypto_service.deriveSessionKey(network_config.shared_secret, nonce1, nonce2))
    {
        Serial.println("MitaClient: Failed to derive session key");
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
    BasicProtocolPacket packet;

    if (transport->receivePacket(packet, 10))
    {
        if (packet.msg_type == MSG_DATA)
        {
            uint8_t decrypted[MAX_PAYLOAD_SIZE];
            size_t decrypted_length;

            // Use AES-GCM authenticated decryption
            if (crypto_service.decryptGCM(packet.payload, packet.payload_length,
                                          nullptr, 0, // No AAD for now
                                          decrypted, decrypted_length))
            {
                String message = String((char *)decrypted, decrypted_length);
                Serial.printf("MitaClient: Received GCM authenticated message: %s\n", message.c_str());

                String response;
                if (message_dispatcher.processMessage(message, response))
                {
                    // TODO: Test sending to router
                    sendEncryptedMessage(ROUTER_ADDRESS, response);

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
            else
            {
                Serial.println("MitaClient: Failed to decrypt message - MAC verification may have failed");
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

    BasicProtocolPacket packet;
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
    // Use AES-GCM authenticated encryption
    if (!crypto_service.encryptGCM((uint8_t *)message.c_str(), message.length(),
                                   nullptr, 0, // No AAD for now
                                   packet.payload, encrypted_len))
    {
        Serial.println("MitaClient: Failed to encrypt message with GCM");
        return false;
    }

    packet.payload_length = encrypted_len;
    Serial.printf("MitaClient: Sending authenticated encrypted message (%d bytes)\n", encrypted_len);
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