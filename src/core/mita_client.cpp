#include "../include/core/mita_client.h"
#include "../include/transport/wifi_transport.h"
#include "../include/transport/ble_transport.h"
#include "../include/transport/protocol_selector.h"

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

MitaClient::MitaClient(const NetworkConfig &config)
    : transport(nullptr), network_config(config),
      assigned_address(UNASSIGNED_ADDRESS), handshake_completed(false),
      challenge_baseline_timestamp(0), challenge_baseline_millis(0),
      last_heartbeat(0), last_sensor_reading(0), last_ping_sent(0),
      qos_level(QoSLevel::WITH_ACK),  // Default to QoS with ACK
      packets_sent(0)  // Initialize packet counter for session rekey
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

    // Always derive device-specific PSK from master secret (forced for security)
    Serial.println("MitaClient: Deriving device-specific PSK from master secret...");
    uint8_t device_psk[HMAC_SIZE];
    
    if (!CryptoService::deriveDevicePSK(network_config.shared_secret, 
                                       network_config.device_id, 
                                       device_psk))
    {
        Serial.println("MitaClient: ERROR - Failed to derive device PSK!");
        return false;
    }
    
    // Replace shared_secret with derived device PSK (as binary string)
    network_config.shared_secret = String((char*)device_psk, HMAC_SIZE);
    
#ifdef DEBUG_CRYPTO
    Serial.println("MitaClient: Device PSK derived and configured");
    Serial.println("MitaClient: ========================================");
    Serial.print("MitaClient: Device PSK (hex): ");
    for (int i = 0; i < 16; i++)  // Show first 16 bytes
    {
        if (device_psk[i] < 0x10) Serial.print("0");
        Serial.print(device_psk[i], HEX);
    }
    Serial.println("...");
    Serial.println("MitaClient: ========================================");
#else
    Serial.println("MitaClient: Device PSK derived and configured");
#endif

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

bool MitaClient::connectToNetworkSmart(ProtocolSelector* selector, const String& shared_secret)
{
    if (!selector)
    {
        Serial.println("MitaClient: No protocol selector provided");
        return false;
    }

    Serial.println("MitaClient: Starting smart protocol selection...");

    // Get priority list of protocols to try
    TransportType priority_list[2];
    size_t protocol_count = 0;
    selector->getProtocolPriority(priority_list, protocol_count);

    // Try each protocol in priority order
    for (size_t i = 0; i < protocol_count; i++)
    {
        TransportType protocol = priority_list[i];
        const char* protocol_name = (protocol == TRANSPORT_WIFI) ? "WiFi" : "BLE";

        Serial.printf("\nMitaClient: Attempting connection via %s (priority %d/%d)\n",
                     protocol_name, i + 1, protocol_count);

        // Create appropriate transport
        ITransport* transport_impl = nullptr;
        unsigned long connect_start = millis();

        if (protocol == TRANSPORT_WIFI)
        {
            transport_impl = new WiFiTransport(shared_secret);
        }
        else
        {
            transport_impl = new BLETransport(network_config.device_id, network_config.router_id);
        }

        if (!transport_impl)
        {
            Serial.printf("MitaClient: Failed to create %s transport\n", protocol_name);
            selector->reportConnectionAttempt(protocol, false, 0, -100);
            continue;
        }

        // Attempt connection
        bool connect_success = connectToNetwork(transport_impl);
        int connect_time_ms = millis() - connect_start;

        if (connect_success)
        {
            // Get signal strength for reporting
            int signal_strength = -100;
            if (protocol == TRANSPORT_WIFI)
            {
                WiFiTransport* wifi = static_cast<WiFiTransport*>(transport_impl);
                signal_strength = wifi->getSignalStrength();
            }
            // BLE signal strength would need to be added to BLETransport

            Serial.printf("MitaClient: ✓ Successfully connected via %s in %d ms\n",
                         protocol_name, connect_time_ms);

            // Report success to selector for learning
            selector->reportConnectionAttempt(protocol, true, connect_time_ms, signal_strength);

            return true;
        }
        else
        {
            Serial.printf("MitaClient: Failed to connect via %s (took %d ms)\n",
                         protocol_name, connect_time_ms);

            // Report failure to selector for learning
            selector->reportConnectionAttempt(protocol, false, connect_time_ms, -100);

            // Clean up failed transport
            delete transport_impl;
            transport = nullptr;
        }
    }

    Serial.println("\nMitaClient: All connection methods failed");
    return false;
}

void MitaClient::disconnect()
{
    // Default disconnect with NORMAL_SHUTDOWN reason
    disconnect(DisconnectReason::NORMAL_SHUTDOWN);
}

void MitaClient::disconnect(DisconnectReason reason)
{
    if (!transport)
    {
        return;
    }

    // If we have an active session, send graceful disconnect
    if (handshake_completed && assigned_address != UNASSIGNED_ADDRESS)
    {
        Serial.printf("MitaClient: Sending graceful disconnect (reason: 0x%02X)\n", 
                     static_cast<uint8_t>(reason));
        
        if (sendDisconnect(reason))
        {
            // Wait briefly for DISCONNECT_ACK (best effort)
            receiveDisconnectAck();
        }
    }

    // Clean up connection state
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
    packet.timestamp = (uint32_t)millis();
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

bool MitaClient::sendPing()
{
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_CONTROL;  // Use CONTROL message for PING
    packet.source_addr = assigned_address;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;
    packet.sequence_number = 0;
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH;  // PING is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)millis();

    // Payload: PING control type (0x00) + timestamp for RTT calculation
    packet.payload[0] = 0x00;  // ControlType::PING
    uint32_t ping_time = millis();
    packet.payload[1] = (ping_time >> 24) & 0xFF;
    packet.payload[2] = (ping_time >> 16) & 0xFF;
    packet.payload[3] = (ping_time >> 8) & 0xFF;
    packet.payload[4] = ping_time & 0xFF;
    packet.payload_length = 5;

    last_ping_sent = ping_time;
    
    Serial.printf("MitaClient: Sending PING (time=%lu)\n", ping_time);
    return transport->sendPacket(packet);
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

    // Reset timestamp validation baseline for each new handshake
    challenge_baseline_timestamp = 0;
    challenge_baseline_millis = 0;

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
    packet.timestamp = (uint32_t)millis();

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

#ifdef DEBUG_CRYPTO
    Serial.print("MitaClient: Sending HELLO (nonce1: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce1[i] < 0x10)
            Serial.print("0");
        Serial.print(nonce1[i], HEX);
    }
    Serial.println(")");
#else
    Serial.println("MitaClient: Sending HELLO");
#endif

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

    // Extract 8-byte timestamp
    uint64_t timestamp_ms = 0;
    for (int i = 0; i < 8; i++)
    {
        timestamp_ms = (timestamp_ms << 8) | packet.payload[NONCE_SIZE + i];
    }

    // Validate challenge timestamp freshness (10-second window)
    // Protects against replay attacks using old CHALLENGE packets
    // Use instance variables (not static) to reset baseline per handshake attempt
    
    // On first CHALLENGE of this handshake, establish baseline
    if (challenge_baseline_timestamp == 0)
    {
        challenge_baseline_timestamp = timestamp_ms;
        challenge_baseline_millis = millis();
        Serial.printf("MitaClient: Established timestamp baseline: %llu ms\n", timestamp_ms);
    }
    else
    {
        // Calculate expected timestamp based on elapsed time since first challenge
        unsigned long elapsed_millis = millis() - challenge_baseline_millis;
        uint64_t expected_timestamp = challenge_baseline_timestamp + elapsed_millis;
        
        // Strict 2-second window for clock drift and network delays 
        const uint64_t MAX_TIMESTAMP_DRIFT_MS = 2000;
        
        uint64_t timestamp_diff;
        if (timestamp_ms > expected_timestamp)
        {
            timestamp_diff = timestamp_ms - expected_timestamp;
        }
        else
        {
            timestamp_diff = expected_timestamp - timestamp_ms;
        }
        
        if (timestamp_diff > MAX_TIMESTAMP_DRIFT_MS)
        {
            Serial.printf("MitaClient: CHALLENGE timestamp drift too large: %llu ms (expected ~%llu, got %llu)\n", 
                         timestamp_diff, expected_timestamp, timestamp_ms);
            Serial.println("MitaClient: Possible replay attack detected");
            return false;
        }
        
        Serial.printf("MitaClient: Timestamp validation passed (drift: %llu ms)\n", timestamp_diff);
    }

#ifdef DEBUG_CRYPTO
    Serial.print("MitaClient: Received CHALLENGE (nonce2: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce2[i] < 0x10)
            Serial.print("0");
        Serial.print(nonce2[i], HEX);
    }
    Serial.printf(", timestamp: %llu)\n", timestamp_ms);
#else
    Serial.printf("MitaClient: Received CHALLENGE (timestamp: %llu)\n", timestamp_ms);
#endif

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
    packet.timestamp = (uint32_t)millis();

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

    packet.payload_length = 32;

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

#ifdef DEBUG_CRYPTO
    // Log session key for debugging/decryption purposes (ONLY in debug builds)
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
#endif

    Serial.printf("MitaClient: AUTH_ACK received, assigned address: 0x%04X\n", assigned_address);
    return true;
}

void MitaClient::handleIncomingMessages()
{
    BasicProtocolPacket packet;

    if (transport->receivePacket(packet, 10))
    {
        if (packet.msg_type == MSG_CONTROL)
        {
            // Handle CONTROL messages (PING/PONG, etc.)
            if (packet.payload_length >= 5)
            {
                uint8_t control_type = packet.payload[0];
                
                if (control_type == 0x01)  // ControlType::PONG
                {
                    // Extract original timestamp
                    uint32_t sent_time = ((uint32_t)packet.payload[1] << 24) |
                                        ((uint32_t)packet.payload[2] << 16) |
                                        ((uint32_t)packet.payload[3] << 8) |
                                        ((uint32_t)packet.payload[4]);
                    
                    uint32_t now = millis();
                    uint32_t rtt = now - sent_time;
                    
                    Serial.printf("MitaClient: PONG received! RTT = %lu ms\n", rtt);
                }
            }
            return;
        }
        
        if (packet.msg_type == MSG_ERROR)
        {
            // Handle ERROR message from router
            if (packet.payload_length >= 3)
            {
                uint8_t error_code = packet.payload[0];
                uint16_t failed_seq = (packet.payload[1] << 8) | packet.payload[2];
                
                const char* error_str = "UNKNOWN";
                switch (error_code)
                {
                    case 0x01: error_str = "INVALID_SEQUENCE"; break;
                    case 0x02: error_str = "STALE_TIMESTAMP"; break;
                    case 0x03: error_str = "DECRYPTION_FAILED"; break;
                    case 0x04: error_str = "INVALID_DESTINATION"; break;
                    case 0x05: error_str = "TTL_EXPIRED"; break;
                    case 0x06: error_str = "RATE_LIMIT_EXCEEDED"; break;
                    case 0x07: error_str = "SESSION_EXPIRED"; break;
                    case 0x08: error_str = "MALFORMED_PACKET"; break;
                    case 0x09: error_str = "UNSUPPORTED_VERSION"; break;
                    case 0x0A: error_str = "AUTHENTICATION_FAILED"; break;
                }
                
                Serial.printf("MitaClient: ERROR from router: %s (code=0x%02X, seq=%d)\n",
                             error_str, error_code, failed_seq);
                
                // TODO: React to specific errors
                // - INVALID_SEQUENCE: Reset sequence counter
                // - SESSION_EXPIRED: Reconnect with full handshake
                // - RATE_LIMIT_EXCEEDED: Slow down transmission
            }
            return;
        }
        
        if (packet.msg_type == MSG_DATA)
        {
            uint8_t decrypted[MAX_PAYLOAD_SIZE];
            size_t decrypted_length;

            // Reconstruct AAD from packet header for verification
            uint8_t aad[6];
            aad[0] = (packet.source_addr >> 8) & 0xFF;
            aad[1] = packet.source_addr & 0xFF;
            aad[2] = (packet.dest_addr >> 8) & 0xFF;
            aad[3] = packet.dest_addr & 0xFF;
            aad[4] = (packet.sequence_number >> 8) & 0xFF;
            aad[5] = packet.sequence_number & 0xFF;

            // Use AES-GCM authenticated decryption with AAD
            if (crypto_service.decryptGCM(packet.payload, packet.payload_length,
                                          aad, sizeof(aad),
                                          decrypted, decrypted_length))
            {
                String message = String((char *)decrypted, decrypted_length);
                Serial.printf("MitaClient: Received GCM authenticated message: %s\n", message.c_str());

                String response;
                if (message_dispatcher.processMessage(message, response))
                {
                    // TODO: Test sending to non-existent device
                    sendEncryptedMessage(0x1f3e, response);

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
    // Use the configured QoS level
    return sendEncryptedMessageWithQoS(dest_addr, message, qos_level);
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

void MitaClient::setQoSLevel(QoSLevel level)
{
    qos_level = level;
    Serial.printf("MitaClient: QoS level set to %s\n", 
                  level == QoSLevel::NO_QOS ? "NO_QOS" : "WITH_ACK");
}

QoSLevel MitaClient::getQoSLevel() const
{
    return qos_level;
}

bool MitaClient::sendDisconnect(DisconnectReason reason)
{
    if (!transport)
    {
        return false;
    }

    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_DISCONNECT;
    packet.source_addr = assigned_address;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;
    packet.sequence_number = 0;  // Disconnect packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH;  // Disconnect is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)millis();

    // Payload: disconnect reason (1 byte)
    packet.payload[0] = static_cast<uint8_t>(reason);
    packet.payload_length = 1;

    Serial.printf("MitaClient: Sending DISCONNECT (reason=0x%02X)\n", 
                 static_cast<uint8_t>(reason));
    return transport->sendPacket(packet);
}

bool MitaClient::receiveDisconnectAck()
{
    BasicProtocolPacket packet;
    
    // Wait up to 1 second for DISCONNECT_ACK (best effort)
    if (!transport->receivePacket(packet, 1000))
    {
        Serial.println("MitaClient: No DISCONNECT_ACK received (timeout)");
        return false;
    }

    if (packet.msg_type != MSG_DISCONNECT_ACK)
    {
        Serial.printf("MitaClient: Expected DISCONNECT_ACK, got msg_type=0x%02X\n", 
                     packet.msg_type);
        return false;
    }

    Serial.println("MitaClient: DISCONNECT_ACK received");
    return true;
}

bool MitaClient::waitForAck(uint16_t expected_sequence)
{
    unsigned long start_time = millis();
    unsigned int check_count = 0;
    
    while (millis() - start_time < ACK_TIMEOUT_MS)
    {
        BasicProtocolPacket packet;
        
        // Check for incoming packets with moderate timeout (50ms for better responsiveness)
        if (transport->receivePacket(packet, 50))
        {
            check_count++;
            Serial.printf("MitaClient: Received packet type=0x%02X while waiting for ACK (check #%d)\n", 
                         packet.msg_type, check_count);
            if (packet.msg_type == MSG_ACK)
            {
                // ACK packet contains the sequence number being acknowledged
                // Router sends ACK with sequence number in payload (2 bytes)
                if (packet.payload_length >= 2)
                {
                    uint16_t acked_sequence = (packet.payload[0] << 8) | packet.payload[1];
                    
                    if (acked_sequence == expected_sequence)
                    {
                        Serial.printf("MitaClient: ACK received for sequence %d\n", expected_sequence);
                        return true;
                    }
                    else
                    {
                        Serial.printf("MitaClient: ACK received for wrong sequence (expected %d, got %d)\n", 
                                    expected_sequence, acked_sequence);
                    }
                }
            }
            else if (packet.msg_type == MSG_ERROR)
            {
                // Handle ERROR messages from router
                if (packet.payload_length >= 3)
                {
                    uint8_t error_code = packet.payload[0];
                    uint16_t failed_seq = (packet.payload[1] << 8) | packet.payload[2];
                    
                    const char* error_str = "UNKNOWN";
                    switch (error_code)
                    {
                        case 0x01: error_str = "INVALID_SEQUENCE"; break;
                        case 0x02: error_str = "STALE_TIMESTAMP"; break;
                        case 0x03: error_str = "DECRYPTION_FAILED"; break;
                        case 0x04: error_str = "INVALID_DESTINATION"; break;
                        case 0x05: error_str = "TTL_EXPIRED"; break;
                        case 0x06: error_str = "RATE_LIMIT_EXCEEDED"; break;
                        case 0x07: error_str = "SESSION_EXPIRED"; break;
                        case 0x08: error_str = "MALFORMED_PACKET"; break;
                        case 0x09: error_str = "UNSUPPORTED_VERSION"; break;
                        case 0x0A: error_str = "AUTHENTICATION_FAILED"; break;
                    }
                    
                    Serial.printf("MitaClient: ERROR from router: %s (code=0x%02X, seq=%d)\n", 
                                 error_str, error_code, failed_seq);
                    
                    // If this error is for our current sequence, treat it as a failed ACK
                    if (failed_seq == expected_sequence)
                    {
                        Serial.printf("MitaClient: Packet seq=%d rejected by router, stopping retries\n", expected_sequence);
                        return false;  // Stop retrying - packet was rejected
                    }
                }
            }
            else if (packet.msg_type == MSG_DATA)
            {
                // Handle incoming DATA messages while waiting for ACK
                uint8_t decrypted[MAX_PAYLOAD_SIZE];
                size_t decrypted_length;

                uint8_t aad[6];
                aad[0] = (packet.source_addr >> 8) & 0xFF;
                aad[1] = packet.source_addr & 0xFF;
                aad[2] = (packet.dest_addr >> 8) & 0xFF;
                aad[3] = packet.dest_addr & 0xFF;
                aad[4] = (packet.sequence_number >> 8) & 0xFF;
                aad[5] = packet.sequence_number & 0xFF;

                if (crypto_service.decryptGCM(packet.payload, packet.payload_length,
                                             aad, sizeof(aad),
                                             decrypted, decrypted_length))
                {
                    String message = String((char *)decrypted, decrypted_length);
                    Serial.printf("MitaClient: Received message while waiting for ACK: %s\n", message.c_str());

                    String response;
                    if (message_dispatcher.processMessage(message, response))
                    {
                        // Send response without QoS to avoid nested waiting
                        sendEncryptedMessageWithQoS(packet.source_addr, response, QoSLevel::NO_QOS);
                    }
                }
            }
        }
    }
    
    Serial.printf("MitaClient: ACK timeout for sequence %d after %u checks\n", expected_sequence, check_count);
    return false;
}

bool MitaClient::sendEncryptedMessageWithQoS(uint16_t dest_addr, const String &message, QoSLevel qos)
{
    if (!crypto_service.hasValidSessionKey())
    {
        Serial.println("MitaClient: No valid session key for encryption");
        return false;
    }

    // Increment packet counter for session key rotation
    packets_sent++;
    
    // Check if we need to rotate session key
    if (packets_sent >= REKEY_PACKET_THRESHOLD) {
        Serial.println("MitaClient: Packet threshold reached, triggering session rekey");
        if (!performSessionRekey()) {
            Serial.println("MitaClient: Session rekey failed, continuing with old key");
        }
    }

    static uint16_t sequence_counter = 0;
    sequence_counter++;

    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4) | FLAG_ENCRYPTED;
    packet.msg_type = MSG_DATA;
    packet.source_addr = assigned_address;
    packet.dest_addr = dest_addr;
    packet.checksum = 0;
    packet.sequence_number = sequence_counter;
    packet.ttl = DEFAULT_TTL;
    
    // Set priority and QoS flags
    packet.priority_flags = PRIORITY_NORMAL;
    if (qos == QoSLevel::NO_QOS)
    {
        packet.priority_flags |= FLAG_QOS_NO_ACK;  // Tell router: don't send ACK
    }
    else
    {
        packet.priority_flags |= FLAG_QOS_RELIABLE;  // Tell router: send ACK
    }
    
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)millis();

    // Build AAD
    uint8_t aad[6];
    aad[0] = (assigned_address >> 8) & 0xFF;
    aad[1] = assigned_address & 0xFF;
    aad[2] = (dest_addr >> 8) & 0xFF;
    aad[3] = dest_addr & 0xFF;
    aad[4] = (sequence_counter >> 8) & 0xFF;
    aad[5] = sequence_counter & 0xFF;
    
    size_t encrypted_len;
    if (!crypto_service.encryptGCM((uint8_t *)message.c_str(), message.length(),
                                   aad, sizeof(aad),
                                   packet.payload, encrypted_len))
    {
        Serial.println("MitaClient: Failed to encrypt message with GCM");
        return false;
    }

    packet.payload_length = encrypted_len;

    // Send with retry if QoS level requires ACK
    if (qos == QoSLevel::WITH_ACK)
    {
        for (uint8_t attempt = 0; attempt <= MAX_RETRIES; attempt++)
        {
            if (attempt > 0)
            {
                Serial.printf("MitaClient: Retry %d/%d for sequence %d\n", 
                            attempt, MAX_RETRIES, sequence_counter);
                
                // Before retrying, check one more time if ACK arrived
                // This handles cases where ACK arrived during the delay
                BasicProtocolPacket check_packet;
                if (transport->receivePacket(check_packet, 10))
                {
                    if (check_packet.msg_type == MSG_ACK && check_packet.payload_length >= 2)
                    {
                        uint16_t acked_seq = (check_packet.payload[0] << 8) | check_packet.payload[1];
                        if (acked_seq == sequence_counter)
                        {
                            Serial.printf("MitaClient: ACK received before retry for sequence %d\n", sequence_counter);
                            return true;
                        }
                    }
                    else if (check_packet.msg_type == MSG_ERROR && check_packet.payload_length >= 3)
                    {
                        uint8_t error_code = check_packet.payload[0];
                        uint16_t failed_seq = (check_packet.payload[1] << 8) | check_packet.payload[2];
                        if (failed_seq == sequence_counter)
                        {
                            Serial.printf("MitaClient: ERROR received - packet rejected by router (seq=%d)\n", sequence_counter);
                            return false;
                        }
                    }
                }
            }

            Serial.printf("MitaClient: Sending DATA with QoS (seq=%d, attempt=%d, %d bytes)\n", 
                         sequence_counter, attempt + 1, encrypted_len);

            if (!transport->sendPacket(packet))
            {
                Serial.println("MitaClient: Failed to send packet");
                continue;
            }

            // Wait for ACK
            if (waitForAck(sequence_counter))
            {
                Serial.printf("MitaClient: Message delivered successfully (seq=%d)\n", sequence_counter);
                return true;
            }

            // If this was the last attempt, fail
            if (attempt == MAX_RETRIES)
            {
                Serial.printf("MitaClient: Failed to deliver message after %d attempts (seq=%d)\n", 
                            MAX_RETRIES + 1, sequence_counter);
                return false;
            }

            // Wait a bit before retry (exponential backoff)
            delay(500 * (attempt + 1));
        }
        
        return false;
    }
    else
    {
        // NO_QOS: Fire and forget
        Serial.printf("MitaClient: Sending DATA without QoS (seq=%d, %d bytes)\n", 
                     sequence_counter, encrypted_len);
        bool sent = transport->sendPacket(packet);
        if (sent)
        {
            Serial.printf("MitaClient: Message sent (no ACK expected, seq=%d)\n", sequence_counter);
        }
        return sent;
    }
}

bool MitaClient::performSessionRekey() {
    Serial.println("MitaClient: Starting session key rotation");
    
    // Generate new client nonce (nonce3)
    uint8_t new_client_nonce[16];
    crypto_service.generateNonce(new_client_nonce);
    
    // Build SESSION_REKEY_REQ packet
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);  // Not encrypted
    packet.msg_type = MSG_SESSION_REKEY_REQ;
    packet.source_addr = assigned_address;
    packet.dest_addr = 0;  // To router
    packet.checksum = 0;  // Will be computed by transport
    packet.sequence_number = 0;  // Control packet, no sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH;
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)millis();
    
    // Payload: [packets_sent(4 bytes)] + [new_client_nonce(16 bytes)]
    uint8_t payload[20];
    payload[0] = (packets_sent >> 24) & 0xFF;
    payload[1] = (packets_sent >> 16) & 0xFF;
    payload[2] = (packets_sent >> 8) & 0xFF;
    payload[3] = packets_sent & 0xFF;
    memcpy(payload + 4, new_client_nonce, 16);
    
    memcpy(packet.payload, payload, 20);
    packet.payload_length = 20;
    
    // Send rekey request
    Serial.printf("MitaClient: Sending SESSION_REKEY_REQ (packets_sent=%u)\n", packets_sent);
    if (!transport->sendPacket(packet)) {
        Serial.println("MitaClient: Failed to send SESSION_REKEY_REQ");
        return false;
    }
    
    // Wait for SESSION_REKEY_ACK with router's new nonce (nonce4)
    unsigned long start_time = millis();
    while (millis() - start_time < 5000) {  // 5 second timeout
        BasicProtocolPacket response;
        if (transport->receivePacket(response, 100)) {
            if (response.msg_type == MSG_SESSION_REKEY_ACK && 
                response.payload_length == 16) {
                
                Serial.println("MitaClient: Received SESSION_REKEY_ACK");
                
                // Extract router's new nonce (nonce4)
                uint8_t new_router_nonce[16];
                memcpy(new_router_nonce, response.payload, 16);
                
                // Derive new session key from old key + both nonces
                // This provides forward secrecy - old packets can't be decrypted with new key
                if (crypto_service.rekeySession(new_client_nonce, new_router_nonce)) {
                    // Reset packet counter
                    packets_sent = 0;
                    
                    Serial.println("MitaClient: Session key rotated successfully");
                    Serial.println("MitaClient: ========================================");
                    Serial.println("MitaClient: Forward secrecy established - old packets");
                    Serial.println("MitaClient: cannot be decrypted with new session key");
                    Serial.println("MitaClient: ========================================");
                    return true;
                } else {
                    Serial.println("MitaClient: Failed to derive new session key");
                    return false;
                }
            }
        }
        delay(10);
    }
    
    Serial.println("MitaClient: SESSION_REKEY_ACK timeout");
    return false;
}