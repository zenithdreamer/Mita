#include "../include/core/mita_client.h"
#include "../include/transport/wifi_transport.h"
#include "../include/transport/ble_transport.h"
#include "../include/transport/protocol_selector.h"
#include <driver/gpio.h>
#include <esp_random.h>
#include <esp_system.h>

static const char *TAG = "MITA_CLIENT";

#ifndef LED_BUILTIN
#define LED_BUILTIN GPIO_NUM_2
#endif

MitaClient::MitaClient(const NetworkConfig &config)
    : transport(nullptr), network_config(config),
      assigned_address(UNASSIGNED_ADDRESS), handshake_completed(false),
      packets_sent(0),  // Initialize packet counter for session rekey
      last_heartbeat(0), last_ping_sent(0),
      last_reconnect_attempt(0),
      auto_reconnect_enabled(true),   // Auto-reconnect enabled by default
      reconnect_interval_ms(5000),    // Default 5 second reconnect interval
      saved_protocol_selector(nullptr),
      challenge_baseline_timestamp(0), challenge_baseline_millis(0),
      qos_level(QoSLevel::WITH_ACK)   // Default to QoS with ACK
{
    // Initialize nonce arrays to zero
    memset(nonce1, 0, NONCE_SIZE);
    memset(nonce2, 0, NONCE_SIZE);
}

// Get timestamp adjusted to router's time base
// Returns local ((unsigned long)(esp_timer_get_time() / 1000ULL)) if no baseline established (pre-handshake)
uint32_t MitaClient::getAdjustedTimestamp() const
{
    if (challenge_baseline_timestamp == 0)
    {
        // No baseline yet, use local time
        return (uint32_t)((unsigned long)(esp_timer_get_time() / 1000ULL));
    }

    // Calculate elapsed time since baseline was established
    unsigned long elapsed = ((unsigned long)(esp_timer_get_time() / 1000ULL)) - challenge_baseline_millis;

    // Add elapsed time to router's baseline to get synchronized timestamp
    // Note: This truncates to 32-bit, which is fine for the protocol
    uint64_t adjusted = challenge_baseline_timestamp + elapsed;
    return (uint32_t)adjusted;
}

MitaClient::~MitaClient()
{
    disconnect();
}

bool MitaClient::initialize()
{
    ESP_LOGI(TAG, "MitaClient: Initializing...");

    // Initialize LED pin
    gpio_set_direction(LED_BUILTIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_BUILTIN, 0);

    ESP_LOGI(TAG, "MitaClient: Device ID: %s", network_config.device_id.c_str());
    ESP_LOGI(TAG, "MitaClient: Router ID: %s", network_config.router_id.c_str());

    // Always derive device-specific PSK from master secret (forced for security)
    ESP_LOGI(TAG, "MitaClient: Deriving device-specific PSK from master secret...");
    uint8_t device_psk[HMAC_SIZE];
    
    if (!CryptoService::deriveDevicePSK(network_config.shared_secret, 
                                       network_config.device_id, 
                                       device_psk))
    {
        ESP_LOGI(TAG, "%s", "MitaClient: ERROR - Failed to derive device PSK!");
        return false;
    }
    
    // Replace shared_secret with derived device PSK (as binary string)
    network_config.shared_secret = std::string((char*)device_psk, HMAC_SIZE);
    
#ifdef DEBUG_CRYPTO
    ESP_LOGI(TAG, "%s", "MitaClient: Device PSK derived and configured");
    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
    ESP_LOGI(TAG, "%s", "MitaClient: Device PSK (hex): ");
    for (int i = 0; i < 16; i++)  // Show first 16 bytes
    {
        if (device_psk[i] < 0x10) ESP_LOGI(TAG, "%s", "0");
        ESP_LOGI(TAG, "%s", device_psk[i], HEX);
    }
    ESP_LOGI(TAG, "%s", "...");
    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
#else
    ESP_LOGI(TAG, "%s", "MitaClient: Device PSK derived and configured");
#endif

    return true;
}

bool MitaClient::connectToNetwork(ITransport *transport_impl)
{
    if (!transport_impl)
    {
        ESP_LOGI(TAG, "%s", "MitaClient: No transport provided");
        return false;
    }

    transport = transport_impl;
    ESP_LOGI(TAG, "MitaClient: Attempting to connect via %s\n",
                  transport->getType() == TRANSPORT_WIFI ? "WiFi" : "BLE");

    if (!transport->connect())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Transport connection failed");
        return false;
    }

    if (!performHandshake())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Handshake failed");
        transport->disconnect();
        return false;
    }

    ESP_LOGI(TAG, "%s", "MitaClient: Successfully connected to network");
    ESP_LOGI(TAG, "MitaClient: Assigned address: 0x%04X\n", assigned_address);
    ESP_LOGI(TAG, "MitaClient: Transport: %s\n", transport->getConnectionInfo().c_str());

    return true;
}

bool MitaClient::connectToNetworkSmart(ProtocolSelector* selector, const std::string& shared_secret)
{
    if (!selector)
    {
        ESP_LOGI(TAG, "%s", "MitaClient: No protocol selector provided");
        return false;
    }

    // Save for auto-reconnect
    saved_protocol_selector = selector;
    saved_shared_secret = shared_secret;

    ESP_LOGI(TAG, "%s", "MitaClient: Starting smart protocol selection...");

    // Get priority list of protocols to try
    TransportType priority_list[2];
    size_t protocol_count = 0;
    selector->getProtocolPriority(priority_list, protocol_count);

    // Try each protocol in priority order
    for (size_t i = 0; i < protocol_count; i++)
    {
        TransportType protocol = priority_list[i];
        const char* protocol_name = (protocol == TRANSPORT_WIFI) ? "WiFi" : "BLE";

        ESP_LOGI(TAG, "\nMitaClient: Attempting connection via %s (priority %d/%d)\n",
                     protocol_name, i + 1, protocol_count);

        // Create appropriate transport
        ITransport* transport_impl = nullptr;
        unsigned long connect_start = ((unsigned long)(esp_timer_get_time() / 1000ULL));

        if (protocol == TRANSPORT_WIFI)
        {
            transport_impl = new WiFiTransport(shared_secret);
        }
        else if (protocol == TRANSPORT_BLE)
        {
            // BLE L2CAP CoC transport enabled
            transport_impl = new BLETransport(network_config.device_id, network_config.router_id);
        }

        if (!transport_impl)
        {
            ESP_LOGI(TAG, "MitaClient: Failed to create %s transport\n", protocol_name);
            selector->updateStats(protocol, false, 0, -100);
            continue;
        }

        // Attempt connection
        bool connect_success = connectToNetwork(transport_impl);
        int connect_time_ms = ((unsigned long)(esp_timer_get_time() / 1000ULL)) - connect_start;

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

            ESP_LOGI(TAG, "MitaClient: Successfully connected via %s in %d ms\n",
                          protocol_name, connect_time_ms);

            // Report success to selector for learning
            selector->updateStats(protocol, true, connect_time_ms, signal_strength);

            return true;
        }
        else
        {
            ESP_LOGI(TAG, "MitaClient: Failed to connect via %s (took %d ms)\n",
                          protocol_name, connect_time_ms);

            // Report failure to selector for learning
            selector->updateStats(protocol, false, connect_time_ms, -100);

            // Clean up failed transport
            delete transport_impl;
            transport = nullptr;
        }
    }

    ESP_LOGI(TAG, "%s", "\nMitaClient: All connection methods failed");
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
        ESP_LOGI(TAG, "MitaClient: Sending graceful disconnect (reason: 0x%02X)\n",
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

    ESP_LOGI(TAG, "%s", "MitaClient: Disconnected");
}

void MitaClient::update()
{
    unsigned long current_time = ((unsigned long)(esp_timer_get_time() / 1000ULL));

    // Auto-reconnect if enabled and disconnected
    if (!isConnected())
    {
        if (auto_reconnect_enabled && saved_protocol_selector)
        {
            if (current_time - last_reconnect_attempt >= reconnect_interval_ms)
            {
                ESP_LOGI(TAG, "%s", "MitaClient: Auto-reconnecting...");
                
                if (connectToNetworkSmart(saved_protocol_selector, saved_shared_secret))
                {
                    ESP_LOGI(TAG, "MitaClient: Auto-reconnected! Address: 0x%04X", assigned_address);
                }
                
                last_reconnect_attempt = current_time;
            }
        }
        return;
    }

    // Handle incoming messages
    handleIncomingMessages();

    // Send periodic heartbeat
    if (current_time - last_heartbeat >= HEARTBEAT_INTERVAL)
    {
        sendHeartbeat();
        last_heartbeat = current_time;
    }

    // Note: Sensor data sending removed - user should call sendData() in their app
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

std::string MitaClient::getDeviceId() const
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
    packet.timestamp = getAdjustedTimestamp();
    packet.payload_length = 0;

    ESP_LOGI(TAG, "%s", "MitaClient: Sending heartbeat");
    return transport->sendPacket(packet);
}

// send data to router
bool MitaClient::sendData(const std::string& json_data)
{
    if (!isConnected())
    {
        ESP_LOGW(TAG, "%s", "MitaClient: Cannot send data - not connected");
        return false;
    }

    ESP_LOGI(TAG, "MitaClient: Sending data (%d bytes)", json_data.length());
    return sendEncryptedMessage(ROUTER_ADDRESS, json_data);
}

bool MitaClient::sendPing()
{
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_CONTROL; // Use CONTROL message for PING
    packet.source_addr = assigned_address;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;
    packet.sequence_number = 0;
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // PING is high priority
    packet.fragment_id = 0;
    packet.timestamp = getAdjustedTimestamp();

    // Payload: PING control type (0x00) + timestamp for RTT calculation
    packet.payload[0] = 0x00; // ControlType::PING
    uint32_t ping_time = ((unsigned long)(esp_timer_get_time() / 1000ULL));
    packet.payload[1] = (ping_time >> 24) & 0xFF;
    packet.payload[2] = (ping_time >> 16) & 0xFF;
    packet.payload[3] = (ping_time >> 8) & 0xFF;
    packet.payload[4] = ping_time & 0xFF;
    packet.payload_length = 5;

    last_ping_sent = ping_time;

    ESP_LOGI(TAG, "MitaClient: Sending PING (time=%lu)\n", ping_time);
    return transport->sendPacket(packet);
}

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
    ESP_LOGI(TAG, "%s", "MitaClient: Starting handshake...");

    // Reset timestamp validation baseline for each new handshake
    challenge_baseline_timestamp = 0;
    challenge_baseline_millis = 0;

    if (!sendHello())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to send HELLO");
        return false;
    }

    if (!receiveChallenge())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to receive CHALLENGE");
        return false;
    }

    if (!sendAuth())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to send AUTH");
        return false;
    }

    ESP_LOGI(TAG, "%s", "MitaClient: sendAuth() returned successfully, calling receiveAuthAck()...");

    if (!receiveAuthAck())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to receive AUTH_ACK");
        return false;
    }

    handshake_completed = true;
    ESP_LOGI(TAG, "%s", "MitaClient: Handshake completed successfully");
    return true;
}

bool MitaClient::sendHello()
{
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_HELLO;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;        // Will be computed automatically
    packet.sequence_number = 0; // Handshake packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // Handshake is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)((unsigned long)(esp_timer_get_time() / 1000ULL));

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
    ESP_LOGI(TAG, "%s", "MitaClient: Sending HELLO (nonce1: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce1[i] < 0x10)
            ESP_LOGI(TAG, "%s", "0");
        ESP_LOGI(TAG, "%s", nonce1[i], HEX);
    }
    ESP_LOGI(TAG, "%s", ")");
#else
    ESP_LOGI(TAG, "%s", "MitaClient: Sending HELLO");
#endif

    // Debug: Print packet header for checksum debugging
    ESP_LOGI(TAG, "MitaClient: HELLO packet header: ver_flags=0x%02X type=0x%02X src=0x%04X dst=0x%04X len=%d chk=0x%02X seq=%d\n",
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
        ESP_LOGI(TAG, "MitaClient: CHALLENGE payload too small: %d bytes (expected 24)\n", packet.payload_length);
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
        challenge_baseline_millis = ((unsigned long)(esp_timer_get_time() / 1000ULL));
        ESP_LOGI(TAG, "MitaClient: Established timestamp baseline: %llu ms\n", timestamp_ms);
    }
    else
    {
        // Calculate expected timestamp based on elapsed time since first challenge
        unsigned long elapsed_millis = ((unsigned long)(esp_timer_get_time() / 1000ULL)) - challenge_baseline_millis;
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
            ESP_LOGI(TAG, "MitaClient: CHALLENGE timestamp drift too large: %llu ms (expected ~%llu, got %llu)\n",
                          timestamp_diff, expected_timestamp, timestamp_ms);
            ESP_LOGI(TAG, "%s", "MitaClient: Possible replay attack detected");
            return false;
        }

        ESP_LOGI(TAG, "MitaClient: Timestamp validation passed (drift: %llu ms)\n", timestamp_diff);
    }

#ifdef DEBUG_CRYPTO
    ESP_LOGI(TAG, "%s", "MitaClient: Received CHALLENGE (nonce2: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce2[i] < 0x10)
            ESP_LOGI(TAG, "%s", "0");
        ESP_LOGI(TAG, "%s", nonce2[i], HEX);
    }
    ESP_LOGI(TAG, ", timestamp: %llu)\n", timestamp_ms);
#else
    ESP_LOGI(TAG, "MitaClient: Received CHALLENGE (timestamp: %llu)\n", timestamp_ms);
#endif

    return true;
}

bool MitaClient::sendAuth()
{
    ESP_LOGI(TAG, "%s", "MitaClient: sendAuth() - Creating packet");
    
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_AUTH;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.checksum = 0;        // Will be computed automatically
    packet.sequence_number = 0; // Handshake packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // Handshake is high priority
    packet.fragment_id = 0;
    packet.timestamp = (uint32_t)((unsigned long)(esp_timer_get_time() / 1000ULL));

    ESP_LOGI(TAG, "MitaClient: sendAuth() - Constructing HMAC data (device_id_len=%d, router_id_len=%d)\n",
             network_config.device_id.length(), network_config.router_id.length());
    
    // Construct HMAC data: nonce2 (16 bytes) || device_id || router_id
    size_t data_len = NONCE_SIZE + network_config.device_id.length() + network_config.router_id.length();
    uint8_t *auth_data = new uint8_t[data_len];

    // Copy full 16-byte nonce2
    memcpy(auth_data, nonce2, NONCE_SIZE);

    memcpy(auth_data + NONCE_SIZE, network_config.device_id.c_str(), network_config.device_id.length());
    memcpy(auth_data + NONCE_SIZE + network_config.device_id.length(),
           network_config.router_id.c_str(), network_config.router_id.length());

    ESP_LOGI(TAG, "MitaClient: sendAuth() - Computing HMAC (psk_len=%d, data_len=%d)\n",
             network_config.shared_secret.length(), data_len);
    
    uint8_t auth_hmac[HMAC_SIZE];
    bool hmac_result = crypto_service.computeHMAC(
        (uint8_t *)network_config.shared_secret.data(), network_config.shared_secret.length(),
        auth_data, data_len, auth_hmac);

    delete[] auth_data;

    if (!hmac_result)
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to compute AUTH HMAC");
        return false;
    }

    ESP_LOGI(TAG, "%s", "MitaClient: sendAuth() - HMAC computed successfully");

    // Payload: HMAC (16 bytes) || nonce1 (16 bytes) = 32 bytes total
    memcpy(packet.payload, auth_hmac, 16);
    memcpy(packet.payload + 16, nonce1, NONCE_SIZE);

    packet.payload_length = 32;

    ESP_LOGI(TAG, "MitaClient: Sending AUTH (32 bytes), packet addr=%p, payload_len=%d\n", 
             &packet, packet.payload_length);
    
    return transport->sendPacket(packet);
}

bool MitaClient::receiveAuthAck()
{
    ESP_LOGI(TAG, "%s", "MitaClient: Waiting for AUTH_ACK...");
    
    BasicProtocolPacket packet;
    if (!transport->receivePacket(packet, 5000) || packet.msg_type != MSG_AUTH_ACK)
    {
        ESP_LOGI(TAG, "%s", "MitaClient: No AUTH_ACK received or wrong message type");
        return false;
    }

    ESP_LOGI(TAG, "MitaClient: Received AUTH_ACK, payload_length=%d\n", packet.payload_length);

    // Expect 18 bytes: HMAC (16) + address (2)
    if (packet.payload_length < 18)
    {
        ESP_LOGI(TAG, "MitaClient: AUTH_ACK payload too small: %d bytes (expected 18)\n", packet.payload_length);
        return false;
    }

    // Verify HMAC computed over full 16-byte nonce1
    uint8_t expected_hmac[HMAC_SIZE];
    if (!crypto_service.computeHMAC(
            (uint8_t *)network_config.shared_secret.data(), network_config.shared_secret.length(),
            nonce1, NONCE_SIZE, expected_hmac))
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to compute expected HMAC");
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
        ESP_LOGI(TAG, "%s", "MitaClient: Router authentication failed - HMAC mismatch");
        return false;
    }

    assigned_address = (packet.payload[16] << 8) | packet.payload[17];

    // Derive session key from both 16-byte nonces
    if (!crypto_service.deriveSessionKey(network_config.shared_secret, nonce1, nonce2))
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to derive session key");
        return false;
    }

#ifdef DEBUG_CRYPTO
    // Log session key for debugging/decryption purposes (ONLY in debug builds)
    uint8_t session_key_bytes[SESSION_KEY_SIZE];
    crypto_service.getSessionKey(session_key_bytes);

    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
    ESP_LOGI(TAG, "%s", "MitaClient: SESSION KEY");
    ESP_LOGI(TAG, "%s", "MitaClient: ");
    for (int i = 0; i < SESSION_KEY_SIZE; i++)
    {
        if (session_key_bytes[i] < 0x10)
            ESP_LOGI(TAG, "%s", "0");
        ESP_LOGI(TAG, "%s", session_key_bytes[i], HEX);
    }
    ESP_LOGI(TAG, "%s", );
    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
#endif

    ESP_LOGI(TAG, "MitaClient: AUTH_ACK received, assigned address: 0x%04X\n", assigned_address);
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

                if (control_type == 0x01) // ControlType::PONG
                {
                    // Extract original timestamp
                    uint32_t sent_time = ((uint32_t)packet.payload[1] << 24) |
                                         ((uint32_t)packet.payload[2] << 16) |
                                         ((uint32_t)packet.payload[3] << 8) |
                                         ((uint32_t)packet.payload[4]);

                    uint32_t now = ((unsigned long)(esp_timer_get_time() / 1000ULL));
                    uint32_t rtt = now - sent_time;

                    ESP_LOGI(TAG, "MitaClient: PONG received! RTT = %lu ms\n", rtt);
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

                const char *error_str = "UNKNOWN";
                switch (error_code)
                {
                case 0x01:
                    error_str = "INVALID_SEQUENCE";
                    break;
                case 0x02:
                    error_str = "STALE_TIMESTAMP";
                    break;
                case 0x03:
                    error_str = "DECRYPTION_FAILED";
                    break;
                case 0x04:
                    error_str = "INVALID_DESTINATION";
                    break;
                case 0x05:
                    error_str = "TTL_EXPIRED";
                    break;
                case 0x06:
                    error_str = "RATE_LIMIT_EXCEEDED";
                    break;
                case 0x07:
                    error_str = "SESSION_EXPIRED";
                    break;
                case 0x08:
                    error_str = "MALFORMED_PACKET";
                    break;
                case 0x09:
                    error_str = "UNSUPPORTED_VERSION";
                    break;
                case 0x0A:
                    error_str = "AUTHENTICATION_FAILED";
                    break;
                case 0x0B:
                    error_str = "NOT_AUTHENTICATED";
                    break;
                }

                ESP_LOGI(TAG, "MitaClient: ERROR from router: %s (code=0x%02X, seq=%d)\n",
                              error_str, error_code, failed_seq);

                // React to specific errors
                if (error_code == 0x0B) // NOT_AUTHENTICATED
                {
                    ESP_LOGI(TAG, "%s", "MitaClient: Router requires re-authentication - triggering reconnect");
                    // Clear session state to force full handshake on next connection attempt
                    crypto_service.clearSessionKey();
                    handshake_completed = false;
                    // Disconnect transport to trigger reconnection
                    if (transport) {
                        transport->disconnect();
                    }
                }
                // TODO: React to other errors
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
                std::string message = std::string((char *)decrypted, decrypted_length);
                ESP_LOGI(TAG, "MitaClient: Received GCM authenticated message: %s\n", message.c_str());

                std::string response;
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
                            vTaskDelay(pdMS_TO_TICKS(1000));
                            esp_restart();
                        }
                    }
                }
            }
            else
            {
                ESP_LOGI(TAG, "%s", "MitaClient: Failed to decrypt message - MAC verification may have failed");
            }
        }
    }
}

bool MitaClient::sendEncryptedMessage(uint16_t dest_addr, const std::string &message)
{
    // Use the configured QoS level
    return sendEncryptedMessageWithQoS(dest_addr, message, qos_level);
}

void MitaClient::setQoSLevel(QoSLevel level)
{
    qos_level = level;
    ESP_LOGI(TAG, "MitaClient: QoS level set to %s\n",
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
    packet.sequence_number = 0; // Disconnect packets don't need sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH; // Disconnect is high priority
    packet.fragment_id = 0;
    packet.timestamp = getAdjustedTimestamp();

    // Payload: disconnect reason (1 byte)
    packet.payload[0] = static_cast<uint8_t>(reason);
    packet.payload_length = 1;

    ESP_LOGI(TAG, "MitaClient: Sending DISCONNECT (reason=0x%02X)\n",
                  static_cast<uint8_t>(reason));
    return transport->sendPacket(packet);
}

bool MitaClient::receiveDisconnectAck()
{
    BasicProtocolPacket packet;

    // Wait up to 1 second for DISCONNECT_ACK (best effort)
    if (!transport->receivePacket(packet, 1000))
    {
        ESP_LOGI(TAG, "%s", "MitaClient: No DISCONNECT_ACK received (timeout)");
        return false;
    }

    if (packet.msg_type != MSG_DISCONNECT_ACK)
    {
        ESP_LOGI(TAG, "MitaClient: Expected DISCONNECT_ACK, got msg_type=0x%02X\n",
                      packet.msg_type);
        return false;
    }

    ESP_LOGI(TAG, "%s", "MitaClient: DISCONNECT_ACK received");
    return true;
}

bool MitaClient::waitForAck(uint16_t expected_sequence)
{
    unsigned long start_time = ((unsigned long)(esp_timer_get_time() / 1000ULL));
    unsigned int check_count = 0;

    while (((unsigned long)(esp_timer_get_time() / 1000ULL)) - start_time < ACK_TIMEOUT_MS)
    {
        BasicProtocolPacket packet;

        // Check for incoming packets with longer timeout (200ms) to handle WiFi/BLE latency
        if (transport->receivePacket(packet, 200))
        {
            check_count++;
            ESP_LOGI(TAG, "MitaClient: Received packet type=0x%02X while waiting for ACK (check #%d)\n",
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
                        unsigned long rtt = ((unsigned long)(esp_timer_get_time() / 1000ULL)) - start_time;
                        ESP_LOGI(TAG, "MitaClient: ACK received for sequence %d (RTT: %lu ms, after %d checks)\n", 
                                      expected_sequence, rtt, check_count);
                        return true;
                    }
                    else
                    {
                        ESP_LOGI(TAG, "MitaClient: ACK received for wrong sequence (expected %d, got %d)\n",
                                      expected_sequence, acked_sequence);
                    }
                }
                else
                {
                    ESP_LOGI(TAG, "MitaClient: ACK packet with insufficient payload (got %d bytes, need 2)\n",
                                  packet.payload_length);
                }
            }
            else if (packet.msg_type == MSG_ERROR)
            {
                // Handle ERROR messages from router
                if (packet.payload_length >= 3)
                {
                    uint8_t error_code = packet.payload[0];
                    uint16_t failed_seq = (packet.payload[1] << 8) | packet.payload[2];

                    const char *error_str = "UNKNOWN";
                    switch (error_code)
                    {
                    case 0x01:
                        error_str = "INVALID_SEQUENCE";
                        break;
                    case 0x02:
                        error_str = "STALE_TIMESTAMP";
                        break;
                    case 0x03:
                        error_str = "DECRYPTION_FAILED";
                        break;
                    case 0x04:
                        error_str = "INVALID_DESTINATION";
                        break;
                    case 0x05:
                        error_str = "TTL_EXPIRED";
                        break;
                    case 0x06:
                        error_str = "RATE_LIMIT_EXCEEDED";
                        break;
                    case 0x07:
                        error_str = "SESSION_EXPIRED";
                        break;
                    case 0x08:
                        error_str = "MALFORMED_PACKET";
                        break;
                    case 0x09:
                        error_str = "UNSUPPORTED_VERSION";
                        break;
                    case 0x0A:
                        error_str = "AUTHENTICATION_FAILED";
                        break;
                    case 0x0B:
                        error_str = "NOT_AUTHENTICATED";
                        break;
                    }

                    ESP_LOGI(TAG, "MitaClient: ERROR from router: %s (code=0x%02X, seq=%d)\n",
                                  error_str, error_code, failed_seq);

                    // Handle specific error codes
                    if (error_code == 0x02) // STALE_TIMESTAMP
                    {
                        ESP_LOGI(TAG, "%s", "MitaClient: Router reports stale timestamp - session expired, need to re-authenticate");
                        // Mark as disconnected to force re-authentication
                        handshake_completed = false;
                        crypto_service.clearSessionKey();
                        return false;
                    }
                    else if (error_code == 0x07) // SESSION_EXPIRED
                    {
                        ESP_LOGI(TAG, "%s", "MitaClient: Router reports session expired - need to re-authenticate");
                        handshake_completed = false;
                        crypto_service.clearSessionKey();
                        return false;
                    }
                    else if (error_code == 0x0B) // NOT_AUTHENTICATED
                    {
                        ESP_LOGI(TAG, "%s", "MitaClient: Router reports not authenticated - triggering reconnect");
                        handshake_completed = false;
                        crypto_service.clearSessionKey();
                        // Disconnect transport to trigger reconnection
                        if (transport) {
                            transport->disconnect();
                        }
                        return false;
                    }

                    // If this error is for our current sequence, treat it as a failed ACK
                    if (failed_seq == expected_sequence)
                    {
                        ESP_LOGI(TAG, "MitaClient: Packet seq=%d rejected by router, stopping retries\n", expected_sequence);
                        return false; // Stop retrying - packet was rejected
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
                    std::string message = std::string((char *)decrypted, decrypted_length);
                    ESP_LOGI(TAG, "MitaClient: Received message while waiting for ACK: %s\n", message.c_str());

                    std::string response;
                    if (message_dispatcher.processMessage(message, response))
                    {
                        // Send response without QoS to avoid nested waiting
                        sendEncryptedMessageWithQoS(packet.source_addr, response, QoSLevel::NO_QOS);
                    }
                }
            }
        }
    }

    unsigned long total_wait = ((unsigned long)(esp_timer_get_time() / 1000ULL)) - start_time;
    ESP_LOGI(TAG, "MitaClient: ACK TIMEOUT for sequence %d (waited %lu ms, %u receive checks, no ACK received)\n", 
                  expected_sequence, total_wait, check_count);
    ESP_LOGI(TAG, "MitaClient: Router may not be sending ACK or transport layer issue detected\n");
    return false;
}

bool MitaClient::sendEncryptedMessageWithQoS(uint16_t dest_addr, const std::string &message, QoSLevel qos)
{
    if (!crypto_service.hasValidSessionKey())
    {
        ESP_LOGI(TAG, "%s", "MitaClient: No valid session key for encryption");
        return false;
    }

    // Increment packet counter for session key rotation
    packets_sent++;

    // Check if we need to rotate session key
    if (packets_sent >= REKEY_PACKET_THRESHOLD)
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Packet threshold reached, triggering session rekey");
        if (!performSessionRekey())
        {
            ESP_LOGI(TAG, "%s", "MitaClient: Session rekey failed, continuing with old key");
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
        packet.priority_flags |= FLAG_QOS_NO_ACK; // Tell router: don't send ACK
    }
    else
    {
        packet.priority_flags |= FLAG_QOS_RELIABLE; // Tell router: send ACK
    }

    packet.fragment_id = 0;
    packet.timestamp = getAdjustedTimestamp();

    // Build AAD
    uint8_t aad[6];
    aad[0] = (assigned_address >> 8) & 0xFF;
    aad[1] = assigned_address & 0xFF;
    aad[2] = (dest_addr >> 8) & 0xFF;
    aad[3] = dest_addr & 0xFF;
    aad[4] = (sequence_counter >> 8) & 0xFF;
    aad[5] = sequence_counter & 0xFF;

    ESP_LOGI(TAG, "MitaClient: Encrypting with AAD: src=0x%04X dst=0x%04X seq=%d (AAD: %02X %02X %02X %02X %02X %02X)",
             assigned_address, dest_addr, sequence_counter,
             aad[0], aad[1], aad[2], aad[3], aad[4], aad[5]);

    size_t encrypted_len;
    if (!crypto_service.encryptGCM((uint8_t *)message.c_str(), message.length(),
                                   aad, sizeof(aad),
                                   packet.payload, encrypted_len))
    {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to encrypt message with GCM");
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
                ESP_LOGI(TAG, "MitaClient: Retry %d/%d for sequence %d\n",
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
                            ESP_LOGI(TAG, "MitaClient: ACK received before retry for sequence %d\n", sequence_counter);
                            return true;
                        }
                    }
                    else if (check_packet.msg_type == MSG_ERROR && check_packet.payload_length >= 3)
                    {
                        uint16_t failed_seq = (check_packet.payload[1] << 8) | check_packet.payload[2];
                        if (failed_seq == sequence_counter)
                        {
                            ESP_LOGI(TAG, "MitaClient: ERROR received - packet rejected by router (seq=%d, error=0x%02X)\n", 
                                     sequence_counter, check_packet.payload[0]);
                            return false;
                        }
                    }
                }
            }

            ESP_LOGI(TAG, "MitaClient: Sending DATA with QoS (seq=%d, attempt=%d, %d bytes)\n",
                          sequence_counter, attempt + 1, encrypted_len);

            if (!transport->sendPacket(packet))
            {
                ESP_LOGI(TAG, "%s", "MitaClient: Failed to send packet");
                continue;
            }

            // Wait for ACK
            if (waitForAck(sequence_counter))
            {
                ESP_LOGI(TAG, "MitaClient: Message delivered successfully (seq=%d)\n", sequence_counter);
                return true;
            }

            // If this was the last attempt, fail
            if (attempt == MAX_RETRIES)
            {
                ESP_LOGI(TAG, "MitaClient: Failed to deliver message after %d attempts (seq=%d)\n",
                              MAX_RETRIES + 1, sequence_counter);
                return false;
            }

            // Wait a bit before retry (exponential backoff)
            vTaskDelay(pdMS_TO_TICKS(500 * (attempt + 1)));
        }

        return false;
    }
    else
    {
        // NO_QOS: Fire and forget
        ESP_LOGI(TAG, "MitaClient: Sending DATA without QoS (seq=%d, %d bytes)\n",
                      sequence_counter, encrypted_len);
        bool sent = transport->sendPacket(packet);
        if (sent)
        {
            ESP_LOGI(TAG, "MitaClient: Message sent (no ACK expected, seq=%d)\n", sequence_counter);
        }
        return sent;
    }
}

bool MitaClient::performSessionRekey()
{
    ESP_LOGI(TAG, "%s", "MitaClient: Starting session key rotation");

    // Generate new client nonce (nonce3)
    uint8_t new_client_nonce[16];
    crypto_service.generateNonce(new_client_nonce);

    // Build SESSION_REKEY_REQ packet
    BasicProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4); // Not encrypted
    packet.msg_type = MSG_SESSION_REKEY_REQ;
    packet.source_addr = assigned_address;
    packet.dest_addr = 0;       // To router
    packet.checksum = 0;        // Will be computed by transport
    packet.sequence_number = 0; // Control packet, no sequence
    packet.ttl = DEFAULT_TTL;
    packet.priority_flags = PRIORITY_HIGH;
    packet.fragment_id = 0;
    packet.timestamp = getAdjustedTimestamp();

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
    ESP_LOGI(TAG, "MitaClient: Sending SESSION_REKEY_REQ (packets_sent=%u)\n", packets_sent);
    if (!transport->sendPacket(packet)) {
        ESP_LOGI(TAG, "%s", "MitaClient: Failed to send SESSION_REKEY_REQ");
        return false;
    }
    
    // Wait for SESSION_REKEY_ACK with router's new nonce (nonce4)
    unsigned long start_time = ((unsigned long)(esp_timer_get_time() / 1000ULL));
    while (((unsigned long)(esp_timer_get_time() / 1000ULL)) - start_time < 5000) {  // 5 second timeout
        BasicProtocolPacket response;
        if (transport->receivePacket(response, 100)) {
            if (response.msg_type == MSG_SESSION_REKEY_ACK && 
                response.payload_length == 16) {
                
                ESP_LOGI(TAG, "%s", "MitaClient: Received SESSION_REKEY_ACK");
                
                // Extract router's new nonce (nonce4)
                uint8_t new_router_nonce[16];
                memcpy(new_router_nonce, response.payload, 16);
                
                // Derive new session key from old key + both nonces
                // This provides forward secrecy - old packets can't be decrypted with new key
                if (crypto_service.rekeySession(new_client_nonce, new_router_nonce)) {
                    // Reset packet counter
                    packets_sent = 0;
                    
                    ESP_LOGI(TAG, "%s", "MitaClient: Session key rotated successfully");
                    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
                    ESP_LOGI(TAG, "%s", "MitaClient: Forward secrecy established - old packets");
                    ESP_LOGI(TAG, "%s", "MitaClient: cannot be decrypted with new session key");
                    ESP_LOGI(TAG, "%s", "MitaClient: ========================================");
                    return true;
                } else {
                    ESP_LOGI(TAG, "%s", "MitaClient: Failed to derive new session key");
                    return false;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    ESP_LOGI(TAG, "%s", "MitaClient: SESSION_REKEY_ACK timeout");
    return false;
}

void MitaClient::setAutoReconnect(bool enable, unsigned long interval_ms)
{
    auto_reconnect_enabled = enable;
    reconnect_interval_ms = interval_ms;
    ESP_LOGI(TAG, "MitaClient: Auto-reconnect %s (interval: %lu ms)", 
             enable ? "enabled" : "disabled", interval_ms);
}

bool MitaClient::getAutoReconnectEnabled() const
{
    return auto_reconnect_enabled;
}