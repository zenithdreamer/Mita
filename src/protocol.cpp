/**
 * Multi-Protocol IoT Network - Protocol Implementation for ESP32
 * This code need big refactor and cleanup
 */

#include "../include/protocol.h"

// BLE Server Callbacks Class
class IoTBLEServerCallbacks : public BLEServerCallbacks
{
private:
    IoTProtocol *protocol;

public:
    IoTBLEServerCallbacks(IoTProtocol *p) : protocol(p) {}

    void onConnect(BLEServer *server) override
    {
        protocol->onBLEConnect();
    }

    void onDisconnect(BLEServer *server) override
    {
        protocol->onBLEDisconnect();
    }
};

// BLE Characteristic Callbacks Class
class IoTBLECharacteristicCallbacks : public BLECharacteristicCallbacks
{
private:
    IoTProtocol *protocol;

public:
    IoTBLECharacteristicCallbacks(IoTProtocol *p) : protocol(p) {}

    void onWrite(BLECharacteristic *characteristic) override
    {
        std::string value = characteristic->getValue();
        if (value.length() > 0)
        {
            protocol->onBLEWrite((const uint8_t *)value.data(), value.length());
        }
    }
};

IoTProtocol::IoTProtocol()
{
    wifi_connected = false;
    ble_connected = false;
    ble_client_connected = false;
    handshake_completed = false;
    assigned_address = UNASSIGNED_ADDRESS;
    nonce1 = 0;
    nonce2 = 0;
    iv_counter = 0;
    router_port = 8000;
    active_transport = TRANSPORT_WIFI;
    ble_server = nullptr;
    ble_characteristic = nullptr;

    // Initialize BLE packet buffering
    ble_packet_length = 0;
    ble_packet_available = false;

    // Initialize session key to zeros
    memset(session_key, 0, SESSION_KEY_SIZE);
}

bool IoTProtocol::loadConfig(const char *router_id, const char *shared_secret, const char *device_id)
{
    if (!router_id || !shared_secret || !device_id)
    {
        return false;
    }

    this->router_id = String(router_id);
    this->shared_secret = String(shared_secret);
    this->device_id = String(device_id);

    return true;
}

void IoTProtocol::setWiFiConfig(const char *ssid, const char *password, IPAddress ip, uint16_t port)
{
    wifi_ssid = String(ssid);
    wifi_password = String(password);
    router_ip = ip;
    router_port = port;
}

void IoTProtocol::setBLEConfig(const char *service_uuid, const char *char_uuid)
{
    ble_service_uuid = String(service_uuid);
    ble_char_uuid = String(char_uuid);
}

bool IoTProtocol::connectToNetwork()
{
    Serial.println("Attempting to connect to IoT network...");

    // Try WiFi first
    if (connectViaWiFi())
    {
        active_transport = TRANSPORT_WIFI;
        return true;
    }

    Serial.println("WiFi connection failed, trying BLE...");

    // If WiFi fails, try BLE
    if (connectViaBLE())
    {
        active_transport = TRANSPORT_BLE;
        return true;
    }

    Serial.println("All connection methods failed");
    return false;
}

bool IoTProtocol::connectViaWiFi()
{
    Serial.println("Attempting WiFi connection...");

    // Print ESP32 WiFi diagnostics
    Serial.println("=== ESP32 WiFi Diagnostics ===");
    Serial.printf("Chip model: %s\n", ESP.getChipModel());
    Serial.printf("Chip revision: %d\n", ESP.getChipRevision());
    Serial.printf("Flash size: %u bytes\n", ESP.getFlashChipSize());
    Serial.printf("Free heap: %u bytes\n", ESP.getFreeHeap());
    Serial.printf("WiFi MAC: %s\n", WiFi.macAddress().c_str());

    // Check WiFi capability
    Serial.println("Checking WiFi hardware...");
    if (!WiFi.mode(WIFI_STA))
    {
        Serial.println("ERROR: Failed to set WiFi to STA mode!");
        return false;
    }
    Serial.println("WiFi hardware initialized successfully");
    Serial.println("==============================");

    if (!scanForRouter())
    {
        Serial.println("Router AP not found");
        return false;
    }

    if (!connectToAP())
    {
        Serial.println("Failed to connect to AP");
        return false;
    }

    if (!establishTCPConnection())
    {
        Serial.println("Failed to establish TCP connection");
        WiFi.disconnect();
        return false;
    }

    if (!performHandshake())
    {
        Serial.println("Handshake failed");
        wifi_client.stop();
        WiFi.disconnect();
        return false;
    }

    wifi_connected = true;
    Serial.println("WiFi connection successful");
    return true;
}

bool IoTProtocol::connectViaBLE()
{
    Serial.println("Attempting BLE connection...");

    if (!setupBLEServer())
    {
        Serial.println("Failed to setup BLE server");
        return false;
    }

    if (!startBLEAdvertising())
    {
        Serial.println("Failed to start BLE advertising");
        return false;
    }

    Serial.println("BLE server started, waiting for router connection...");

    // Wait for router to connect
    unsigned long start_time = millis();
    while (!ble_client_connected && (millis() - start_time) < 30000)
    {
        delay(100);
    }

    if (!ble_client_connected)
    {
        Serial.println("Router did not connect via BLE");
        return false;
    }

    // Wait for GATT discovery and notification setup before starting handshake
    delay(3000);

    // Set active transport to BLE now that connection is established
    // This must be done BEFORE handshake so sendPacket() works
    active_transport = TRANSPORT_BLE;
    ble_connected = true;
    Serial.printf("BLE connection established, active_transport set to %d, starting handshake...\n", active_transport);

    if (!performHandshake())
    {
        Serial.println("BLE handshake failed");
        ble_connected = false;
        return false;
    }

    Serial.println("BLE connection and handshake successful");
    return true;
}

void IoTProtocol::disconnect()
{
    if (wifi_client.connected())
    {
        wifi_client.stop();
    }
    WiFi.disconnect();
    wifi_connected = false;

    if (ble_server)
    {
        ble_server->getAdvertising()->stop();
        BLEDevice::deinit(true);
    }
    ble_connected = false;
    ble_client_connected = false;

    handshake_completed = false;
    assigned_address = UNASSIGNED_ADDRESS;
    memset(session_key, 0, SESSION_KEY_SIZE);
}

bool IoTProtocol::scanForRouter()
{
    Serial.println("Scanning for router AP...");

    // Set WiFi to station mode and disconnect any existing connection
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    Serial.println("Starting WiFi scan...");
    int networks = WiFi.scanNetworks(false, true); // async=false, show_hidden=true

    if (networks == -1)
    {
        Serial.println("WiFi scan failed!");
        return false;
    }

    Serial.printf("Found %d networks:\n", networks);

    // Try multiple SSID patterns based on Router ID
    String patterns[] = {
        router_id,              // Exact Router ID
        "IoT_" + router_id,     // IoT_<RID> pattern
        router_id + "_Network", // <RID>_Network pattern
        "Mita_Network"          // Fallback for current router config
    };

    // Print all found networks for debugging
    for (int i = 0; i < networks; i++)
    {
        String foundSSID = WiFi.SSID(i);
        int32_t rssi = WiFi.RSSI(i);
        wifi_auth_mode_t authMode = WiFi.encryptionType(i);
        uint8_t *bssid = WiFi.BSSID(i);
        int32_t channel = WiFi.channel(i);

        Serial.printf("  [%d] SSID: %-20s RSSI: %3d dBm  Ch: %2d  ",
                      i, foundSSID.c_str(), rssi, channel);

        // Print BSSID
        Serial.printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X  ",
                      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

        // Print security type
        switch (authMode)
        {
        case WIFI_AUTH_OPEN:
            Serial.print("OPEN");
            break;
        case WIFI_AUTH_WEP:
            Serial.print("WEP");
            break;
        case WIFI_AUTH_WPA_PSK:
            Serial.print("WPA");
            break;
        case WIFI_AUTH_WPA2_PSK:
            Serial.print("WPA2");
            break;
        case WIFI_AUTH_WPA_WPA2_PSK:
            Serial.print("WPA/WPA2");
            break;
        case WIFI_AUTH_WPA2_ENTERPRISE:
            Serial.print("WPA2-ENT");
            break;
        case WIFI_AUTH_WPA3_PSK:
            Serial.print("WPA3");
            break;
        case WIFI_AUTH_WPA2_WPA3_PSK:
            Serial.print("WPA2/WPA3");
            break;
        default:
            Serial.printf("AUTH:%d", authMode);
            break;
        }
        Serial.println();

        // Check if this SSID matches any of our expected patterns
        for (int p = 0; p < 4; p++)
        {
            if (foundSSID == patterns[p])
            {
                Serial.printf("*** MATCH FOUND: Pattern '%s' matches '%s' ***\n",
                              patterns[p].c_str(), foundSSID.c_str());
                wifi_ssid = foundSSID; // Update the SSID to use

                // Print additional info about the matched network
                Serial.printf("    Selected network details:\n");
                Serial.printf("      RSSI: %d dBm (%s signal)\n", rssi,
                              (rssi > -50) ? "Excellent" : (rssi > -60) ? "Good"
                                                       : (rssi > -70)   ? "Fair"
                                                                        : "Weak");
                Serial.printf("      Channel: %d\n", channel);
                Serial.printf("      Security: %s\n",
                              (authMode == WIFI_AUTH_OPEN) ? "Open (no password)" : "Secured");

                return true;
            }
        }
    }

    Serial.println("*** NO MATCHING ROUTER AP FOUND ***");
    Serial.println("Expected patterns:");
    for (int i = 0; i < 4; i++)
    {
        Serial.printf("  - %s\n", patterns[i].c_str());
    }

    // Clean up scan results
    WiFi.scanDelete();

    return false;
}

bool IoTProtocol::connectToAP()
{
    Serial.printf("Connecting to AP: %s\n", wifi_ssid.c_str());

    // Print WiFi status codes for reference
    Serial.println("WiFi Status Codes:");
    Serial.println("  WL_IDLE_STATUS = 0");
    Serial.println("  WL_NO_SSID_AVAIL = 1");
    Serial.println("  WL_SCAN_COMPLETED = 2");
    Serial.println("  WL_CONNECTED = 3");
    Serial.println("  WL_CONNECT_FAILED = 4");
    Serial.println("  WL_CONNECTION_LOST = 5");
    Serial.println("  WL_DISCONNECTED = 6");

    // Make sure WiFi is in correct mode
    WiFi.mode(WIFI_STA);
    delay(100);

    // Check if WiFi is ready
    Serial.printf("WiFi mode: %d, Initial status: %d\n", WiFi.getMode(), WiFi.status());

    // Start connection
    wl_status_t connect_result = WiFi.begin(wifi_ssid.c_str(), wifi_password.c_str());
    Serial.printf("WiFi.begin() returned: %d\n", connect_result);

    int attempts = 0;
    unsigned long start_time = millis();
    wl_status_t last_status = WL_IDLE_STATUS;

    while (WiFi.status() != WL_CONNECTED && attempts < 60) // Increased attempts significantly
    {
        wl_status_t current_status = WiFi.status();

        // Print status changes
        if (current_status != last_status)
        {
            Serial.printf("\nWiFi status changed: %d -> %d ", last_status, current_status);
            switch (current_status)
            {
            case WL_IDLE_STATUS:
                Serial.print("(IDLE)");
                break;
            case WL_NO_SSID_AVAIL:
                Serial.print("(NO_SSID_AVAIL - continuing to retry)");
                break;
            case WL_SCAN_COMPLETED:
                Serial.print("(SCAN_COMPLETED)");
                break;
            case WL_CONNECTED:
                Serial.print("(CONNECTED)");
                break;
            case WL_CONNECT_FAILED:
                Serial.print("(CONNECT_FAILED)");
                break;
            case WL_CONNECTION_LOST:
                Serial.print("(CONNECTION_LOST)");
                break;
            case WL_DISCONNECTED:
                Serial.print("(DISCONNECTED)");
                break;
            default:
                Serial.printf("(UNKNOWN:%d)", current_status);
                break;
            }
            Serial.println();
            last_status = current_status;
        }
        else
        {
            Serial.print(".");
        }

        delay(500);
        attempts++;

        // Check for specific failure conditions
        if (current_status == WL_CONNECT_FAILED)
        {
            Serial.println("\nConnection explicitly failed - breaking");
            break;
        }
        // TODO: I'm not sure if we should break on NO_SSID_AVAIL or not
        // Don't break immediately on NO_SSID_AVAIL - it might be temporary
        // if (current_status == WL_NO_SSID_AVAIL)
        // {
        //     Serial.println("\nSSID not available - breaking");
        //     break;
        // }
    }

    wl_status_t final_status = WiFi.status();
    Serial.printf("\nFinal WiFi status after %d attempts (%.1fs): %d ",
                  attempts, (millis() - start_time) / 1000.0, final_status);

    if (final_status == WL_CONNECTED)
    {
        Serial.printf("(CONNECTED)\nConnected to AP. IP: %s\n", WiFi.localIP().toString().c_str());
        Serial.printf("RSSI: %d dBm\n", WiFi.RSSI());
        Serial.printf("Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
        Serial.printf("DNS: %s\n", WiFi.dnsIP().toString().c_str());
        return true;
    }
    else
    {
        Serial.print("(");
        switch (final_status)
        {
        case WL_IDLE_STATUS:
            Serial.print("IDLE");
            break;
        case WL_NO_SSID_AVAIL:
            Serial.print("NO_SSID_AVAIL - Network not found or out of range");
            break;
        case WL_SCAN_COMPLETED:
            Serial.print("SCAN_COMPLETED");
            break;
        case WL_CONNECT_FAILED:
            Serial.print("CONNECT_FAILED - Wrong password or security mismatch");
            break;
        case WL_CONNECTION_LOST:
            Serial.print("CONNECTION_LOST");
            break;
        case WL_DISCONNECTED:
            Serial.print("DISCONNECTED");
            break;
        default:
            Serial.printf("UNKNOWN:%d", final_status);
            break;
        }
        Serial.println(")");
        Serial.println("Failed to connect to AP");

        // Additional diagnostics
        Serial.println("Diagnostics:");
        Serial.printf("  SSID: %s (len: %d)\n", wifi_ssid.c_str(), wifi_ssid.length());
        Serial.printf("  Password: %s (len: %d)\n", wifi_password.length() > 0 ? "***" : "(empty)", wifi_password.length());
        Serial.printf("  MAC Address: %s\n", WiFi.macAddress().c_str());
        Serial.printf("  Free heap: %u bytes\n", ESP.getFreeHeap());

        return false;
    }
}

bool IoTProtocol::establishTCPConnection()
{
    // Auto-discover gateway IP
    IPAddress gateway = WiFi.gatewayIP();

    Serial.printf("Auto-discovered gateway: %s\n", gateway.toString().c_str());
    Serial.printf("Connecting to router at %s:%d\n", gateway.toString().c_str(), router_port);

    if (wifi_client.connect(gateway, router_port))
    {
        Serial.println("TCP connection established");
        return true;
    }
    else
    {
        Serial.println("TCP connection failed");
        return false;
    }
}

bool IoTProtocol::setupBLEServer()
{
    // Initialize BLE with device ID
    BLEDevice::init(device_id.c_str());

    ble_server = BLEDevice::createServer();
    ble_server->setCallbacks(new IoTBLEServerCallbacks(this));

    BLEService *service = ble_server->createService(IOT_SERVICE_UUID);

    // Create bidirectional data characteristic
    ble_characteristic = service->createCharacteristic(
        IOT_CHARACTERISTIC_UUID,
        BLECharacteristic::PROPERTY_READ |
            BLECharacteristic::PROPERTY_WRITE |
            BLECharacteristic::PROPERTY_WRITE_NR |
            BLECharacteristic::PROPERTY_NOTIFY);
    ble_characteristic->setCallbacks(new IoTBLECharacteristicCallbacks(this));
    ble_characteristic->addDescriptor(new BLE2902());

    service->start();

    return true;
}

bool IoTProtocol::startBLEAdvertising()
{
    BLEAdvertising *advertising = BLEDevice::getAdvertising();
    advertising->addServiceUUID(IOT_SERVICE_UUID);

    // Include Router ID in device name for discovery
    String ble_name = router_id + "_" + device_id;

    // Set the device name in advertisement data
    esp_ble_gap_set_device_name(ble_name.c_str());

    advertising->setScanResponse(true);
    advertising->setMinPreferred(0x06);
    advertising->setMinPreferred(0x12);

    BLEDevice::startAdvertising();

    Serial.printf("BLE advertising started with name: %s\n", ble_name.c_str());

    return true;
}

bool IoTProtocol::performHandshake()
{
    Serial.println("Starting handshake...");

    // Send HELLO
    if (!sendHello())
    {
        Serial.println("Failed to send HELLO");
        return false;
    }

    // Receive CHALLENGE
    if (!receiveChallenge())
    {
        Serial.println("Failed to receive CHALLENGE");
        return false;
    }

    // Send AUTH
    if (!sendAuth())
    {
        Serial.println("Failed to send AUTH");
        return false;
    }

    // Receive AUTH_ACK
    if (!receiveAuthAck())
    {
        Serial.println("Failed to receive AUTH_ACK");
        return false;
    }

    handshake_completed = true;
    Serial.println("Handshake completed successfully");
    return true;
}

bool IoTProtocol::sendHello()
{
    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_HELLO;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.reserved = 0;

    // Generate nonce
    generateNonce(nonce1);

    // Build payload: RID_length | RID | DeviceID_length | DeviceID | Nonce1
    uint8_t *payload = packet.payload;
    size_t offset = 0;

    uint8_t rid_len = router_id.length();
    payload[offset++] = rid_len;
    memcpy(payload + offset, router_id.c_str(), rid_len);
    offset += rid_len;

    uint8_t device_len = device_id.length();
    payload[offset++] = device_len;
    memcpy(payload + offset, device_id.c_str(), device_len);
    offset += device_len;

    // Add nonce (big-endian)
    payload[offset++] = (nonce1 >> 24) & 0xFF;
    payload[offset++] = (nonce1 >> 16) & 0xFF;
    payload[offset++] = (nonce1 >> 8) & 0xFF;
    payload[offset++] = nonce1 & 0xFF;

    packet.payload_length = offset;

    Serial.printf("Sending HELLO (nonce1: 0x%08X)\n", nonce1);
    Serial.printf("Packet details: version_flags=0x%02X, msg_type=0x%02X, source=0x%04X, dest=0x%04X, payload_len=%d\n",
                  packet.version_flags, packet.msg_type, packet.source_addr, packet.dest_addr, packet.payload_length);

    bool result = sendPacket(packet);
    Serial.printf("sendPacket result: %s\n", result ? "SUCCESS" : "FAILED");
    return result;
}

bool IoTProtocol::receiveChallenge()
{
    ProtocolPacket packet;
    if (!receivePacket(packet, 5000) || packet.msg_type != MSG_CHALLENGE)
    {
        return false;
    }

    if (packet.payload_length < 4)
    {
        return false;
    }

    // Extract nonce2 (big-endian)
    nonce2 = (packet.payload[0] << 24) |
             (packet.payload[1] << 16) |
             (packet.payload[2] << 8) |
             packet.payload[3];

    Serial.printf("Received CHALLENGE (nonce2: 0x%08X)\n", nonce2);
    return true;
}

bool IoTProtocol::sendAuth()
{
    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4);
    packet.msg_type = MSG_AUTH;
    packet.source_addr = UNASSIGNED_ADDRESS;
    packet.dest_addr = ROUTER_ADDRESS;
    packet.reserved = 0;

    Serial.printf("Computing HMAC for AUTH packet:\n");
    Serial.printf("  - nonce2: 0x%08X\n", nonce2);
    Serial.printf("  - device_id: '%s'\n", device_id.c_str());
    Serial.printf("  - router_id: '%s'\n", router_id.c_str());
    Serial.printf("  - shared_secret: '%s'\n", shared_secret.c_str());

    // Compute HMAC_SHA256(PSK, Nonce2 || DeviceID || RID)
    // NOTE: nonce2 must be in binary format (4 bytes, big-endian), not decimal string!

    // Create binary data buffer: nonce2 (4 bytes) + device_id + router_id
    size_t data_len = 4 + device_id.length() + router_id.length();
    uint8_t *auth_data = new uint8_t[data_len];

    // Pack nonce2 as 4 bytes (big-endian)
    auth_data[0] = (nonce2 >> 24) & 0xFF;
    auth_data[1] = (nonce2 >> 16) & 0xFF;
    auth_data[2] = (nonce2 >> 8) & 0xFF;
    auth_data[3] = nonce2 & 0xFF;

    // Append device_id
    memcpy(auth_data + 4, device_id.c_str(), device_id.length());

    // Append router_id
    memcpy(auth_data + 4 + device_id.length(), router_id.c_str(), router_id.length());

    Serial.printf("  - HMAC input data (%d bytes): ", data_len);
    for (size_t i = 0; i < data_len && i < 32; i++)
    {
        Serial.printf("%02x", auth_data[i]);
    }
    if (data_len > 32)
        Serial.printf("...");
    Serial.println();

    uint8_t auth_hmac[HMAC_SIZE];
    bool hmac_result = computeHMAC((uint8_t *)shared_secret.c_str(), shared_secret.length(),
                                   auth_data, data_len, auth_hmac);

    delete[] auth_data; // Clean up allocated memory

    if (!hmac_result)
    {
        Serial.println("Failed to compute AUTH HMAC");
        return false;
    }

    Serial.printf("  - Computed HMAC (first 16 bytes): ");
    for (int i = 0; i < 16; i++)
    {
        Serial.printf("%02x", auth_hmac[i]);
    }
    Serial.println();

    // Build payload: AuthTag (16 bytes) | Nonce1 (4 bytes)
    memcpy(packet.payload, auth_hmac, 16); // Use first 16 bytes of HMAC
    packet.payload[16] = (nonce1 >> 24) & 0xFF;
    packet.payload[17] = (nonce1 >> 16) & 0xFF;
    packet.payload[18] = (nonce1 >> 8) & 0xFF;
    packet.payload[19] = nonce1 & 0xFF;

    packet.payload_length = 20;

    Serial.println("Sending AUTH");
    return sendPacket(packet);
}

bool IoTProtocol::receiveAuthAck()
{
    ProtocolPacket packet;
    if (!receivePacket(packet, 5000) || packet.msg_type != MSG_AUTH_ACK)
    {
        Serial.println("Failed to receive AUTH_ACK packet");
        return false;
    }

    Serial.printf("Received AUTH_ACK packet (payload length: %d bytes)\n", packet.payload_length);

    if (packet.payload_length < 18)
    {
        Serial.printf("AUTH_ACK payload too short: %d bytes (expected >= 18)\n", packet.payload_length);
        return false;
    }

    Serial.printf("Verifying router's authentication:\n");
    Serial.printf("  - nonce1: 0x%08X\n", nonce1);
    Serial.printf("  - shared_secret: '%s'\n", shared_secret.c_str());

    // Verify router's HMAC of our nonce1
    // NOTE: Router uses binary nonce1 (4 bytes, big-endian), not decimal string!
    uint8_t verify_data[4];
    verify_data[0] = (nonce1 >> 24) & 0xFF;
    verify_data[1] = (nonce1 >> 16) & 0xFF;
    verify_data[2] = (nonce1 >> 8) & 0xFF;
    verify_data[3] = nonce1 & 0xFF;

    Serial.printf("  - HMAC input data (4 bytes): ");
    for (int i = 0; i < 4; i++)
    {
        Serial.printf("%02x", verify_data[i]);
    }
    Serial.println();

    uint8_t expected_hmac[HMAC_SIZE];

    if (!computeHMAC((uint8_t *)shared_secret.c_str(), shared_secret.length(),
                     verify_data, 4, expected_hmac))
    {
        Serial.println("Failed to compute verification HMAC");
        return false;
    }

    Serial.printf("  - Expected HMAC (first 16 bytes): ");
    for (int i = 0; i < 16; i++)
    {
        Serial.printf("%02x", expected_hmac[i]);
    }
    Serial.println();

    Serial.printf("  - Received HMAC (first 16 bytes): ");
    for (int i = 0; i < 16; i++)
    {
        Serial.printf("%02x", packet.payload[i]);
    }
    Serial.println();

    // Compare first 16 bytes
    if (memcmp(packet.payload, expected_hmac, 16) != 0)
    {
        Serial.println("  - HMAC verification: FAILED");
        Serial.println("Router authentication failed - HMAC mismatch");
        return false;
    }

    Serial.println("  - HMAC verification: PASSED");

    // Extract assigned address
    assigned_address = (packet.payload[16] << 8) | packet.payload[17];
    Serial.printf("  - Assigned address: 0x%04X\n", assigned_address);

    // Derive session key
    if (!deriveSessionKey(nonce1, nonce2))
    {
        Serial.println("Failed to derive session key");
        return false;
    }

    Serial.printf("AUTH_ACK received, assigned address: 0x%04X\n", assigned_address);
    Serial.println("Router authentication successful!");
    return true;
}

bool IoTProtocol::computeHMAC(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *hmac)
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);

    if (mbedtls_md_setup(&ctx, info, 1) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_starts(&ctx, key, key_len) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_update(&ctx, data, data_len) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    if (mbedtls_md_hmac_finish(&ctx, hmac) != 0)
    {
        mbedtls_md_free(&ctx);
        return false;
    }

    mbedtls_md_free(&ctx);
    return true;
}

bool IoTProtocol::deriveSessionKey(uint32_t nonce1, uint32_t nonce2)
{
    // SessionKey = HMAC_SHA256(PSK, Nonce1 || Nonce2)
    uint8_t nonce_data[8];
    nonce_data[0] = (nonce1 >> 24) & 0xFF;
    nonce_data[1] = (nonce1 >> 16) & 0xFF;
    nonce_data[2] = (nonce1 >> 8) & 0xFF;
    nonce_data[3] = nonce1 & 0xFF;
    nonce_data[4] = (nonce2 >> 24) & 0xFF;
    nonce_data[5] = (nonce2 >> 16) & 0xFF;
    nonce_data[6] = (nonce2 >> 8) & 0xFF;
    nonce_data[7] = nonce2 & 0xFF;

    uint8_t session_hmac[HMAC_SIZE];
    if (!computeHMAC((uint8_t *)shared_secret.c_str(), shared_secret.length(),
                     nonce_data, 8, session_hmac))
    {
        return false;
    }

    // Use first 16 bytes as AES-128 key
    memcpy(session_key, session_hmac, SESSION_KEY_SIZE);

    Serial.println("Session key derived successfully");
    return true;
}

bool IoTProtocol::encryptPayload(const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t &ciphertext_len)
{
    // Use AES-128-CBC encryption to match router
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_enc(&aes, session_key, 128) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Generate IV using counter (16 bytes)
    uint8_t iv[16];
    memset(iv, 0, 16);
    // Convert counter to big-endian bytes in last 8 bytes of IV
    for (int i = 0; i < 8; i++)
    {
        iv[15 - i] = (iv_counter >> (i * 8)) & 0xFF;
    }
    iv_counter++;

    // Pad to AES block size using PKCS#7
    size_t padded_len = ((plaintext_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (padded_len + 16 > MAX_PAYLOAD_SIZE) // +16 for IV
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    uint8_t *padded_data = (uint8_t *)malloc(padded_len);
    if (!padded_data)
    {
        mbedtls_aes_free(&aes);
        return false;
    }
    memcpy(padded_data, plaintext, plaintext_len);

    // PKCS#7 padding
    uint8_t pad_value = padded_len - plaintext_len;
    for (size_t i = plaintext_len; i < padded_len; i++)
    {
        padded_data[i] = pad_value;
    }

    // Copy IV to beginning of ciphertext
    memcpy(ciphertext, iv, 16);

    // Encrypt using CBC mode
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len,
                              iv, padded_data, ciphertext + 16) != 0)
    {
        mbedtls_aes_free(&aes);
        free(padded_data);
        return false;
    }

    ciphertext_len = padded_len + 16; // +16 for IV
    mbedtls_aes_free(&aes);
    free(padded_data);
    return true;
}

bool IoTProtocol::decryptPayload(const uint8_t *encrypted_data, unsigned int encrypted_length, uint8_t *decrypted_data, unsigned int &decrypted_length)
{
    if (!handshake_completed)
    {
        // No encryption during handshake
        memcpy(decrypted_data, encrypted_data, encrypted_length);
        decrypted_length = encrypted_length;
        return true;
    }

    // AES-128-CBC decryption to match router
    if (encrypted_length < 16) // Must have at least IV
    {
        return false;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    if (mbedtls_aes_setkey_dec(&aes, session_key, 128) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Extract IV from first 16 bytes
    uint8_t iv[16];
    memcpy(iv, encrypted_data, 16);

    // Encrypted payload starts after IV
    const uint8_t *ciphertext = encrypted_data + 16;
    size_t ciphertext_len = encrypted_length - 16;

    if (ciphertext_len % AES_BLOCK_SIZE != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Decrypt using CBC mode
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ciphertext_len,
                              iv, ciphertext, decrypted_data) != 0)
    {
        mbedtls_aes_free(&aes);
        return false;
    }

    // Remove PKCS#7 padding
    uint8_t pad_value = decrypted_data[ciphertext_len - 1];
    if (pad_value > 0 && pad_value <= AES_BLOCK_SIZE)
    {
        decrypted_length = ciphertext_len - pad_value;
    }
    else
    {
        decrypted_length = ciphertext_len;
    }

    mbedtls_aes_free(&aes);
    return true;
}

bool IoTProtocol::sendMessage(uint16_t dest_addr, const String &message)
{
    return sendData(dest_addr, (const uint8_t *)message.c_str(), message.length());
}

bool IoTProtocol::sendData(uint16_t dest_addr, const uint8_t *data, size_t length)
{
    Serial.printf("sendData: dest=0x%04X, length=%d, handshake_completed=%s\n",
                  dest_addr, length, handshake_completed ? "true" : "false");

    if (!handshake_completed)
    {
        Serial.println("  ERROR: Handshake not completed");
        return false;
    }

    if (length > MAX_PAYLOAD_SIZE)
    {
        Serial.printf("  ERROR: Data too large: %d > %d (MAX_PAYLOAD_SIZE)\n", length, MAX_PAYLOAD_SIZE);
        return false;
    }

    Serial.printf("  Data to send: '%.50s%s'\n",
                  (const char *)data, length > 50 ? "..." : "");

    ProtocolPacket packet;
    packet.version_flags = (PROTOCOL_VERSION << 4) | FLAG_ENCRYPTED;
    packet.msg_type = MSG_DATA;
    packet.source_addr = assigned_address;
    packet.dest_addr = dest_addr;
    packet.reserved = 0;

    Serial.printf("  Assigned address: 0x%04X\n", assigned_address);

    // Encrypt payload
    size_t encrypted_len;
    Serial.println("  Attempting to encrypt payload...");
    if (!encryptPayload(data, length, packet.payload, encrypted_len))
    {
        Serial.println("  ERROR: Failed to encrypt payload");
        return false;
    }

    Serial.printf("  Encrypted payload length: %d bytes\n", encrypted_len);
    packet.payload_length = encrypted_len;

    Serial.println("  Sending packet...");
    bool result = sendPacket(packet);
    Serial.printf("  Packet send result: %s\n", result ? "SUCCESS" : "FAILED");

    return result;
}

bool IoTProtocol::receivePacket(ProtocolPacket &packet, unsigned long timeout_ms)
{
    if (active_transport == TRANSPORT_WIFI)
    {
        return receiveWiFiPacket(packet, timeout_ms);
    }
    else if (active_transport == TRANSPORT_BLE)
    {
        return receiveBLEPacket(packet, timeout_ms);
    }
    return false;
}

bool IoTProtocol::receiveWiFiPacket(ProtocolPacket &packet, unsigned long timeout_ms)
{
    unsigned long start_time = millis();
    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t received = 0;

    while (millis() - start_time < timeout_ms)
    {
        while (wifi_client.available() && received < sizeof(buffer))
        {
            buffer[received++] = wifi_client.read();

            // Check if we have complete packet
            if (received >= HEADER_SIZE)
            {
                uint8_t payload_length = buffer[6]; // Payload length field
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

bool IoTProtocol::receiveBLEPacket(ProtocolPacket &packet, unsigned long timeout_ms)
{
    // Only print debug for longer timeouts (handshake phase) to reduce spam
    bool debug_enabled = (timeout_ms > 100);

    if (debug_enabled) {
        Serial.printf("receiveBLEPacket: waiting for packet (timeout=%lu ms)\n", timeout_ms);
    }

    unsigned long start_time = millis();

    while (millis() - start_time < timeout_ms)
    {
        // Check if a packet is available in the buffer
        if (ble_packet_available)
        {
            Serial.printf("Found BLE packet in buffer: %d bytes\n", ble_packet_length);

            // Parse the packet from the buffer
            if (deserializePacket(ble_packet_buffer, ble_packet_length, packet))
            {
                Serial.printf("Successfully parsed BLE packet: type=0x%02X, src=0x%04X, dest=0x%04X\n",
                              packet.msg_type, packet.source_addr, packet.dest_addr);

                // Clear the buffer
                ble_packet_available = false;
                ble_packet_length = 0;

                return true;
            }
            else
            {
                Serial.println("Failed to parse BLE packet from buffer");
                ble_packet_available = false;
                ble_packet_length = 0;
            }
        }

        delay(10);
    }

    // Only print timeout message for longer timeouts to reduce spam
    if (debug_enabled) {
        Serial.println("receiveBLEPacket: timeout - no packet received");
    }
    return false;
}

bool IoTProtocol::sendPacket(const ProtocolPacket &packet)
{
    Serial.printf("sendPacket: active_transport=%d (WIFI=0, BLE=1)\n", active_transport);

    if (active_transport == TRANSPORT_WIFI)
    {
        Serial.println("Routing packet to WiFi");
        return sendWiFiPacket(packet);
    }
    else if (active_transport == TRANSPORT_BLE)
    {
        Serial.println("Routing packet to BLE");
        return sendBLEPacket(packet);
    }

    Serial.println("ERROR: No active transport set!");
    return false;
}

bool IoTProtocol::sendWiFiPacket(const ProtocolPacket &packet)
{
    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;

    serializePacket(packet, buffer, length);

    if (wifi_client.connected())
    {
        size_t sent = wifi_client.write(buffer, length);
        return sent == length;
    }

    return false;
}

bool IoTProtocol::sendBLEPacket(const ProtocolPacket &packet)
{
    Serial.printf("sendBLEPacket: Starting packet send, type=0x%02X\n", packet.msg_type);

    if (!ble_characteristic)
    {
        Serial.println("BLE packet send failed: ble_characteristic is NULL");
        return false;
    }

    if (!ble_client_connected)
    {
        Serial.println("BLE packet send failed: ble_client_connected is false");
        return false;
    }

    Serial.println("BLE packet send: characteristic and client are ready");

    uint8_t buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t length;

    serializePacket(packet, buffer, length);

    Serial.printf("Serialized packet: type=0x%02X, length=%d bytes\n", packet.msg_type, length);
    Serial.printf("Buffer contents (first 16 bytes): ");
    for (int i = 0; i < min(16, (int)length); i++) {
        Serial.printf("%02X ", buffer[i]);
    }
    Serial.println();

    try {
        // Set the characteristic value (this will trigger the router's onWrite callback)
        ble_characteristic->setValue(buffer, length);
        Serial.println("setValue() completed successfully");

        // Notify the router that new data is available
        ble_characteristic->notify();
        Serial.println("notify() completed successfully");

        Serial.println("BLE packet sent successfully");
        return true;
    } catch (...) {
        Serial.println("Exception occurred during BLE packet send");
        return false;
    }
}

void IoTProtocol::serializePacket(const ProtocolPacket &packet, uint8_t *buffer, size_t &length)
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

bool IoTProtocol::deserializePacket(const uint8_t *buffer, size_t length, ProtocolPacket &packet)
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

void IoTProtocol::generateNonce(uint32_t &nonce)
{
    nonce = esp_random();
}

uint8_t IoTProtocol::calculateSimpleChecksum(const uint8_t *data, size_t length)
{
    uint8_t checksum = 0;
    for (size_t i = 0; i < length; i++)
    {
        checksum ^= data[i];
    }
    return checksum;
}

bool IoTProtocol::verifySimpleChecksum(const uint8_t *data, size_t length, uint8_t expected)
{
    return calculateSimpleChecksum(data, length) == expected;
}

bool IoTProtocol::isConnected() const
{
    if (active_transport == TRANSPORT_WIFI)
    {
        return wifi_connected && const_cast<WiFiClient &>(wifi_client).connected() && handshake_completed;
    }
    else if (active_transport == TRANSPORT_BLE)
    {
        return ble_connected && ble_client_connected && handshake_completed;
    }
    return false;
}

TransportType IoTProtocol::getTransportType() const
{
    return active_transport;
}

uint16_t IoTProtocol::getAssignedAddress() const
{
    return assigned_address;
}

String IoTProtocol::getDeviceId() const
{
    return device_id;
}

// BLE Callback implementations
void IoTProtocol::onBLEConnect()
{
    ble_client_connected = true;
    Serial.println("BLE client connected");
}

void IoTProtocol::onBLEDisconnect()
{
    ble_client_connected = false;
    Serial.println("BLE client disconnected");
}

void IoTProtocol::onBLEWrite(const uint8_t *data, size_t length)
{
    Serial.printf("BLE data received: %d bytes\n", length);

    // Store packet in buffer for later processing
    if (length <= sizeof(ble_packet_buffer))
    {
        memcpy(ble_packet_buffer, data, length);
        ble_packet_length = length;
        ble_packet_available = true;
        Serial.println("BLE packet stored in buffer");

        // Debug: show first 16 bytes
        Serial.printf("Received data (first 16 bytes): ");
        for (size_t i = 0; i < min((size_t)16, length); i++) {
            Serial.printf("%02X ", data[i]);
        }
        Serial.println();
    }
    else
    {
        Serial.printf("BLE packet too large: %d bytes (max %d)\n", length, sizeof(ble_packet_buffer));
    }
}