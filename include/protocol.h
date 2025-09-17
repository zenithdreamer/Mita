/**
 * Multi-Protocol IoT Network - Complete Protocol Implementation for ESP32
 * This code need big refactor and cleanup
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <esp_random.h>

// Protocol constants
#define PROTOCOL_VERSION 1
#define FLAG_ENCRYPTED 0x01
#define HEADER_SIZE 8
#define MAX_PAYLOAD_SIZE 256

// Cryptographic constants
#define HMAC_SIZE 32
#define SESSION_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define NONCE_SIZE 4

// BLE Service and Characteristic UUIDs - must match router configuration
#define IOT_SERVICE_UUID "12345678-1234-1234-1234-123456789abc"
#define IOT_CHARACTERISTIC_UUID "12345678-1234-1234-1234-123456789abd" // Bidirectional data

// Special addresses
#define ROUTER_ADDRESS 0x0000
#define BROADCAST_ADDRESS 0xFFFF
#define UNASSIGNED_ADDRESS 0x0000

// Message types
enum MessageType
{
    MSG_HELLO = 0x01,
    MSG_CHALLENGE = 0x02,
    MSG_AUTH = 0x03,
    MSG_AUTH_ACK = 0x04,
    MSG_DATA = 0x05,
    MSG_ACK = 0x06,
    MSG_CONTROL = 0x07,
    MSG_ERROR = 0xFF
};

// Transport types
enum TransportType
{
    TRANSPORT_WIFI,
    TRANSPORT_BLE
};

// Simple packet structure
struct ProtocolPacket
{
    uint8_t version_flags;
    uint8_t msg_type;
    uint16_t source_addr;
    uint16_t dest_addr;
    uint8_t payload_length;
    uint8_t reserved;
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

// Forward declarations for BLE
class BLECharacteristic;
class BLEServer;

// Simple IoT Protocol class
class IoTProtocol
{
private:
    String router_id;
    String shared_secret;
    String device_id;
    uint16_t assigned_address;

    // WiFi
    WiFiClient wifi_client;
    bool wifi_connected;
    String wifi_ssid;
    String wifi_password;
    IPAddress router_ip;
    uint16_t router_port;

    // BLE
    BLEServer *ble_server;
    BLECharacteristic *ble_characteristic; // Bidirectional data
    bool ble_connected;
    bool ble_client_connected;
    String ble_service_uuid;
    String ble_char_uuid;

    // BLE packet buffering
    uint8_t ble_packet_buffer[HEADER_SIZE + MAX_PAYLOAD_SIZE];
    size_t ble_packet_length;
    bool ble_packet_available;

    // State
    bool handshake_completed;
    uint32_t nonce1;
    uint32_t nonce2;
    uint8_t session_key[SESSION_KEY_SIZE];
    uint32_t iv_counter; // For AES-CBC encryption
    TransportType active_transport;

public:
    IoTProtocol();

    // Configuration
    bool loadConfig(const char *router_id, const char *shared_secret, const char *device_id);
    void setWiFiConfig(const char *ssid, const char *password, IPAddress ip, uint16_t port);
    void setBLEConfig(const char *service_uuid, const char *char_uuid);

    // Connection
    bool connectToNetwork();
    bool connectViaWiFi();
    bool connectViaBLE();
    void disconnect();

    // Handshake
    bool performHandshake();
    bool sendHello();
    bool receiveChallenge();
    bool sendAuth();
    bool receiveAuthAck();

    // Messaging
    bool sendMessage(uint16_t dest_addr, const String &message);
    bool sendData(uint16_t dest_addr, const uint8_t *data, size_t length);
    bool receivePacket(ProtocolPacket &packet, unsigned long timeout_ms = 1000);
    bool decryptPayload(const uint8_t *encrypted_data, unsigned int encrypted_length, uint8_t *decrypted_data, unsigned int &decrypted_length);

    // Status
    bool isConnected() const;
    TransportType getTransportType() const;
    uint16_t getAssignedAddress() const;
    String getDeviceId() const;

    // Utility
    void generateNonce(uint32_t &nonce);
    bool sendPacket(const ProtocolPacket &packet);

    // Cryptographic functions
    bool computeHMAC(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *hmac);
    bool deriveSessionKey(uint32_t nonce1, uint32_t nonce2);
    bool encryptPayload(const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t &ciphertext_len);

    // BLE callbacks and helpers
    void onBLEConnect();
    void onBLEDisconnect();
    void onBLEWrite(const uint8_t *data, size_t length);
    bool setupBLEServer();
    bool startBLEAdvertising();
    bool sendBLEPacket(const ProtocolPacket &packet);

private:
    // Internal helpers
    bool scanForRouter();
    bool connectToAP();
    bool establishTCPConnection();
    void serializePacket(const ProtocolPacket &packet, uint8_t *buffer, size_t &length);
    bool deserializePacket(const uint8_t *buffer, size_t length, ProtocolPacket &packet);
    uint8_t calculateSimpleChecksum(const uint8_t *data, size_t length);
    bool verifySimpleChecksum(const uint8_t *data, size_t length, uint8_t expected);

    // WiFi/BLE packet methods
    bool receiveWiFiPacket(ProtocolPacket &packet, unsigned long timeout_ms);
    bool receiveBLEPacket(ProtocolPacket &packet, unsigned long timeout_ms);
    bool sendWiFiPacket(const ProtocolPacket &packet);

    // BLE helpers
    bool scanForBLERouter();
    bool connectToBLERouter();
};

#endif // PROTOCOL_H