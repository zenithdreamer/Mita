#ifndef TRANSPORT_CONSTANTS_H
#define TRANSPORT_CONSTANTS_H

// WiFi Transport Constants (Raw IP)
#define MITA_WIFI_PORT 8000
#define MITA_IP_PROTOCOL 253 // Custom protocol number (253 reserved for testing/experimentation)

// BLE Transport Constants
// Standard UUIDs for Mita Protocol
#define MITA_SERVICE_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define MITA_CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

// Legacy aliases (for backwards compatibility)
#define MITA_BLE_SERVICE_UUID MITA_SERVICE_UUID
#define MITA_BLE_CHARACTERISTIC_UUID MITA_CHARACTERISTIC_UUID

// BLE Device Names
#define MITA_BLE_ROUTER_NAME "Mita_Router"
#define MITA_BLE_DEVICE_PREFIX "Mita_Client_"

// WiFi Network Discovery Patterns
#define MITA_ROUTER_SSID_PATTERN "Mita_Router"
#define MITA_NETWORK_SSID "Mita_Network"

#define MITA_LORA_SYNC_WORD 0x34
#define MITA_LORA_MAX_PACKET_SIZE 255

#endif // TRANSPORT_CONSTANTS_H