#ifndef MITA_CONFIG_H
#define MITA_CONFIG_H

// Default Configuration Values
// These can be overridden at compile time or loaded from NVRAM

#ifndef MITA_DEFAULT_ROUTER_ID
#define MITA_DEFAULT_ROUTER_ID "Mita_Router_1"
#endif

#ifndef MITA_DEFAULT_SHARED_SECRET
#define MITA_DEFAULT_SHARED_SECRET "Mita_password"
#endif

#ifndef MITA_DEFAULT_DEVICE_ID
#define MITA_DEFAULT_DEVICE_ID "ESP32_Sensor_001"
#endif

// Connection timeouts and retry parameters
#define MITA_CONNECTION_TIMEOUT_MS 30000
#define MITA_RECONNECT_INTERVAL_MS 10000
#define MITA_PACKET_TIMEOUT_MS 1000
#define MITA_HEARTBEAT_TIMEOUT_MS 30000 

// BLE advertising parameters
#define MITA_BLE_MIN_INTERVAL 0x06
#define MITA_BLE_MAX_INTERVAL 0x12

#endif // MITA_CONFIG_H