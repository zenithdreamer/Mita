#ifndef MITA_SDK_H
#define MITA_SDK_H

/**
 * Mita SDK - Simple callback-based API for ESP32 Mita clients
 * 
 * Debug Logging:
 * Define MITA_SDK_DEBUG=1 before including this header to enable detailed debug logs.
 * 
 * Example:
 *   #define MITA_SDK_DEBUG 1
 *   #include "mita_sdk.h"
 */

#include <string>
#include <functional>
#include <cstdint>
#include "shared/protocol/transport_interface.h"
#include "shared/protocol/protocol_types.h"
#include "transport/protocol_selector.h"

// Forward declarations
class MitaClient;
class ProtocolSelector;
class ITransport;

namespace Mita {

/**
 * @brief Connection status enum
 */
enum class ConnectionStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    RECONNECTING,
    ERROR
};

/**
 * @brief QoS (Quality of Service) levels
 */
enum class QoS {
    NO_ACK = 0,      // Fire-and-forget (UDP-like), no ACK expected
    WITH_ACK = 1     // Wait for ACK with retry (MQTT-like)
};

/**
 * @brief Configuration for the Mita SDK
 */
struct Config {
    std::string device_id;
    std::string router_id;
    std::string shared_secret;
    QoS qos_level = QoS::WITH_ACK;
    bool auto_reconnect = true;
    uint32_t reconnect_interval_ms = 5000;
};

/**
 * @brief Callback function types
 */
using OnConnectedCallback = std::function<void(TransportType transport, uint16_t assigned_address)>;
using OnDisconnectedCallback = std::function<void()>;
using OnMessageCallback = std::function<void(const std::string& message_type, const std::string& payload)>;
using OnErrorCallback = std::function<void(const std::string& error_message)>;
using OnStatusChangeCallback = std::function<void(ConnectionStatus status)>;

/**
 * @brief Main Mita SDK class
 * 
 * Simplified API for connecting to Mita network and sending/receiving data.
 * 
 * Example usage:
 * ```cpp
 * Mita::SDK sdk;
 * sdk.setConfig({
 *     .device_id = "device-001",
 *     .router_id = "router-001",
 *     .shared_secret = "my-secret"
 * });
 * 
 * sdk.onConnected([](TransportType type, uint16_t addr) {
 *     ESP_LOGI("APP", "Connected via %s, address: 0x%04X", 
 *              type == TRANSPORT_WIFI ? "WiFi" : "BLE", addr);
 * });
 * 
 * sdk.onMessage([](const std::string& type, const std::string& payload) {
 *     ESP_LOGI("APP", "Received %s: %s", type.c_str(), payload.c_str());
 * });
 * 
 * WiFiTransport wifi_transport("my-secret");
 * BLETransport ble_transport("device-001", "router-001");
 * 
 * sdk.addTransport(&wifi_transport);
 * sdk.addTransport(&ble_transport);
 * 
 * sdk.connect();  // Automatically tries transports in order
 * 
 * while (true) {
 *     sdk.loop();  // Call regularly to process messages
 *     vTaskDelay(pdMS_TO_TICKS(100));
 * }
 * ```
 */
class SDK {
public:
    SDK();
    ~SDK();

    /**
     * @brief Set SDK configuration
     * @param config Configuration structure
     */
    void setConfig(const Config& config);

    /**
     * @brief Add a transport to the SDK (WiFi, BLE, etc.)
     * @param transport Pointer to transport instance (must remain valid)
     * @return true if added successfully
     */
    bool addTransport(ITransport* transport);

    /**
     * @brief Connect to Mita network using available transports
     * Tries transports in the order they were added
     * @return true if connection successful
     */
    bool connect();

    /**
     * @brief Connect using smart protocol selection
     * Automatically selects best transport based on history and conditions
     * @param strategy Selection strategy (ADAPTIVE, PREFER_WIFI, etc.)
     * @return true if connection successful
     */
    bool connectSmart(SelectionStrategy strategy = SelectionStrategy::ADAPTIVE);

    /**
     * @brief Disconnect from network
     * @param graceful If true, sends disconnect message to router
     */
    void disconnect(bool graceful = true);

    /**
     * @brief Main loop - call this regularly to process messages
     * Handles incoming messages, heartbeats, reconnection, etc.
     */
    void loop();

    /**
     * @brief Send data to the router
     * @param payload Data to send (will be encrypted)
     * @return true if sent successfully
     */
    bool send(const std::string& payload);

    /**
     * @brief Send data with custom message type
     * @param message_type Type of message (e.g., "SENSOR_DATA", "COMMAND")
     * @param payload Message payload as JSON string or raw data
     * @return true if sent successfully
     */
    bool send(const std::string& message_type, const std::string& payload);

    /**
     * @brief Send heartbeat to router
     * @return true if sent successfully
     */
    bool sendHeartbeat();

    /**
     * @brief Send ping to measure RTT
     * @return true if sent successfully
     */
    bool sendPing();

    // Callback setters
    void onConnected(OnConnectedCallback callback);
    void onDisconnected(OnDisconnectedCallback callback);
    void onMessage(OnMessageCallback callback);
    void onError(OnErrorCallback callback);
    void onStatusChange(OnStatusChangeCallback callback);

    // Status getters
    bool isConnected() const;
    ConnectionStatus getStatus() const;
    uint16_t getAssignedAddress() const;
    TransportType getCurrentTransport() const;
    std::string getDeviceId() const;
    QoS getQoS() const;

    // Configuration setters
    void setQoS(QoS qos);
    void setAutoReconnect(bool enable);

private:
    class Impl;
    Impl* impl_;  // PIMPL pattern to hide internal complexity

    // Disable copy/move
    SDK(const SDK&) = delete;
    SDK& operator=(const SDK&) = delete;
};

} // namespace Mita

#endif // MITA_SDK_H
