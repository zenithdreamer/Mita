#include "../include/mita_sdk.h"
#include "../include/core/mita_client.h"
#include "../include/transport/protocol_selector.h"
#include "../include/messaging/message_handler.h"
#include <esp_log.h>
#include <esp_timer.h>
#include <ArduinoJson.h>

// Debug logging - only enabled when MITA_SDK_DEBUG is defined
#ifndef MITA_SDK_DEBUG
#define MITA_SDK_DEBUG 0
#endif

#if MITA_SDK_DEBUG
#define SDK_LOGD(tag, format, ...) ESP_LOGI(tag, format, ##__VA_ARGS__)
#define SDK_LOGV(tag, format, ...) ESP_LOGD(tag, format, ##__VA_ARGS__)
#else
#define SDK_LOGD(tag, format, ...) do {} while(0)
#define SDK_LOGV(tag, format, ...) do {} while(0)
#endif

static const char *TAG = "MITA_SDK";

namespace Mita {

/**
 * @brief Internal implementation class (PIMPL pattern)
 * Hides all the complexity from the user
 */
class SDK::Impl {
public:
    // Configuration
    Config config;
    
    // Core components
    MitaClient* client = nullptr;
    ProtocolSelector* selector = nullptr;
    
    // Transports
    ITransport* transports[2] = {nullptr, nullptr};  // Max 2 transports (WiFi + BLE)
    size_t transport_count = 0;
    
    // State
    ConnectionStatus status = ConnectionStatus::DISCONNECTED;
    unsigned long last_reconnect_attempt = 0;
    
    // Callbacks
    OnConnectedCallback on_connected;
    OnDisconnectedCallback on_disconnected;
    OnMessageCallback on_message;
    OnErrorCallback on_error;
    OnStatusChangeCallback on_status_change;
    
    // Message handlers for bridging to callbacks
    class CallbackMessageHandler : public IMessageHandler {
    private:
        SDK::Impl* sdk_impl;
        
    public:
        CallbackMessageHandler(SDK::Impl* impl) : sdk_impl(impl) {}
        
        bool canHandle(const std::string &message_type) const override {
            // Handle all message types and forward to callbacks
            return true;
        }
        
        bool handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response) override {
            if (!sdk_impl->on_message) {
                return false;  // No callback registered
            }
            
            // Extract message type and payload
            const char* msg_type = message["type"] | "UNKNOWN";
            
            // Serialize payload to JSON string
            std::string payload;
            serializeJson(message, payload);
            
            // Call user callback
            sdk_impl->on_message(msg_type, payload);
            
            // For now, no response
            return true;
        }
    };
    
    CallbackMessageHandler* callback_handler = nullptr;
    
    Impl() {}
    
    ~Impl() {
        cleanup();
    }
    
    void cleanup() {
        if (client) {
            delete client;
            client = nullptr;
        }
        if (selector) {
            delete selector;
            selector = nullptr;
        }
        if (callback_handler) {
            delete callback_handler;
            callback_handler = nullptr;
        }
    }
    
    void setStatus(ConnectionStatus new_status) {
        if (status != new_status) {
            status = new_status;
            if (on_status_change) {
                on_status_change(new_status);
            }
        }
    }
    
    void triggerError(const std::string& error) {
        ESP_LOGE(TAG, "%s", error.c_str());
        if (on_error) {
            on_error(error);
        }
    }
    
    bool initialize() {
        if (client) {
            return true;  // Already initialized
        }
        
        // Validate configuration
        if (config.device_id.empty() || config.router_id.empty() || config.shared_secret.empty()) {
            triggerError("Invalid configuration: device_id, router_id, and shared_secret are required");
            return false;
        }
        
        // Create network config
        NetworkConfig net_config;
        net_config.device_id = config.device_id;
        net_config.router_id = config.router_id;
        net_config.shared_secret = config.shared_secret;
        
        // Create client
        client = new MitaClient(net_config);
        if (!client) {
            triggerError("Failed to create MitaClient instance");
            return false;
        }
        
        if (!client->initialize()) {
            triggerError("Failed to initialize MitaClient");
            delete client;
            client = nullptr;
            return false;
        }
        
        // Set QoS level
        client->setQoSLevel(config.qos_level == QoS::WITH_ACK ? QoSLevel::WITH_ACK : QoSLevel::NO_QOS);
        
        // Create callback handler
        callback_handler = new CallbackMessageHandler(this);
        client->addMessageHandler(callback_handler);
        
        SDK_LOGD(TAG, "SDK initialized for device: %s", config.device_id.c_str());
        SDK_LOGD(TAG, "  Router ID: %s", config.router_id.c_str());
        SDK_LOGD(TAG, "  QoS Level: %s", config.qos_level == QoS::WITH_ACK ? "WITH_ACK" : "NO_ACK");
        SDK_LOGD(TAG, "  Auto-reconnect: %s", config.auto_reconnect ? "enabled" : "disabled");
        
        ESP_LOGI(TAG, "SDK initialized for device: %s", config.device_id.c_str());
        return true;
    }
};

// SDK Implementation

SDK::SDK() : impl_(new Impl()) {
}

SDK::~SDK() {
    delete impl_;
}

void SDK::setConfig(const Config& config) {
    impl_->config = config;
}

bool SDK::addTransport(ITransport* transport) {
    if (!transport) {
        impl_->triggerError("Cannot add null transport");
        return false;
    }
    
    if (impl_->transport_count >= 2) {
        impl_->triggerError("Maximum number of transports (2) already added");
        return false;
    }
    
    impl_->transports[impl_->transport_count++] = transport;
    SDK_LOGD(TAG, "Added transport: %s (total: %zu)", 
             transport->getType() == TRANSPORT_WIFI ? "WiFi" : "BLE",
             impl_->transport_count);
    ESP_LOGI(TAG, "Added transport: %s", 
             transport->getType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
    return true;
}

bool SDK::connect() {
    if (!impl_->initialize()) {
        return false;
    }
    
    if (impl_->transport_count == 0) {
        impl_->triggerError("No transports added. Add at least one transport before connecting.");
        return false;
    }
    
    impl_->setStatus(ConnectionStatus::CONNECTING);
    
    SDK_LOGD(TAG, "========================================");
    SDK_LOGD(TAG, "Starting connection attempt...");
    SDK_LOGD(TAG, "========================================");
    
    // Try each transport in order
    for (size_t i = 0; i < impl_->transport_count; i++) {
        ITransport* transport = impl_->transports[i];
        const char* transport_name = transport->getType() == TRANSPORT_WIFI ? "WiFi" : "BLE";
        
        SDK_LOGD(TAG, "Attempting connection via %s (%zu/%zu)...", 
                 transport_name, i + 1, impl_->transport_count);
        ESP_LOGI(TAG, "Attempting connection via %s...", transport_name);
        
        if (impl_->client->connectToNetwork(transport)) {
            impl_->setStatus(ConnectionStatus::CONNECTED);
            
            SDK_LOGD(TAG, "========================================");
            SDK_LOGD(TAG, "Connection successful!");
            SDK_LOGD(TAG, "  Transport: %s", transport_name);
            SDK_LOGD(TAG, "  Address: 0x%04X", impl_->client->getAssignedAddress());
            SDK_LOGD(TAG, "========================================");
            
            // Trigger connected callback
            if (impl_->on_connected) {
                impl_->on_connected(transport->getType(), impl_->client->getAssignedAddress());
            }
            
            ESP_LOGI(TAG, "Connected via %s, address: 0x%04X", 
                     transport_name, impl_->client->getAssignedAddress());
            return true;
        }
        
        SDK_LOGD(TAG, "Connection via %s failed, trying next transport...", transport_name);
        ESP_LOGW(TAG, "Connection via %s failed", transport_name);
    }
    
    impl_->setStatus(ConnectionStatus::ERROR);
    impl_->triggerError("All transport connection attempts failed");
    return false;
}

bool SDK::connectSmart(SelectionStrategy strategy) {
    if (!impl_->initialize()) {
        return false;
    }
    
    if (impl_->transport_count == 0) {
        impl_->triggerError("No transports added. Add at least one transport before connecting.");
        return false;
    }
    
    impl_->setStatus(ConnectionStatus::CONNECTING);
    
    SDK_LOGD(TAG, "========================================");
    SDK_LOGD(TAG, "Starting smart connection...");
    SDK_LOGD(TAG, "  Strategy: %d", (int)strategy);
    SDK_LOGD(TAG, "========================================");
    
    // Create protocol selector if not exists
    if (!impl_->selector) {
        impl_->selector = new ProtocolSelector(impl_->config.device_id.c_str(), strategy);
        if (!impl_->selector) {
            impl_->triggerError("Failed to create ProtocolSelector");
            impl_->setStatus(ConnectionStatus::ERROR);
            return false;
        }
    }
    
    SDK_LOGV(TAG, "Protocol selector ready, initiating smart connection...");
    ESP_LOGI(TAG, "Starting smart connection with strategy: %d", (int)strategy);
    
    // Use smart connection
    if (impl_->client->connectToNetworkSmart(impl_->selector, impl_->config.shared_secret)) {
        impl_->setStatus(ConnectionStatus::CONNECTED);
        
        SDK_LOGD(TAG, "========================================");
        SDK_LOGD(TAG, "Smart connection successful!");
        SDK_LOGD(TAG, "  Transport: %s", impl_->client->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
        SDK_LOGD(TAG, "  Address: 0x%04X", impl_->client->getAssignedAddress());
        SDK_LOGD(TAG, "========================================");
        
        // Trigger connected callback
        if (impl_->on_connected) {
            impl_->on_connected(impl_->client->getTransportType(), 
                              impl_->client->getAssignedAddress());
        }
        
        ESP_LOGI(TAG, "Smart connection successful, address: 0x%04X", 
                 impl_->client->getAssignedAddress());
        return true;
    }
    
    impl_->setStatus(ConnectionStatus::ERROR);
    impl_->triggerError("Smart connection failed");
    return false;
}

void SDK::disconnect(bool graceful) {
    if (!impl_->client) {
        return;
    }
    
    if (graceful) {
        impl_->client->disconnect(DisconnectReason::NORMAL_SHUTDOWN);
    } else {
        impl_->client->disconnect();
    }
    
    impl_->setStatus(ConnectionStatus::DISCONNECTED);
    
    SDK_LOGD(TAG, "Disconnected from network (%s)", graceful ? "graceful" : "immediate");
    
    if (impl_->on_disconnected) {
        impl_->on_disconnected();
    }
    
    ESP_LOGI(TAG, "Disconnected from network");
}

void SDK::loop() {
    if (!impl_->client) {
        return;
    }
    
    // Check connection status
    if (!impl_->client->isConnected()) {
        if (impl_->status == ConnectionStatus::CONNECTED) {
            // Connection lost
            impl_->setStatus(ConnectionStatus::DISCONNECTED);
            if (impl_->on_disconnected) {
                impl_->on_disconnected();
            }
            SDK_LOGD(TAG, "Connection lost, auto-reconnect is %s", 
                     impl_->config.auto_reconnect ? "enabled" : "disabled");
            ESP_LOGW(TAG, "Connection lost");
        }
        
        // Auto-reconnect if enabled
        if (impl_->config.auto_reconnect) {
            unsigned long current_time = (unsigned long)(esp_timer_get_time() / 1000ULL);
            
            if (current_time - impl_->last_reconnect_attempt >= impl_->config.reconnect_interval_ms) {
                SDK_LOGD(TAG, "Attempting auto-reconnect (interval: %lu ms)...", 
                         impl_->config.reconnect_interval_ms);
                ESP_LOGI(TAG, "Attempting auto-reconnect...");
                impl_->setStatus(ConnectionStatus::RECONNECTING);
                
                // Try smart reconnect if selector exists, otherwise normal connect
                bool reconnected = false;
                if (impl_->selector) {
                    reconnected = impl_->client->connectToNetworkSmart(
                        impl_->selector, impl_->config.shared_secret);
                } else if (impl_->transport_count > 0) {
                    // Try first transport
                    reconnected = impl_->client->connectToNetwork(impl_->transports[0]);
                }
                
                if (reconnected) {
                    impl_->setStatus(ConnectionStatus::CONNECTED);
                    SDK_LOGD(TAG, "Auto-reconnect successful!");
                    if (impl_->on_connected) {
                        impl_->on_connected(impl_->client->getTransportType(), 
                                          impl_->client->getAssignedAddress());
                    }
                    ESP_LOGI(TAG, "Reconnected successfully");
                } else {
                    impl_->setStatus(ConnectionStatus::DISCONNECTED);
                    SDK_LOGD(TAG, "Auto-reconnect failed, will retry later");
                }
                
                impl_->last_reconnect_attempt = current_time;
            }
        }
    } else {
        // Connected - process messages and update
        impl_->client->update();
    }
}

bool SDK::send(const std::string& payload, uint16_t dest_address) {
    return send("DATA", payload, dest_address);
}

bool SDK::send(const std::string& message_type, const std::string& payload, uint16_t dest_address) {
    if (!impl_->client || !impl_->client->isConnected()) {
        SDK_LOGD(TAG, "Cannot send %s: not connected", message_type.c_str());
        impl_->triggerError("Cannot send: not connected");
        return false;
    }
    
    SDK_LOGV(TAG, "Sending %s message (payload length: %zu)", 
             message_type.c_str(), payload.length());
    
    // Create JSON message
    DynamicJsonDocument doc(1024);
    doc["type"] = message_type;
    doc["device_id"] = impl_->config.device_id;
    doc["payload"] = payload;
    doc["timestamp"] = (unsigned long)(esp_timer_get_time() / 1000ULL);
    
    std::string json_message;
    serializeJson(doc, json_message);
    
    SDK_LOGD(TAG, "Sending %s message to 0x%04X: %s", message_type.c_str(), dest_address, json_message.c_str());

    // Use the new sendData method with explicit destination
    return impl_->client->sendData(json_message, dest_address);
}

bool SDK::sendHeartbeat() {
    if (!impl_->client || !impl_->client->isConnected()) {
        return false;
    }
    return impl_->client->sendHeartbeat();
}

bool SDK::sendPing() {
    if (!impl_->client || !impl_->client->isConnected()) {
        return false;
    }
    return impl_->client->sendPing();
}

// Callback setters
void SDK::onConnected(OnConnectedCallback callback) {
    impl_->on_connected = callback;
}

void SDK::onDisconnected(OnDisconnectedCallback callback) {
    impl_->on_disconnected = callback;
}

void SDK::onMessage(OnMessageCallback callback) {
    impl_->on_message = callback;
}

void SDK::onError(OnErrorCallback callback) {
    impl_->on_error = callback;
}

void SDK::onStatusChange(OnStatusChangeCallback callback) {
    impl_->on_status_change = callback;
}

// Status getters
bool SDK::isConnected() const {
    return impl_->client && impl_->client->isConnected();
}

ConnectionStatus SDK::getStatus() const {
    return impl_->status;
}

uint16_t SDK::getAssignedAddress() const {
    return impl_->client ? impl_->client->getAssignedAddress() : UNASSIGNED_ADDRESS;
}

TransportType SDK::getCurrentTransport() const {
    return impl_->client ? impl_->client->getTransportType() : TRANSPORT_WIFI;
}

std::string SDK::getDeviceId() const {
    return impl_->config.device_id;
}

QoS SDK::getQoS() const {
    return impl_->config.qos_level;
}

// Configuration setters
void SDK::setQoS(QoS qos) {
    impl_->config.qos_level = qos;
    if (impl_->client) {
        impl_->client->setQoSLevel(qos == QoS::WITH_ACK ? QoSLevel::WITH_ACK : QoSLevel::NO_QOS);
    }
}

void SDK::setAutoReconnect(bool enable) {
    impl_->config.auto_reconnect = enable;
}

} // namespace Mita
