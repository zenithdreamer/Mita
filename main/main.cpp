/**
 * Mita - ESP32 Client Firmware (ESP-IDF)
 * 
 * Development/Debugging Version
 * Simple main using direct MitaClient API
 */

// Enable detailed SDK logging for debugging
#define MITA_SDK_DEBUG 1

#include <string.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <nvs_flash.h>
#include <driver/gpio.h>

#include "core/mita_client.h"
#include "transport/wifi_transport.h"
#include "transport/ble_transport.h"
#include "transport/protocol_selector.h"
#include "messaging/message_handler.h"
#include "../shared/config/mita_config.h"
#include <ArduinoJson.h>

static const char *TAG = "MITA_MAIN";

// Helper function to generate sensor data JSON
std::string generateSensorData(const char* device_id) {
    DynamicJsonDocument doc(256);
    doc["type"] = "sensor_data";
    doc["device_id"] = device_id;
    doc["timestamp"] = (unsigned long)(esp_timer_get_time() / 1000ULL);
    
    // Simulated sensor readings
    doc["temperature"] = 20.0 + ((esp_random() % 200) / 10.0);
    doc["humidity"] = 40.0 + ((esp_random() % 400) / 10.0);
    doc["pressure"] = 1000.0 + ((esp_random() % 100) / 10.0);
    doc["light"] = esp_random() % 1024;
    
    std::string result;
    serializeJson(doc, result);
    return result;
}

extern "C" void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "       Mita - ESP32 Development Client");
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "Device ID: %s", MITA_DEFAULT_DEVICE_ID);
    ESP_LOGI(TAG, "Router ID: %s", MITA_DEFAULT_ROUTER_ID);

    // Create network configuration
    NetworkConfig config;
    config.router_id = MITA_DEFAULT_ROUTER_ID;
    config.shared_secret = MITA_DEFAULT_SHARED_SECRET;
    config.device_id = MITA_DEFAULT_DEVICE_ID;

    // Create and initialize client
    MitaClient* client = new MitaClient(config);
    if (!client || !client->initialize()) {
        ESP_LOGE(TAG, "Failed to initialize MitaClient");
        return;
    }

    // Create protocol selector (ADAPTIVE learns best protocol over time)
    ProtocolSelector* selector = new ProtocolSelector(MITA_DEFAULT_DEVICE_ID, SelectionStrategy::ADAPTIVE);
    
    // Create and register message handlers
    CommandHandler* cmdHandler = new CommandHandler(MITA_DEFAULT_DEVICE_ID);
    PingHandler* pingHandler = new PingHandler(MITA_DEFAULT_DEVICE_ID);
    client->addMessageHandler(cmdHandler);
    client->addMessageHandler(pingHandler);

    // Set QoS level
    client->setQoSLevel(QoSLevel::WITH_ACK);
    
    // Enable auto-reconnect (enabled by default, but showing for clarity)
    client->setAutoReconnect(true, 5000);  // Reconnect every 5 seconds if disconnected

    // Connect using smart protocol selection
    ESP_LOGI(TAG, "Connecting to network...");
    selector->printStats();
    
    if (!client->connectToNetworkSmart(selector, MITA_DEFAULT_SHARED_SECRET)) {
        ESP_LOGE(TAG, "Failed to connect to network");
        return;
    }

    ESP_LOGI(TAG, "Successfully connected!");
    ESP_LOGI(TAG, "  Address: 0x%04X", client->getAssignedAddress());
    ESP_LOGI(TAG, "  Transport: %s", client->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
    ESP_LOGI(TAG, "================================================");

    // Main loop - send sensor data every 10 seconds
    unsigned long last_sensor_send = 0;
    const unsigned long SENSOR_INTERVAL = 10000;  // 10 seconds
    
    while (1) {
        client->update();  // Handles messages, heartbeats, AND auto-reconnect
        
        // Send sensor data periodically (only if connected)
        if (client->isConnected()) {
            unsigned long current_time = (unsigned long)(esp_timer_get_time() / 1000ULL);
            if (current_time - last_sensor_send >= SENSOR_INTERVAL) {
                std::string sensor_data = generateSensorData(MITA_DEFAULT_DEVICE_ID);
                ESP_LOGI(TAG, "Sending sensor data: %s", sensor_data.c_str());
                client->sendData(sensor_data);
                last_sensor_send = current_time;
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
