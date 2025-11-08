/**
 * Mita - ESP32 Client Firmware (ESP-IDF)
 */

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

static const char *TAG = "MITA_MAIN";

#ifndef LED_BUILTIN
#define LED_BUILTIN GPIO_NUM_2
#endif

// Configuration - these would normally be loaded from NVRAM or config file
const char *ROUTER_ID = MITA_DEFAULT_ROUTER_ID;
const char *SHARED_SECRET = MITA_DEFAULT_SHARED_SECRET;
const char *DEVICE_ID = MITA_DEFAULT_DEVICE_ID;

// Global objects using dependency injection
MitaClient *mitaClient = nullptr;
CommandHandler *commandHandler = nullptr;
PingHandler *pingHandler = nullptr;
ProtocolSelector *protocolSelector = nullptr;

// Function prototypes
bool initializeDevice();
bool connectToNetwork();
bool connectToNetworkSmart();
void printStatus();

extern "C" void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Small delay for system stabilization
    vTaskDelay(pdMS_TO_TICKS(1000));

    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "       Mita - ESP32 Client");
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "Device ID: %s", DEVICE_ID);
    ESP_LOGI(TAG, "Router ID: %s", ROUTER_ID);

    if (!initializeDevice())
    {
        ESP_LOGI(TAG, "ERROR: Failed to initialize device");
        return;
    }

    // Use smart protocol selection
    if (connectToNetworkSmart())
    {
        ESP_LOGI(TAG, "Successfully connected to Mita network!");
        printStatus();
    }
    else
    {
        ESP_LOGI(TAG, "Failed to connect to network");
    }

    ESP_LOGI(TAG, "Setup complete");

    // Main loop
    unsigned long last_reconnect_attempt = 0;
    
    while (1)
    {
        if (!mitaClient)
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        // Check network connection and attempt reconnection if needed
        if (!mitaClient->isConnected())
        {
            unsigned long current_time = ((unsigned long)(esp_timer_get_time() / 1000ULL));

            if (current_time - last_reconnect_attempt >= MITA_RECONNECT_INTERVAL_MS)
            { // Try reconnecting at configured interval
                ESP_LOGI(TAG, "Connection lost, attempting smart reconnect...");
                if (connectToNetworkSmart())
                {
                    ESP_LOGI(TAG, "Reconnected to network!");
                    printStatus();
                }
                last_reconnect_attempt = current_time;
            }
        }
        else
        {
            // Device handles all messaging, heartbeats, and sensor data internally
            mitaClient->update();
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

bool initializeDevice()
{
    // Create network configuration
    NetworkConfig config;
    config.router_id = ROUTER_ID;
    config.shared_secret = SHARED_SECRET; // Master secret (always derives device PSK)
    config.device_id = DEVICE_ID;

    // Create device instance
    mitaClient = new MitaClient(config);
    if (!mitaClient)
    {
        ESP_LOGI(TAG, "%s", "Failed to create MitaClient instance");
        return false;
    }

    if (!mitaClient->initialize())
    {
        delete mitaClient;
        mitaClient = nullptr;
        return false;
    }

    // Create smart protocol selector
    // Strategies: ADAPTIVE (learns), LAST_SUCCESSFUL, FASTEST, STRONGEST_SIGNAL, PREFER_WIFI, PREFER_BLE
    protocolSelector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::ADAPTIVE);
    if (!protocolSelector)
    {
        ESP_LOGI(TAG, "%s", "Failed to create ProtocolSelector instance");
        delete mitaClient;
        mitaClient = nullptr;
        return false;
    }

    // Create and register message handlers
    commandHandler = new CommandHandler(DEVICE_ID);
    pingHandler = new PingHandler(DEVICE_ID);

    if (!commandHandler || !pingHandler)
    {
        ESP_LOGI(TAG, "%s", "Failed to create message handlers");
        delete mitaClient;
        delete commandHandler;
        delete pingHandler;
        delete protocolSelector;
        mitaClient = nullptr;
        commandHandler = nullptr;
        pingHandler = nullptr;
        protocolSelector = nullptr;
        return false;
    }

    mitaClient->addMessageHandler(commandHandler);
    mitaClient->addMessageHandler(pingHandler);

    // Configure QoS level (optional - defaults to WITH_ACK)
    // QoSLevel::NO_QOS = Fire-and-forget, no ACK, UDP-like (faster, no reliability)
    // QoSLevel::WITH_ACK = Wait for ACK with retry, MQTT-like (reliable, slower)
    mitaClient->setQoSLevel(QoSLevel::WITH_ACK); // Default: reliable delivery
    // mitaClient->setQoSLevel(QoSLevel::NO_QOS);  // Uncomment for faster, best-effort delivery

    ESP_LOGI(TAG, "%s", "Device initialized successfully");
    return true;
}

bool connectToNetwork()
{
    if (!mitaClient)
    {
        return false;
    }

    ESP_LOGI(TAG, "%s", "Attempting to connect to Mita network...");

    // Try WiFi first (auto-discovery)
    WiFiTransport *wifi_transport = new WiFiTransport(SHARED_SECRET);
    if (mitaClient->connectToNetwork(wifi_transport))
    {
        ESP_LOGI(TAG, "%s", "Connected via WiFi");
        return true;
    }

    delete wifi_transport;
    ESP_LOGI(TAG, "%s", "WiFi connection failed, trying BLE...");

    // Try BLE if WiFi fails
    BLETransport *ble_transport = new BLETransport(DEVICE_ID, ROUTER_ID);
    if (mitaClient->connectToNetwork(ble_transport))
    {
        ESP_LOGI(TAG, "%s", "Connected via BLE");
        return true;
    }

    delete ble_transport;
    ESP_LOGI(TAG, "%s", "All connection methods failed");
    return false;
}

bool connectToNetworkSmart()
{
    if (!mitaClient || !protocolSelector)
    {
        ESP_LOGI(TAG, "%s", "ERROR: MitaClient or ProtocolSelector not initialized");
        return false;
    }

    ESP_LOGI(TAG, "%s", );
    ESP_LOGI(TAG, "%s", "========================================");
    ESP_LOGI(TAG, "%s", "   Smart Protocol Selection");
    ESP_LOGI(TAG, "%s", "========================================");

    // Show current statistics
    protocolSelector->printStats();

    // Use smart connection method
    bool connected = mitaClient->connectToNetworkSmart(protocolSelector, SHARED_SECRET);

    if (connected)
    {
        ESP_LOGI(TAG, "%s", "========================================");
        ESP_LOGI(TAG, "%s", "   Connection Successful!");
        ESP_LOGI(TAG, "%s", "========================================");
    }
    else
    {
        ESP_LOGI(TAG, "%s", "========================================");
        ESP_LOGI(TAG, "%s", "   Connection Failed");
        ESP_LOGI(TAG, "%s", "========================================");
    }

    return connected;
}

void printStatus()
{
    if (!mitaClient)
    {
        ESP_LOGI(TAG, "%s", "Device not initialized");
        return;
    }

    ESP_LOGI(TAG, "%s", );
    ESP_LOGI(TAG, "%s", "=== Device Status ===");
    ESP_LOGI(TAG, "Device ID: %s", mitaClient->getDeviceId().c_str());
    ESP_LOGI(TAG, "Network Address: 0x%04X", mitaClient->getAssignedAddress());
    ESP_LOGI(TAG, "Transport: %s", mitaClient->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
    ESP_LOGI(TAG, "Connected: %s", mitaClient->isConnected() ? "Yes" : "No");
    ESP_LOGI(TAG, "Uptime: %lu seconds", ((unsigned long)(esp_timer_get_time() / 1000ULL)) / 1000);
    ESP_LOGI(TAG, "Free Heap: %u bytes", esp_get_free_heap_size());
    ESP_LOGI(TAG, "====================");
}
