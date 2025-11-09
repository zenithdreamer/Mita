/**
 * Mita SDK Demo - LED Device
 *
 * This ESP32 acts as an LED device that:
 * - Toggles LED when receiving toggle commands
 * - Broadcasts its status every 30 seconds
 *
 * Hardware:
 * - LED on GPIO (default: GPIO2 - onboard LED)
 */

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <nvs_flash.h>
#include <driver/gpio.h>
#include <ArduinoJson.h>

#include "core/mita_client.h"
#include "transport/wifi_transport.h"
#include "transport/ble_transport.h"
#include "transport/protocol_selector.h"
#include "messaging/message_handler.h"
#include "config/mita_config.h"
#include "protocol/protocol_types.h"

static const char *TAG = "DEMO_LED";

// Configuration from build flags (or defaults)
#ifndef DEVICE_ID
#define DEVICE_ID "LED"
#endif

#ifndef LED_GPIO
#define LED_GPIO 2 // Onboard LED on most ESP32 boards
#endif

// LED state
static bool led_state = false;

// Status broadcast interval
#define STATUS_BROADCAST_INTERVAL_MS 30000 // 30 seconds

/**
 * Custom message handler for toggle commands
 */
class ToggleLEDHandler : public IMessageHandler
{
private:
    const char *device_id;

public:
    ToggleLEDHandler(const char *dev_id) : device_id(dev_id) {}

    bool canHandle(const std::string &message_type) const override
    {
        return message_type == "toggle_led";
    }

    bool handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response) override
    {
        ESP_LOGI(TAG, "Received toggle command!");

        // Toggle LED
        led_state = !led_state;
        gpio_set_level((gpio_num_t)LED_GPIO, led_state ? 1 : 0);

        ESP_LOGI(TAG, "LED toggled: %s", led_state ? "ON" : "OFF");

        // Prepare response
        response["type"] = "toggle_ack";
        response["state"] = led_state;

        return true; // Message handled
    }
};

/**
 * Initialize GPIO for LED
 */
void initGPIO()
{
    // Configure LED
    gpio_set_direction((gpio_num_t)LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)LED_GPIO, 0);

    ESP_LOGI(TAG, "GPIO initialized - LED: GPIO%d", LED_GPIO);
}

/**
 * Broadcast current LED status
 */
void broadcastStatus(MitaClient *client)
{
    // Create status message (just type and state - address is in packet header)
    DynamicJsonDocument doc(64);
    doc["type"] = "led_status";
    doc["state"] = led_state;

    std::string json_str;
    serializeJson(doc, json_str);

    ESP_LOGI(TAG, "Broadcasting status: LED is %s", led_state ? "ON" : "OFF");

    // Send to broadcast address (address is in packet header)
    if (client->sendData(json_str, BROADCAST_ADDRESS))
    {
        ESP_LOGD(TAG, "Status broadcast sent successfully");
    }
    else
    {
        ESP_LOGE(TAG, "Failed to send status broadcast");
    }
}

extern "C" void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "    Mita SDK Demo - LED Device");
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "Device ID: %s", DEVICE_ID);
    ESP_LOGI(TAG, "Router ID: %s", MITA_DEFAULT_ROUTER_ID);
    ESP_LOGI(TAG, "LED GPIO: %d", LED_GPIO);
    ESP_LOGI(TAG, "================================================");

    // Initialize GPIO
    initGPIO();

    // Create network configuration
    NetworkConfig config;
    config.router_id = MITA_DEFAULT_ROUTER_ID;
    config.shared_secret = MITA_DEFAULT_SHARED_SECRET;
    config.device_id = DEVICE_ID;

    // Create and initialize client
    MitaClient *client = new MitaClient(config);
    if (!client || !client->initialize())
    {
        ESP_LOGE(TAG, "Failed to initialize MitaClient");
        return;
    }

    // Create protocol selector (ADAPTIVE learns best protocol)
    ProtocolSelector *selector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::ADAPTIVE);

    // Create message handlers
    ToggleLEDHandler *toggleHandler = new ToggleLEDHandler(DEVICE_ID);
    CommandHandler *cmdHandler = new CommandHandler(DEVICE_ID);
    PingHandler *pingHandler = new PingHandler(DEVICE_ID);

    client->addMessageHandler(toggleHandler); // Add toggle handler first
    client->addMessageHandler(cmdHandler);
    client->addMessageHandler(pingHandler);

    // Set QoS level (with ACK for reliable delivery)
    client->setQoSLevel(QoSLevel::WITH_ACK);

    // Enable auto-reconnect
    client->setAutoReconnect(true, 5000);

    // Connect using smart protocol selection
    ESP_LOGI(TAG, "Connecting to Mita network...");

    if (!client->connectToNetworkSmart(selector, MITA_DEFAULT_SHARED_SECRET))
    {
        ESP_LOGE(TAG, "Failed to connect to network");
        ESP_LOGI(TAG, "Auto-reconnect is enabled, waiting for connection...");
    }
    else
    {
        ESP_LOGI(TAG, "Successfully connected!");
        ESP_LOGI(TAG, "  Address: 0x%04X", client->getAssignedAddress());
        ESP_LOGI(TAG, "  Transport: %s", client->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
        ESP_LOGI(TAG, "================================================");
        ESP_LOGI(TAG, "Waiting for toggle commands...");
        ESP_LOGI(TAG, "Broadcasting status every %d seconds", STATUS_BROADCAST_INTERVAL_MS / 1000);
        ESP_LOGI(TAG, "================================================");
    }

    // Main loop - broadcast status every 30 seconds
    unsigned long last_status_broadcast = 0;

    while (1)
    {
        // Update client (handles messages, heartbeats, auto-reconnect)
        client->update();

        // Broadcast status periodically (only if connected)
        if (client->isConnected())
        {
            unsigned long current_time = (unsigned long)(esp_timer_get_time() / 1000ULL);
            if (current_time - last_status_broadcast >= STATUS_BROADCAST_INTERVAL_MS)
            {
                broadcastStatus(client);
                last_status_broadcast = current_time;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
