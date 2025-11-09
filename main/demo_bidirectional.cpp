/**
 * Mita SDK Demo - Bidirectional Communication
 *
 * This demo creates two identical ESP32 devices that can toggle each other's LEDs.
 * Each device:
 * - Has a button (GPIO0 - boot button)
 * - Has an LED (GPIO2 - onboard LED)
 * - When button pressed, sends toggle command to the OTHER device
 * - When receiving toggle command, toggles its OWN LED
 *
 *
 * Build for two devices:
 * - Device 1: DEVICE_ID="DEVICE_A" ADDRESS=0x0001
 * - Device 2: DEVICE_ID="DEVICE_B" ADDRESS=0x0002
 *
 * Hardware:
 * - Button: GPIO0 (boot button)
 * - LED: GPIO2 (onboard LED)
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

static const char *TAG = "DEMO_BIDIR";

// Configuration from build flags (or defaults)
#ifndef DEVICE_ID
#define DEVICE_ID "DEVICE_A"
#endif

#ifndef BUTTON_GPIO
#define BUTTON_GPIO 0 // Boot button
#endif

// Dual LED configuration (external + fallback)
#ifndef LED_GPIO_EXTERNAL
#define LED_GPIO_EXTERNAL 22 // D22 = GPIO22 (external LED)
#endif

#ifndef LED_GPIO_FALLBACK
#define LED_GPIO_FALLBACK 2 // GPIO2 (onboard LED fallback)
#endif

// Button debounce
#define BUTTON_DEBOUNCE_MS 300 // Increased to prevent accidental double-presses
static uint32_t last_button_press = 0;
static volatile bool button_pressed = false;

// LED state
static bool my_led_state = false;

// Global client reference for message handler
static MitaClient *g_client = nullptr;

/**
 * Get destination address based on current address
 * Device A (0x0001) → sends to Device B (0x0002)
 * Device B (0x0002) → sends to Device A (0x0001)
 */
uint16_t getDestinationAddress(uint16_t my_address)
{
    if (my_address == 0x0001)
    {
        return 0x0002;
    }
    else if (my_address == 0x0002)
    {
        return 0x0001;
    }
    else
    {
        // Unknown address - use broadcast
        return BROADCAST_ADDRESS;
    }
}

/**
 * Custom message handler for toggle commands
 * This handles incoming toggle requests from the other device
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
        ESP_LOGI(TAG, "Received toggle command from other device");

        // Toggle both LEDs (external + fallback)
        my_led_state = !my_led_state;
        gpio_set_level((gpio_num_t)LED_GPIO_EXTERNAL, my_led_state ? 1 : 0);
        gpio_set_level((gpio_num_t)LED_GPIO_FALLBACK, my_led_state ? 1 : 0);

        ESP_LOGI(TAG, "LEDs toggled: %s - GPIO%d (ext) + GPIO%d (fallback)",
                 my_led_state ? "ON" : "OFF", LED_GPIO_EXTERNAL, LED_GPIO_FALLBACK);

        // No need to send application-level ACK - protocol layer handles it automatically
        return true; // Message handled
    }
};

/**
 * Button interrupt handler
 */
static void IRAM_ATTR button_isr_handler(void *arg)
{
    uint32_t current_time = esp_timer_get_time() / 1000;
    if (current_time - last_button_press > BUTTON_DEBOUNCE_MS)
    {
        button_pressed = true;
        last_button_press = current_time;
    }
}

/**
 * Initialize GPIO for button and LED
 */
void initGPIO()
{
    // Configure button with pull-up (active low)
    gpio_config_t button_conf = {};
    button_conf.intr_type = GPIO_INTR_NEGEDGE; // Trigger on falling edge
    button_conf.mode = GPIO_MODE_INPUT;
    button_conf.pin_bit_mask = (1ULL << BUTTON_GPIO);
    button_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    button_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_config(&button_conf);

    // Install GPIO ISR service
    gpio_install_isr_service(0);
    gpio_isr_handler_add((gpio_num_t)BUTTON_GPIO, button_isr_handler, NULL);

    // Configure dual LEDs (output, initially off)
    gpio_set_direction((gpio_num_t)LED_GPIO_EXTERNAL, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)LED_GPIO_EXTERNAL, 0);

    gpio_set_direction((gpio_num_t)LED_GPIO_FALLBACK, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)LED_GPIO_FALLBACK, 0);

    ESP_LOGI(TAG, "GPIO initialized - Button: GPIO%d, LEDs: GPIO%d (ext) + GPIO%d (fallback)",
             BUTTON_GPIO, LED_GPIO_EXTERNAL, LED_GPIO_FALLBACK);
}

/**
 * Send toggle command to the OTHER device
 */
void sendToggleToOther(MitaClient *client)
{
    uint16_t my_address = client->getAssignedAddress();
    uint16_t dest_address = getDestinationAddress(my_address);

    // Create toggle command message
    DynamicJsonDocument doc(128);
    doc["type"] = "toggle_led";
    doc["from"] = DEVICE_ID;

    std::string json_str;
    serializeJson(doc, json_str);

    ESP_LOGI(TAG, "Button pressed! Sending toggle to other device (0x%04X)", dest_address);

    // Send the command
    if (client->sendData(json_str, dest_address))
    {
        ESP_LOGI(TAG, "Toggle command sent successfully");
    }
    else
    {
        ESP_LOGE(TAG, "Failed to send toggle command");
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
    ESP_LOGI(TAG, "  Mita SDK - Bidirectional Communication Demo");
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "Device ID: %s", DEVICE_ID);
    ESP_LOGI(TAG, "Router ID: %s", MITA_DEFAULT_ROUTER_ID);
    ESP_LOGI(TAG, "Button: GPIO%d (Press to toggle OTHER device)", BUTTON_GPIO);
    ESP_LOGI(TAG, "LED: GPIO%d (Toggles when OTHER presses button)", LED_GPIO);
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
    g_client = client; // Store global reference

    if (!client || !client->initialize())
    {
        ESP_LOGE(TAG, "Failed to initialize MitaClient");
        return;
    }

    // Create protocol selector with different preferences per device
    // DEVICE_A prefers WiFi, DEVICE_B prefers BLE
    ProtocolSelector *selector;

    std::string device_id_str(DEVICE_ID);
    if (device_id_str == "DEVICE_A")
    {
        selector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::PREFER_WIFI);
        ESP_LOGI(TAG, "Device A configured with WiFi preference");
    }
    else if (device_id_str == "DEVICE_B")
    {
        selector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::PREFER_BLE);
        ESP_LOGI(TAG, "Device B configured with BLE preference");
    }
    else
    {
        // Fallback to adaptive for unknown devices
        selector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::ADAPTIVE);
        ESP_LOGI(TAG, "Unknown device - using ADAPTIVE strategy");
    }

    // Create message handlers
    ToggleLEDHandler *toggleHandler = new ToggleLEDHandler(DEVICE_ID);
    CommandHandler *cmdHandler = new CommandHandler(DEVICE_ID);
    PingHandler *pingHandler = new PingHandler(DEVICE_ID);

    client->addMessageHandler(toggleHandler); // Handle incoming toggle commands
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
        uint16_t my_addr = client->getAssignedAddress();
        uint16_t other_addr = getDestinationAddress(my_addr);

        ESP_LOGI(TAG, "Successfully connected!");
        ESP_LOGI(TAG, "  Self Address: 0x%04X", my_addr);
        ESP_LOGI(TAG, "  Other Device: 0x%04X", other_addr);
        ESP_LOGI(TAG, "  Transport: %s", client->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
        ESP_LOGI(TAG, "================================================");
        ESP_LOGI(TAG, "Press button to toggle OTHER device's LED");
        ESP_LOGI(TAG, "Incoming toggles will control SELF LED");
        ESP_LOGI(TAG, "================================================");
    }

    // Main loop
    while (1)
    {
        // Update client (handles messages, heartbeats, auto-reconnect)
        client->update();

        // Check for button press
        if (button_pressed && client->isConnected())
        {
            button_pressed = false;
            sendToggleToOther(client);
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
