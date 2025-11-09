/**
 * Mita SDK Demo - Controller
 *
 * This ESP32 acts as a controller that sends toggle commands to the LED device
 * when a button is pressed.
 *
 * Hardware:
 * - Button on GPIO (default: GPIO0 - boot button)
 * - Optional LED for status feedback (default: GPIO2)
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

static const char *TAG = "DEMO_CONTROLLER";

// Configuration from build flags (or defaults)
#ifndef DEVICE_ID
#define DEVICE_ID "CONTROLLER"
#endif

#ifndef BUTTON_GPIO
#define BUTTON_GPIO 0  // Boot button on most ESP32 boards
#endif

#ifndef LED_GPIO
#define LED_GPIO 2  // Onboard LED on most ESP32 boards
#endif

// Button debounce
#define BUTTON_DEBOUNCE_MS 50
static uint32_t last_button_press = 0;
static bool button_pressed = false;

// LED state
static bool status_led_state = false;

/**
 * Get destination address based on current address
 * If 0x0001, send to 0x0002
 * If 0x0002, send to 0x0001
 * Else, send to broadcast (0xFFFF)
 */
uint16_t getDestinationAddress(uint16_t current_address) {
    if (current_address == 0x0001) {
        return 0x0002;
    } else if (current_address == 0x0002) {
        return 0x0001;
    } else {
        return BROADCAST_ADDRESS;
    }
}

/**
 * Button interrupt handler
 */
static void IRAM_ATTR button_isr_handler(void* arg) {
    uint32_t current_time = esp_timer_get_time() / 1000;
    if (current_time - last_button_press > BUTTON_DEBOUNCE_MS) {
        button_pressed = true;
        last_button_press = current_time;
    }
}

/**
 * Initialize GPIO for button and LED
 */
void initGPIO() {
    // Configure button with pull-up (active low)
    gpio_config_t button_conf = {};
    button_conf.intr_type = GPIO_INTR_NEGEDGE;  // Trigger on falling edge
    button_conf.mode = GPIO_MODE_INPUT;
    button_conf.pin_bit_mask = (1ULL << BUTTON_GPIO);
    button_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    button_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    gpio_config(&button_conf);

    // Install GPIO ISR service
    gpio_install_isr_service(0);
    gpio_isr_handler_add((gpio_num_t)BUTTON_GPIO, button_isr_handler, NULL);

    // Configure status LED
    gpio_set_direction((gpio_num_t)LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level((gpio_num_t)LED_GPIO, 0);

    ESP_LOGI(TAG, "GPIO initialized - Button: GPIO%d, LED: GPIO%d", BUTTON_GPIO, LED_GPIO);
}

/**
 * Toggle status LED (visual feedback)
 */
void toggleStatusLED() {
    status_led_state = !status_led_state;
    gpio_set_level((gpio_num_t)LED_GPIO, status_led_state ? 1 : 0);
}

/**
 * Send toggle command to LED device
 */
void sendToggleCommand(MitaClient* client) {
    uint16_t my_address = client->getAssignedAddress();
    uint16_t dest_address = getDestinationAddress(my_address);

    // Create toggle command message (just the command, no device_id)
    DynamicJsonDocument doc(128);
    doc["type"] = "toggle_led";

    std::string json_str;
    serializeJson(doc, json_str);

    const char* dest_str = (dest_address == BROADCAST_ADDRESS) ? "BROADCAST" : "";
    ESP_LOGI(TAG, "Button pressed! Sending toggle command to 0x%04X %s", dest_address, dest_str);

    // Send the command
    if (client->sendData(json_str, dest_address)) {
        toggleStatusLED();  // Visual feedback
        ESP_LOGI(TAG, "Toggle command sent successfully");
    } else {
        ESP_LOGE(TAG, "Failed to send toggle command");
    }
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

    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "    Mita SDK Demo - Controller");
    ESP_LOGI(TAG, "================================================");
    ESP_LOGI(TAG, "Device ID: %s", DEVICE_ID);
    ESP_LOGI(TAG, "Router ID: %s", MITA_DEFAULT_ROUTER_ID);
    ESP_LOGI(TAG, "Button GPIO: %d", BUTTON_GPIO);
    ESP_LOGI(TAG, "Status LED GPIO: %d", LED_GPIO);
    ESP_LOGI(TAG, "================================================");

    // Initialize GPIO
    initGPIO();

    // Create network configuration
    NetworkConfig config;
    config.router_id = MITA_DEFAULT_ROUTER_ID;
    config.shared_secret = MITA_DEFAULT_SHARED_SECRET;
    config.device_id = DEVICE_ID;

    // Create and initialize client
    MitaClient* client = new MitaClient(config);
    if (!client || !client->initialize()) {
        ESP_LOGE(TAG, "Failed to initialize MitaClient");
        return;
    }

    // Create protocol selector (ADAPTIVE learns best protocol)
    ProtocolSelector* selector = new ProtocolSelector(DEVICE_ID, SelectionStrategy::ADAPTIVE);

    // Create message handlers
    CommandHandler* cmdHandler = new CommandHandler(DEVICE_ID);
    PingHandler* pingHandler = new PingHandler(DEVICE_ID);

    client->addMessageHandler(cmdHandler);
    client->addMessageHandler(pingHandler);

    // Set QoS level (with ACK for reliable delivery)
    client->setQoSLevel(QoSLevel::WITH_ACK);

    // Enable auto-reconnect
    client->setAutoReconnect(true, 5000);

    // Connect using smart protocol selection
    ESP_LOGI(TAG, "Connecting to Mita network...");

    if (!client->connectToNetworkSmart(selector, MITA_DEFAULT_SHARED_SECRET)) {
        ESP_LOGE(TAG, "Failed to connect to network");
        ESP_LOGI(TAG, "Auto-reconnect is enabled, waiting for connection...");
    } else {
        ESP_LOGI(TAG, "Successfully connected!");
        ESP_LOGI(TAG, "  Address: 0x%04X", client->getAssignedAddress());
        ESP_LOGI(TAG, "  Transport: %s", client->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
        ESP_LOGI(TAG, "================================================");
        ESP_LOGI(TAG, "Press the button to toggle the LED device!");
        ESP_LOGI(TAG, "================================================");
    }

    // Main loop
    while (1) {
        // Update client (handles messages, heartbeats, auto-reconnect)
        client->update();

        // Check for button press
        if (button_pressed && client->isConnected()) {
            button_pressed = false;
            sendToggleCommand(client);
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
