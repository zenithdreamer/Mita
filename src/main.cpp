/**
 * Mita - ESP32 Client Firmware
 */

#include <Arduino.h>
#include "core/mita_client.h"
#include "transport/wifi_transport.h"
#include "transport/ble_transport.h"
#include "transport/protocol_selector.h"
#include "messaging/message_handler.h"
#include "../shared/config/mita_config.h"

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
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

void setup()
{
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("================================================");
    Serial.println("       Mita - ESP32 Client");
    Serial.println("================================================");
    Serial.printf("Device ID: %s\n", DEVICE_ID);
    Serial.printf("Router ID: %s\n", ROUTER_ID);
    Serial.println();

    if (!initializeDevice())
    {
        Serial.println("ERROR: Failed to initialize device");
        return;
    }

    // Use smart protocol selection
    if (connectToNetworkSmart())
    {
        Serial.println("Successfully connected to Mita network!");
        printStatus();
    }
    else
    {
        Serial.println("Failed to connect to network");
    }

    Serial.println("Setup complete");
    Serial.println();
}

void loop()
{
    if (!mitaClient)
    {
        delay(1000);
        return;
    }

    // Check network connection and attempt reconnection if needed
    if (!mitaClient->isConnected())
    {
        static unsigned long last_reconnect_attempt = 0;
        unsigned long current_time = millis();

        if (current_time - last_reconnect_attempt >= MITA_RECONNECT_INTERVAL_MS)
        { // Try reconnecting at configured interval
            Serial.println("Connection lost, attempting smart reconnect...");
            if (connectToNetworkSmart())
            {
                Serial.println("Reconnected to network!");
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

    delay(100);
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
        Serial.println("Failed to create MitaClient instance");
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
        Serial.println("Failed to create ProtocolSelector instance");
        delete mitaClient;
        mitaClient = nullptr;
        return false;
    }

    // Create and register message handlers
    commandHandler = new CommandHandler(DEVICE_ID);
    pingHandler = new PingHandler(DEVICE_ID);

    if (!commandHandler || !pingHandler)
    {
        Serial.println("Failed to create message handlers");
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

    Serial.println("Device initialized successfully");
    return true;
}

bool connectToNetwork()
{
    if (!mitaClient)
    {
        return false;
    }

    Serial.println("Attempting to connect to Mita network...");

    // Try WiFi first (auto-discovery)
    WiFiTransport *wifi_transport = new WiFiTransport(SHARED_SECRET);
    if (mitaClient->connectToNetwork(wifi_transport))
    {
        Serial.println("Connected via WiFi");
        return true;
    }

    delete wifi_transport;
    Serial.println("WiFi connection failed, trying BLE...");

    // Try BLE if WiFi fails
    BLETransport *ble_transport = new BLETransport(DEVICE_ID, ROUTER_ID);
    if (mitaClient->connectToNetwork(ble_transport))
    {
        Serial.println("Connected via BLE");
        return true;
    }

    delete ble_transport;
    Serial.println("All connection methods failed");
    return false;
}

bool connectToNetworkSmart()
{
    if (!mitaClient || !protocolSelector)
    {
        Serial.println("ERROR: MitaClient or ProtocolSelector not initialized");
        return false;
    }

    Serial.println();
    Serial.println("========================================");
    Serial.println("   Smart Protocol Selection");
    Serial.println("========================================");

    // Show current statistics
    protocolSelector->printStats();

    // Use smart connection method
    bool connected = mitaClient->connectToNetworkSmart(protocolSelector, SHARED_SECRET);

    if (connected)
    {
        Serial.println("========================================");
        Serial.println("   Connection Successful!");
        Serial.println("========================================");
    }
    else
    {
        Serial.println("========================================");
        Serial.println("   Connection Failed");
        Serial.println("========================================");
    }

    return connected;
}

void printStatus()
{
    if (!mitaClient)
    {
        Serial.println("Device not initialized");
        return;
    }

    Serial.println();
    Serial.println("=== Device Status ===");
    Serial.printf("Device ID: %s\n", mitaClient->getDeviceId().c_str());
    Serial.printf("Network Address: 0x%04X\n", mitaClient->getAssignedAddress());
    Serial.printf("Transport: %s\n", mitaClient->getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
    Serial.printf("Connected: %s\n", mitaClient->isConnected() ? "Yes" : "No");
    Serial.printf("Uptime: %lu seconds\n", millis() / 1000);
    Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());

    if (mitaClient->getTransportType() == TRANSPORT_WIFI && WiFi.status() == WL_CONNECTED)
    {
        Serial.printf("WiFi RSSI: %d dBm\n", WiFi.RSSI());
        Serial.printf("Local IP: %s\n", WiFi.localIP().toString().c_str());
    }

    Serial.println("====================");
    Serial.println();
}
