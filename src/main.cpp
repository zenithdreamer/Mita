/**
 * Multi-Protocol IoT Network - ESP32 Client Firmware
 * Main application that connects to the IoT router via WiFi or BLE
 * This code need big refactor and cleanup
 */

#include <Arduino.h>
#include "protocol.h"

// Define LED_BUILTIN for ESP32 if not already defined (i don't know but for some reason some boards may not define it)
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// Global objects
IoTProtocol iotProtocol;

// Configuration - these would normally be loaded from NVRAM or config file
const char *ROUTER_ID = "Mita_Router_1";
const char *SHARED_SECRET = "Mita_password";
const char *DEVICE_ID = "ESP32_Sensor_001";

// Network configuration - auto-discovered based on Router ID
IPAddress ROUTER_IP(10, 42, 0, 1); // AP gateway IP (Just placeholder, will be auto-discovered)
const uint16_t ROUTER_PORT = 8000;

// BLE configuration
const char *BLE_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc";
const char *BLE_CHAR_UUID = "12345678-1234-1234-1234-123456789abd";

// Application state
bool network_connected = false;
unsigned long last_heartbeat = 0;
unsigned long last_sensor_reading = 0;
const unsigned long HEARTBEAT_INTERVAL = 30000; // 30 seconds
const unsigned long SENSOR_INTERVAL = 10000;    // 10 seconds

// Function prototypes
bool connectToNetwork();
void sendHeartbeat();
void sendSensorData();
void handleIncomingMessages();
void printStatus();
String generateSensorData();
void handleCommand(DynamicJsonDocument &doc);
void handlePing(DynamicJsonDocument &doc);

void setup()
{
    Serial.begin(115200);
    delay(1000);

    Serial.println();
    Serial.println("================================================");
    Serial.println("  Multi-Protocol IoT Network - ESP32 Client");
    Serial.println("================================================");
    Serial.printf("Device ID: %s\n", DEVICE_ID);
    Serial.printf("Router ID: %s\n", ROUTER_ID);
    Serial.println();

    // Initialize the protocol
    if (!iotProtocol.loadConfig(ROUTER_ID, SHARED_SECRET, DEVICE_ID))
    {
        Serial.println("ERROR: Failed to load protocol configuration");
        return;
    }

    // Configure WiFi settings - auto-discovery will find SSID pattern based on Router ID
    iotProtocol.setWiFiConfig("", SHARED_SECRET, ROUTER_IP, ROUTER_PORT); // Empty SSID = auto-discover

    // Configure BLE settings
    iotProtocol.setBLEConfig(BLE_SERVICE_UUID, BLE_CHAR_UUID);

    Serial.println("Protocol initialized successfully");
    Serial.println("Attempting to connect to network...");

    // Connect to network
    network_connected = connectToNetwork();

    if (network_connected)
    {
        Serial.println("Successfully connected to IoT network!");
        Serial.printf("Assigned address: 0x%04X\n", iotProtocol.getAssignedAddress());
        Serial.printf("Transport: %s\n", iotProtocol.getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
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
    unsigned long current_time = millis();

    // Check network connection
    if (!iotProtocol.isConnected())
    {
        if (network_connected)
        {
            Serial.println("Network connection lost, attempting to reconnect...");
            network_connected = false;
        }

        // Try to reconnect
        if (current_time % 10000 == 0)
        { // Try every 10 seconds
            network_connected = connectToNetwork();
            if (network_connected)
            {
                Serial.println("Reconnected to network!");
                printStatus();
            }
        }
    }

    if (network_connected)
    {
        // Handle incoming messages
        handleIncomingMessages();

        // Send periodic heartbeat
        if (current_time - last_heartbeat >= HEARTBEAT_INTERVAL)
        {
            sendHeartbeat();
            last_heartbeat = current_time;
        }

        // Send sensor data
        if (current_time - last_sensor_reading >= SENSOR_INTERVAL)
        {
            sendSensorData();
            last_sensor_reading = current_time;
        }
    }

    delay(100);
}

bool connectToNetwork()
{
    Serial.println("Connecting to IoT network...");

    // Try to connect (will attempt WiFi first, then BLE)
    if (iotProtocol.connectToNetwork())
    {
        return true;
    }

    Serial.println("Failed to connect to network");
    return false;
}

void sendHeartbeat()
{
    Serial.println("Sending heartbeat...");

    DynamicJsonDocument doc(256);
    doc["type"] = "heartbeat";
    doc["device_id"] = DEVICE_ID;
    doc["timestamp"] = millis();
    doc["uptime"] = millis() / 1000;
    doc["free_heap"] = ESP.getFreeHeap();
    doc["transport"] = iotProtocol.getTransportType() == TRANSPORT_WIFI ? "wifi" : "ble";

    String message;
    serializeJson(doc, message);

    Serial.printf("Heartbeat message size: %d bytes\n", message.length());
    Serial.printf("Heartbeat content: %s\n", message.c_str());

    if (iotProtocol.sendMessage(ROUTER_ADDRESS, message))
    {
        Serial.println("Heartbeat sent successfully");
    }
    else
    {
        Serial.println("Failed to send heartbeat");
    }
}

void sendSensorData()
{
    Serial.println("Sending sensor data...");

    String sensorData = generateSensorData();

    Serial.printf("Sensor data message size: %d bytes\n", sensorData.length());
    Serial.printf("Sensor data content: %s\n", sensorData.c_str());

    if (iotProtocol.sendMessage(ROUTER_ADDRESS, sensorData))
    {
        Serial.println("Sensor data sent successfully");
    }
    else
    {
        Serial.println("Failed to send sensor data");
    }
}

String generateSensorData()
{
    DynamicJsonDocument doc(256);
    doc["type"] = "sensor_data";
    doc["device_id"] = DEVICE_ID;
    doc["timestamp"] = millis();

    // Some Mock sensor readings
    doc["temperature"] = 20.0 + (random(0, 200) / 10.0); // 20-40°C
    doc["humidity"] = 40.0 + (random(0, 400) / 10.0);    // 40-80%
    doc["pressure"] = 1000.0 + (random(0, 100) / 10.0);  // 1000-1010 hPa
    doc["light"] = random(0, 1024);                      // 0-1023 (ADC reading)

    String result;
    serializeJson(doc, result);
    return result;
}

void handleIncomingMessages()
{
    ProtocolPacket packet;

    // Check for incoming packets (non-blocking)
    if (iotProtocol.receivePacket(packet, 10))
    { // 10ms timeout
        Serial.printf("Received packet from 0x%04X: ", packet.source_addr);

        if (packet.msg_type == MSG_DATA)
        {
            // Decrypt and process data
            uint8_t decrypted[MAX_PAYLOAD_SIZE];
            unsigned int decrypted_length;

            if (iotProtocol.decryptPayload(packet.payload, packet.payload_length,
                                           decrypted, decrypted_length))
            {

                String message = String((char *)decrypted, decrypted_length);
                Serial.printf("DATA: %s\n", message.c_str());

                // Parse and handle message
                DynamicJsonDocument doc(256);
                DeserializationError error = deserializeJson(doc, message);

                if (!error)
                {
                    const char *type = doc["type"];

                    if (strcmp(type, "command") == 0)
                    {
                        handleCommand(doc);
                    }
                    else if (strcmp(type, "ping") == 0)
                    {
                        handlePing(doc);
                    }
                }
                else
                {
                    Serial.printf("Raw message: %s\n", message.c_str());
                }
            }
            else
            {
                Serial.println("Failed to decrypt payload");
            }
        }
        else
        {
            Serial.printf("Type: 0x%02X, Length: %d\n", packet.msg_type, packet.payload_length);
        }
    }
}

void handleCommand(DynamicJsonDocument &doc)
{
    const char *command = doc["command"];
    Serial.printf("Received command: %s\n", command);

    DynamicJsonDocument response(256);
    response["type"] = "command_response";
    response["device_id"] = DEVICE_ID;
    response["command"] = command;
    response["timestamp"] = millis();

    if (strcmp(command, "status") == 0)
    {
        response["status"] = "online";
        response["uptime"] = millis() / 1000;
        response["free_heap"] = ESP.getFreeHeap();
        response["transport"] = iotProtocol.getTransportType() == TRANSPORT_WIFI ? "wifi" : "ble";
        response["address"] = String(iotProtocol.getAssignedAddress(), HEX);
    }
    else if (strcmp(command, "restart") == 0)
    {
        response["status"] = "restarting";
        String responseMsg;
        serializeJson(response, responseMsg);
        iotProtocol.sendMessage(ROUTER_ADDRESS, responseMsg);
        delay(1000);
        ESP.restart();
    }
    else if (strcmp(command, "led_on") == 0)
    {
        digitalWrite(LED_BUILTIN, HIGH);
        response["status"] = "led_on";
    }
    else if (strcmp(command, "led_off") == 0)
    {
        digitalWrite(LED_BUILTIN, LOW);
        response["status"] = "led_off";
    }
    else
    {
        response["status"] = "unknown_command";
    }

    String responseMsg;
    serializeJson(response, responseMsg);
    iotProtocol.sendMessage(ROUTER_ADDRESS, responseMsg);
}

void handlePing(DynamicJsonDocument &doc)
{
    Serial.println("Received ping, sending pong");

    DynamicJsonDocument response(256);
    response["type"] = "pong";
    response["device_id"] = DEVICE_ID;
    response["timestamp"] = millis();
    response["ping_id"] = doc["ping_id"];

    String responseMsg;
    serializeJson(response, responseMsg);
    iotProtocol.sendMessage(ROUTER_ADDRESS, responseMsg);
}

void printStatus()
{
    Serial.println();
    Serial.println("=== Device Status ===");
    Serial.printf("Device ID: %s\n", iotProtocol.getDeviceId().c_str());
    Serial.printf("Network Address: 0x%04X\n", iotProtocol.getAssignedAddress());
    Serial.printf("Transport: %s\n", iotProtocol.getTransportType() == TRANSPORT_WIFI ? "WiFi" : "BLE");
    Serial.printf("Connected: %s\n", iotProtocol.isConnected() ? "Yes" : "No");
    Serial.printf("Uptime: %lu seconds\n", millis() / 1000);
    Serial.printf("Free Heap: %u bytes\n", ESP.getFreeHeap());

    if (iotProtocol.getTransportType() == TRANSPORT_WIFI)
    {
        Serial.printf("WiFi RSSI: %d dBm\n", WiFi.RSSI());
        Serial.printf("Local IP: %s\n", WiFi.localIP().toString().c_str());
    }

    Serial.println("====================");
    Serial.println();
}