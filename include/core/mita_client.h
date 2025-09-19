#ifndef MITA_CLIENT_H
#define MITA_CLIENT_H

#include <Arduino.h>
#include <ArduinoJson.h>
#include "../common/transport_interface.h"
#include "../crypto/crypto_service.h"
#include "../messaging/message_handler.h"
#include "../common/protocol_types.h"

class MitaClient
{
private:
    // Core components
    ITransport *transport;
    CryptoService crypto_service;
    MessageDispatcher message_dispatcher;

    // Configuration
    NetworkConfig network_config;
    uint16_t assigned_address;

    // State
    bool handshake_completed;
    uint32_t nonce1;
    uint32_t nonce2;

    // Timing
    unsigned long last_heartbeat;
    unsigned long last_sensor_reading;
    static const unsigned long HEARTBEAT_INTERVAL = 30000;
    static const unsigned long SENSOR_INTERVAL = 10000;

    // Handshake methods
    bool performHandshake();
    bool sendHello();
    bool receiveChallenge();
    bool sendAuth();
    bool receiveAuthAck();

    // Message handling
    void handleIncomingMessages();
    bool sendEncryptedMessage(uint16_t dest_addr, const String &message);

    // Utility methods
    String generateSensorData();
    void printConnectionStatus();

public:
    MitaClient(const NetworkConfig &config);
    ~MitaClient();

    // Main lifecycle methods
    bool initialize();
    bool connectToNetwork(ITransport *transport_impl);
    void disconnect();
    void update();

    // Status methods
    bool isConnected() const;
    TransportType getTransportType() const;
    uint16_t getAssignedAddress() const;
    String getDeviceId() const;

    // Messaging methods
    bool sendHeartbeat();
    bool sendSensorData();

    // Configuration
    void setNetworkConfig(const NetworkConfig &config);
    bool addMessageHandler(IMessageHandler *handler);
};

#endif // MITA_CLIENT_H