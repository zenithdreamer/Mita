#ifndef MITA_CLIENT_H
#define MITA_CLIENT_H

#include <Arduino.h>
#include <ArduinoJson.h>
#include "../../shared/protocol/transport_interface.h"
#include "../crypto/crypto_service.h"
#include "../messaging/message_handler.h"
#include "../../shared/protocol/protocol_types.h"
#include "../transport/protocol_selector.h"

// QoS (Quality of Service) levels
enum class QoSLevel : uint8_t
{
    NO_QOS = 0,      // Fire-and-forget (UDP-like), no ACK expected
    WITH_ACK = 1     // Wait for ACK with retry (MQTT-like)
};

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
    uint8_t nonce1[NONCE_SIZE];
    uint8_t nonce2[NONCE_SIZE];
    
    // Session key rotation
    uint32_t packets_sent;                // Count packets since last rekey
    static const uint32_t REKEY_PACKET_THRESHOLD = 1000;  // Rekey after 1000 packets

    // Timestamp validation state (instance variables)
    uint64_t challenge_baseline_timestamp;
    unsigned long challenge_baseline_millis;

    // Timing
    unsigned long last_heartbeat;
    unsigned long last_sensor_reading;
    unsigned long last_ping_sent;      // For measuring RTT
    static const unsigned long HEARTBEAT_INTERVAL = 10000;
    static const unsigned long SENSOR_INTERVAL = 10000;

    // QoS configuration
    QoSLevel qos_level;
    static const unsigned long ACK_TIMEOUT_MS = 3000;  // Wait 3s for ACK
    static const uint8_t MAX_RETRIES = 3;              // Retry up to 3 times

    // Handshake methods
    bool performHandshake();
    bool sendHello();
    bool receiveChallenge();
    bool sendAuth();
    bool receiveAuthAck();
    
    // Control methods
    bool sendDisconnect(DisconnectReason reason);
    bool receiveDisconnectAck();
    bool performSessionRekey();  // Trigger session key rotation

    // Message handling
    void handleIncomingMessages();
    bool sendEncryptedMessage(uint16_t dest_addr, const String &message);
    bool sendEncryptedMessageWithQoS(uint16_t dest_addr, const String &message, QoSLevel qos);
    bool waitForAck(uint16_t expected_sequence);

    // Utility methods
    String generateSensorData();
    void printConnectionStatus();

public:
    MitaClient(const NetworkConfig &config);
    ~MitaClient();

    // Main lifecycle methods
    bool initialize();
    bool connectToNetwork(ITransport *transport_impl);
    bool connectToNetworkSmart(ProtocolSelector* selector, const String& shared_secret);  // Smart connection with protocol selection
    void disconnect();
    void disconnect(DisconnectReason reason);  // Graceful disconnect with reason
    void update();

    // Status methods
    bool isConnected() const;
    TransportType getTransportType() const;
    uint16_t getAssignedAddress() const;
    String getDeviceId() const;

    // Messaging methods
    bool sendHeartbeat();
    bool sendSensorData();
    bool sendPing();  // Send PING and measure round-trip time

    // Configuration
    void setNetworkConfig(const NetworkConfig &config);
    bool addMessageHandler(IMessageHandler *handler);
    void setQoSLevel(QoSLevel level);
    QoSLevel getQoSLevel() const;
};

#endif // MITA_CLIENT_H