#ifndef PROTOCOL_SELECTOR_H
#define PROTOCOL_SELECTOR_H

#include <Arduino.h>
#include <Preferences.h>
#include "../../shared/protocol/transport_interface.h"
#include "../../shared/protocol/protocol_types.h"

// Connection statistics for learning
struct ConnectionStats {
    uint32_t success_count;
    uint32_t failure_count;
    uint32_t total_attempts;
    int32_t avg_connect_time_ms;  // Average connection time
    int32_t last_signal_strength;  // RSSI for WiFi, BLE signal for BLE
    unsigned long last_success_time;  // millis() of last successful connection

    float getSuccessRate() const {
        if (total_attempts == 0) return 0.0f;
        return (float)success_count / (float)total_attempts;
    }

    bool isRecentlySuccessful(unsigned long current_time, unsigned long threshold_ms = 300000) const {
        // Consider connection recently successful if it worked in last 5 minutes
        return last_success_time > 0 && (current_time - last_success_time) < threshold_ms;
    }
};

// Protocol selection strategy
enum class SelectionStrategy {
    PREFER_WIFI,        // Always try WiFi first (default)
    PREFER_BLE,         // Always try BLE first
    ADAPTIVE,           // Learn from history and signal strength
    LAST_SUCCESSFUL,    // Use whatever worked last time
    FASTEST,            // Use protocol with fastest recent connection time
    STRONGEST_SIGNAL    // Use protocol with best signal strength
};

class ProtocolSelector {
private:
    Preferences prefs;
    String device_id;

    // Statistics for each protocol
    ConnectionStats wifi_stats;
    ConnectionStats ble_stats;

    // Configuration
    SelectionStrategy strategy;
    bool persist_stats;  // Save stats to NVRAM

    // Helper methods
    void loadStatsFromNVRAM();
    void saveStatsToNVRAM();
    void updateStats(TransportType type, bool success, int connect_time_ms, int signal_strength);
    int quickScanWiFi();  // Quick scan to check if WiFi is available, returns RSSI or -1
    int quickScanBLE();   // Quick scan to check if BLE is available, returns signal or -1
    float calculateScore(const ConnectionStats& stats, int current_signal) const;

public:
    ProtocolSelector(const String& device_id, SelectionStrategy strategy = SelectionStrategy::ADAPTIVE);
    ~ProtocolSelector();

    // Main selection method
    TransportType selectBestProtocol();

    // Get ordered list of protocols to try
    void getProtocolPriority(TransportType* priority_list, size_t& count);

    // Report connection results for learning
    void reportConnectionAttempt(TransportType type, bool success, int connect_time_ms = 0, int signal_strength = 0);

    // Configuration
    void setStrategy(SelectionStrategy strategy);
    SelectionStrategy getStrategy() const { return strategy; }
    void setPersistence(bool enable) { persist_stats = enable; }

    // Statistics access
    const ConnectionStats& getWiFiStats() const { return wifi_stats; }
    const ConnectionStats& getBLEStats() const { return ble_stats; }
    void resetStats();

    // Manual override for testing
    void forceProtocol(TransportType type);

    // Debugging
    void printStats() const;
};

#endif // PROTOCOL_SELECTOR_H
