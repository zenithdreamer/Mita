#include "../../include/transport/protocol_selector.h"
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEScan.h>

ProtocolSelector::ProtocolSelector(const String& device_id, SelectionStrategy strategy)
    : device_id(device_id), strategy(strategy), persist_stats(true)
{
    // Initialize stats to zero
    memset(&wifi_stats, 0, sizeof(ConnectionStats));
    memset(&ble_stats, 0, sizeof(ConnectionStats));

    // Load historical stats from NVRAM if persistence is enabled
    if (persist_stats) {
        loadStatsFromNVRAM();
    }

    Serial.printf("ProtocolSelector: Initialized for device %s\n", device_id.c_str());
    Serial.printf("ProtocolSelector: Strategy = %d\n", (int)strategy);
}

ProtocolSelector::~ProtocolSelector()
{
    if (persist_stats) {
        saveStatsToNVRAM();
    }
}

void ProtocolSelector::loadStatsFromNVRAM()
{
    prefs.begin("mita_proto", false);  // Read-write mode

    // Load WiFi stats
    wifi_stats.success_count = prefs.getUInt("wifi_success", 0);
    wifi_stats.failure_count = prefs.getUInt("wifi_fail", 0);
    wifi_stats.total_attempts = prefs.getUInt("wifi_total", 0);
    wifi_stats.avg_connect_time_ms = prefs.getInt("wifi_time", 0);
    wifi_stats.last_signal_strength = prefs.getInt("wifi_rssi", -100);
    wifi_stats.last_success_time = prefs.getULong("wifi_last", 0);

    // Load BLE stats
    ble_stats.success_count = prefs.getUInt("ble_success", 0);
    ble_stats.failure_count = prefs.getUInt("ble_fail", 0);
    ble_stats.total_attempts = prefs.getUInt("ble_total", 0);
    ble_stats.avg_connect_time_ms = prefs.getInt("ble_time", 0);
    ble_stats.last_signal_strength = prefs.getInt("ble_sig", -100);
    ble_stats.last_success_time = prefs.getULong("ble_last", 0);

    prefs.end();

    Serial.println("ProtocolSelector: Loaded stats from NVRAM");
    printStats();
}

void ProtocolSelector::saveStatsToNVRAM()
{
    prefs.begin("mita_proto", false);

    // Save WiFi stats
    prefs.putUInt("wifi_success", wifi_stats.success_count);
    prefs.putUInt("wifi_fail", wifi_stats.failure_count);
    prefs.putUInt("wifi_total", wifi_stats.total_attempts);
    prefs.putInt("wifi_time", wifi_stats.avg_connect_time_ms);
    prefs.putInt("wifi_rssi", wifi_stats.last_signal_strength);
    prefs.putULong("wifi_last", wifi_stats.last_success_time);

    // Save BLE stats
    prefs.putUInt("ble_success", ble_stats.success_count);
    prefs.putUInt("ble_fail", ble_stats.failure_count);
    prefs.putUInt("ble_total", ble_stats.total_attempts);
    prefs.putInt("ble_time", ble_stats.avg_connect_time_ms);
    prefs.putInt("ble_sig", ble_stats.last_signal_strength);
    prefs.putULong("ble_last", ble_stats.last_success_time);

    prefs.end();

    Serial.println("ProtocolSelector: Saved stats to NVRAM");
}

void ProtocolSelector::updateStats(TransportType type, bool success, int connect_time_ms, int signal_strength)
{
    ConnectionStats* stats = (type == TRANSPORT_WIFI) ? &wifi_stats : &ble_stats;

    stats->total_attempts++;

    if (success) {
        stats->success_count++;
        stats->last_success_time = millis();
        stats->last_signal_strength = signal_strength;

        // Update average connection time (exponential moving average)
        if (stats->avg_connect_time_ms == 0) {
            stats->avg_connect_time_ms = connect_time_ms;
        } else {
            // EMA with alpha = 0.3 (30% new value, 70% old value)
            stats->avg_connect_time_ms = (connect_time_ms * 3 + stats->avg_connect_time_ms * 7) / 10;
        }
    } else {
        stats->failure_count++;
    }

    // Persist after every update
    if (persist_stats) {
        saveStatsToNVRAM();
    }
}

int ProtocolSelector::quickScanWiFi()
{
    Serial.println("ProtocolSelector: Quick WiFi scan...");

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(50);

    // Quick scan (async=false, show_hidden=true)
    int networks = WiFi.scanNetworks(false, true);

    if (networks == -1) {
        Serial.println("ProtocolSelector: WiFi scan failed");
        return -1;
    }

    Serial.printf("ProtocolSelector: Found %d WiFi networks\n", networks);

    // Look for Mita router networks
    String patterns[] = {"Mita_Router", "Mita_Network"};
    int best_rssi = -100;

    for (int i = 0; i < networks; i++) {
        String ssid = WiFi.SSID(i);
        int rssi = WiFi.RSSI(i);

        for (const String& pattern : patterns) {
            if (ssid.indexOf(pattern) >= 0) {
                Serial.printf("ProtocolSelector:   Found %s with RSSI %d dBm\n", ssid.c_str(), rssi);
                if (rssi > best_rssi) {
                    best_rssi = rssi;
                }
            }
        }
    }

    WiFi.scanDelete();

    if (best_rssi > -100) {
        Serial.printf("ProtocolSelector: WiFi available (RSSI: %d dBm)\n", best_rssi);
        return best_rssi;
    }

    Serial.println("ProtocolSelector: No Mita WiFi networks found");
    return -1;
}

int ProtocolSelector::quickScanBLE()
{
    Serial.println("ProtocolSelector: Quick BLE scan...");

    // Initialize BLE if not already done
    if (!BLEDevice::getInitialized()) {
        BLEDevice::init(device_id.c_str());
    }

    BLEScan* pBLEScan = BLEDevice::getScan();
    pBLEScan->setActiveScan(false);  // Passive scan is faster
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(50);

    // Quick 2-second scan
    BLEScanResults results = pBLEScan->start(2, false);
    int count = results.getCount();

    Serial.printf("ProtocolSelector: Found %d BLE devices\n", count);

    int best_rssi = -100;
    for (int i = 0; i < count; i++) {
        BLEAdvertisedDevice device = results.getDevice(i);
        String name = device.getName().c_str();

        // Look for Mita router or known BLE patterns
        if (name.indexOf("Mita") >= 0 || name.indexOf("Router") >= 0) {
            int rssi = device.getRSSI();
            Serial.printf("ProtocolSelector:   Found %s with RSSI %d dBm\n", name.c_str(), rssi);
            if (rssi > best_rssi) {
                best_rssi = rssi;
            }
        }
    }

    pBLEScan->clearResults();

    if (best_rssi > -100) {
        Serial.printf("ProtocolSelector: BLE available (RSSI: %d dBm)\n", best_rssi);
        return best_rssi;
    }

    Serial.println("ProtocolSelector: No Mita BLE devices found");
    return -1;
}

float ProtocolSelector::calculateScore(const ConnectionStats& stats, int current_signal) const
{
    float score = 0.0f;

    // Factor 1: Success rate (0-40 points)
    score += stats.getSuccessRate() * 40.0f;

    // Factor 2: Recency (0-30 points)
    if (stats.isRecentlySuccessful(millis(), 300000)) {  // Last 5 minutes
        score += 30.0f;
    } else if (stats.isRecentlySuccessful(millis(), 3600000)) {  // Last hour
        score += 15.0f;
    }

    // Factor 3: Signal strength (0-20 points)
    // WiFi: -30 dBm = excellent (20), -90 dBm = poor (0)
    // BLE: Similar scale
    if (current_signal > -100) {
        float signal_score = ((current_signal + 100.0f) / 70.0f) * 20.0f;
        score += constrain(signal_score, 0.0f, 20.0f);
    }

    // Factor 4: Connection speed (0-10 points)
    // Faster connection = better score
    if (stats.avg_connect_time_ms > 0) {
        float speed_score = 10.0f - (stats.avg_connect_time_ms / 1000.0f);
        score += constrain(speed_score, 0.0f, 10.0f);
    }

    return score;
}

TransportType ProtocolSelector::selectBestProtocol()
{
    Serial.printf("ProtocolSelector: Selecting protocol (strategy=%d)\n", (int)strategy);

    switch (strategy) {
        case SelectionStrategy::PREFER_WIFI:
            Serial.println("ProtocolSelector: Strategy PREFER_WIFI - trying WiFi first");
            return TRANSPORT_WIFI;

        case SelectionStrategy::PREFER_BLE:
            Serial.println("ProtocolSelector: Strategy PREFER_BLE - trying BLE first");
            return TRANSPORT_BLE;

        case SelectionStrategy::LAST_SUCCESSFUL: {
            unsigned long current_time = millis();

            // Use whichever worked most recently
            if (wifi_stats.last_success_time > ble_stats.last_success_time) {
                Serial.println("ProtocolSelector: Strategy LAST_SUCCESSFUL - WiFi was last successful");
                return TRANSPORT_WIFI;
            } else if (ble_stats.last_success_time > 0) {
                Serial.println("ProtocolSelector: Strategy LAST_SUCCESSFUL - BLE was last successful");
                return TRANSPORT_BLE;
            } else {
                Serial.println("ProtocolSelector: Strategy LAST_SUCCESSFUL - no history, defaulting to WiFi");
                return TRANSPORT_WIFI;
            }
        }

        case SelectionStrategy::FASTEST: {
            // Choose protocol with fastest average connection time
            if (wifi_stats.avg_connect_time_ms == 0 && ble_stats.avg_connect_time_ms == 0) {
                Serial.println("ProtocolSelector: Strategy FASTEST - no history, defaulting to WiFi");
                return TRANSPORT_WIFI;
            }

            if (wifi_stats.avg_connect_time_ms == 0) {
                Serial.println("ProtocolSelector: Strategy FASTEST - only BLE has history");
                return TRANSPORT_BLE;
            }

            if (ble_stats.avg_connect_time_ms == 0) {
                Serial.println("ProtocolSelector: Strategy FASTEST - only WiFi has history");
                return TRANSPORT_WIFI;
            }

            if (wifi_stats.avg_connect_time_ms < ble_stats.avg_connect_time_ms) {
                Serial.printf("ProtocolSelector: Strategy FASTEST - WiFi (%dms) faster than BLE (%dms)\n",
                             wifi_stats.avg_connect_time_ms, ble_stats.avg_connect_time_ms);
                return TRANSPORT_WIFI;
            } else {
                Serial.printf("ProtocolSelector: Strategy FASTEST - BLE (%dms) faster than WiFi (%dms)\n",
                             ble_stats.avg_connect_time_ms, wifi_stats.avg_connect_time_ms);
                return TRANSPORT_BLE;
            }
        }

        case SelectionStrategy::STRONGEST_SIGNAL: {
            // Quick scan both protocols and choose stronger signal
            int wifi_signal = quickScanWiFi();
            int ble_signal = quickScanBLE();

            if (wifi_signal == -1 && ble_signal == -1) {
                Serial.println("ProtocolSelector: Strategy STRONGEST_SIGNAL - neither available, trying WiFi");
                return TRANSPORT_WIFI;
            }

            if (wifi_signal > ble_signal) {
                Serial.printf("ProtocolSelector: Strategy STRONGEST_SIGNAL - WiFi (%d dBm) stronger\n", wifi_signal);
                return TRANSPORT_WIFI;
            } else {
                Serial.printf("ProtocolSelector: Strategy STRONGEST_SIGNAL - BLE (%d dBm) stronger\n", ble_signal);
                return TRANSPORT_BLE;
            }
        }

        case SelectionStrategy::ADAPTIVE:
        default: {
            Serial.println("ProtocolSelector: Strategy ADAPTIVE - analyzing best option");

            // Scan for current availability and signal strength
            int wifi_signal = quickScanWiFi();
            int ble_signal = quickScanBLE();

            // If neither is available, default to WiFi and let fallback handle it
            if (wifi_signal == -1 && ble_signal == -1) {
                Serial.println("ProtocolSelector: No protocols available - defaulting to WiFi");
                return TRANSPORT_WIFI;
            }

            // If only one is available, use it
            if (wifi_signal == -1) {
                Serial.println("ProtocolSelector: Only BLE available");
                return TRANSPORT_BLE;
            }
            if (ble_signal == -1) {
                Serial.println("ProtocolSelector: Only WiFi available");
                return TRANSPORT_WIFI;
            }

            // Both available - calculate scores
            float wifi_score = calculateScore(wifi_stats, wifi_signal);
            float ble_score = calculateScore(ble_stats, ble_signal);

            Serial.printf("ProtocolSelector: WiFi score=%.1f, BLE score=%.1f\n", wifi_score, ble_score);

            // Use the protocol with higher score
            if (wifi_score >= ble_score) {
                Serial.println("ProtocolSelector: Selected WiFi (higher score)");
                return TRANSPORT_WIFI;
            } else {
                Serial.println("ProtocolSelector: Selected BLE (higher score)");
                return TRANSPORT_BLE;
            }
        }
    }
}

void ProtocolSelector::getProtocolPriority(TransportType* priority_list, size_t& count)
{
    TransportType primary = selectBestProtocol();

    priority_list[0] = primary;
    priority_list[1] = (primary == TRANSPORT_WIFI) ? TRANSPORT_BLE : TRANSPORT_WIFI;
    count = 2;

    Serial.printf("ProtocolSelector: Priority order: %s, %s\n",
                  (priority_list[0] == TRANSPORT_WIFI) ? "WiFi" : "BLE",
                  (priority_list[1] == TRANSPORT_WIFI) ? "WiFi" : "BLE");
}

void ProtocolSelector::reportConnectionAttempt(TransportType type, bool success,
                                               int connect_time_ms, int signal_strength)
{
    const char* type_str = (type == TRANSPORT_WIFI) ? "WiFi" : "BLE";
    Serial.printf("ProtocolSelector: %s connection %s (time=%dms, signal=%d)\n",
                  type_str, success ? "SUCCESS" : "FAILED", connect_time_ms, signal_strength);

    updateStats(type, success, connect_time_ms, signal_strength);
}

void ProtocolSelector::setStrategy(SelectionStrategy new_strategy)
{
    strategy = new_strategy;
    Serial.printf("ProtocolSelector: Strategy changed to %d\n", (int)strategy);
}

void ProtocolSelector::resetStats()
{
    memset(&wifi_stats, 0, sizeof(ConnectionStats));
    memset(&ble_stats, 0, sizeof(ConnectionStats));

    if (persist_stats) {
        saveStatsToNVRAM();
    }

    Serial.println("ProtocolSelector: Stats reset");
}

void ProtocolSelector::forceProtocol(TransportType type)
{
    if (type == TRANSPORT_WIFI) {
        setStrategy(SelectionStrategy::PREFER_WIFI);
    } else {
        setStrategy(SelectionStrategy::PREFER_BLE);
    }
}

void ProtocolSelector::printStats() const
{
    Serial.println("========================================");
    Serial.println("   Protocol Selection Statistics");
    Serial.println("========================================");

    Serial.println("WiFi:");
    Serial.printf("  Success: %u/%u (%.1f%%)\n",
                  wifi_stats.success_count, wifi_stats.total_attempts,
                  wifi_stats.getSuccessRate() * 100.0f);
    Serial.printf("  Avg Connect Time: %d ms\n", wifi_stats.avg_connect_time_ms);
    Serial.printf("  Last Signal: %d dBm\n", wifi_stats.last_signal_strength);
    Serial.printf("  Last Success: %lu ms ago\n",
                  wifi_stats.last_success_time > 0 ? millis() - wifi_stats.last_success_time : 0);

    Serial.println("\nBLE:");
    Serial.printf("  Success: %u/%u (%.1f%%)\n",
                  ble_stats.success_count, ble_stats.total_attempts,
                  ble_stats.getSuccessRate() * 100.0f);
    Serial.printf("  Avg Connect Time: %d ms\n", ble_stats.avg_connect_time_ms);
    Serial.printf("  Last Signal: %d dBm\n", ble_stats.last_signal_strength);
    Serial.printf("  Last Success: %lu ms ago\n",
                  ble_stats.last_success_time > 0 ? millis() - ble_stats.last_success_time : 0);

    Serial.println("========================================");
}
