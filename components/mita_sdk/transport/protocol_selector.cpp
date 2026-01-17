#include "../../include/transport/protocol_selector.h"
#include <esp_log.h>
#include <string.h>

static const char *TAG = "PROTOCOL_SELECTOR";

ProtocolSelector::ProtocolSelector(const std::string& device_id, SelectionStrategy strategy)
    : device_id(device_id), nvs_handle(0), strategy(strategy), persist_stats(true)
{
    memset(&wifi_stats, 0, sizeof(ConnectionStats));
    memset(&ble_stats, 0, sizeof(ConnectionStats));

    if (persist_stats) {
        loadStatsFromNVRAM();
    }

    ESP_LOGI(TAG, "ProtocolSelector initialized for device %s", device_id.c_str());
}

ProtocolSelector::~ProtocolSelector()
{
    if (persist_stats) {
        saveStatsToNVRAM();
    }
    if (nvs_handle) {
        nvs_close(nvs_handle);
    }
}

void ProtocolSelector::loadStatsFromNVRAM()
{
    esp_err_t err = nvs_open("mita_proto", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS: %d", err);
        return;
    }

    nvs_get_u32(nvs_handle, "wifi_success", &wifi_stats.success_count);
    nvs_get_u32(nvs_handle, "wifi_fail", &wifi_stats.failure_count);
    nvs_get_u32(nvs_handle, "wifi_total", &wifi_stats.total_attempts);
    nvs_get_i32(nvs_handle, "wifi_time", &wifi_stats.avg_connect_time_ms);
    nvs_get_i32(nvs_handle, "wifi_rssi", &wifi_stats.last_signal_strength);

    nvs_get_u32(nvs_handle, "ble_success", &ble_stats.success_count);
    nvs_get_u32(nvs_handle, "ble_fail", &ble_stats.failure_count);
    nvs_get_u32(nvs_handle, "ble_total", &ble_stats.total_attempts);
    nvs_get_i32(nvs_handle, "ble_time", &ble_stats.avg_connect_time_ms);
    nvs_get_i32(nvs_handle, "ble_sig", &ble_stats.last_signal_strength);
}

void ProtocolSelector::saveStatsToNVRAM()
{
    if (!nvs_handle) {
        esp_err_t err = nvs_open("mita_proto", NVS_READWRITE, &nvs_handle);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to open NVS for saving: %d", err);
            return;
        }
    }

    nvs_set_u32(nvs_handle, "wifi_success", wifi_stats.success_count);
    nvs_set_u32(nvs_handle, "wifi_fail", wifi_stats.failure_count);
    nvs_set_u32(nvs_handle, "wifi_total", wifi_stats.total_attempts);
    nvs_set_i32(nvs_handle, "wifi_time", wifi_stats.avg_connect_time_ms);
    nvs_set_i32(nvs_handle, "wifi_rssi", wifi_stats.last_signal_strength);

    nvs_set_u32(nvs_handle, "ble_success", ble_stats.success_count);
    nvs_set_u32(nvs_handle, "ble_fail", ble_stats.failure_count);
    nvs_set_u32(nvs_handle, "ble_total", ble_stats.total_attempts);
    nvs_set_i32(nvs_handle, "ble_time", ble_stats.avg_connect_time_ms);
    nvs_set_i32(nvs_handle, "ble_sig", ble_stats.last_signal_strength);

    nvs_commit(nvs_handle);
}

TransportType ProtocolSelector::selectBestProtocol()
{
    switch (strategy) {
    case SelectionStrategy::PREFER_WIFI:
        return TRANSPORT_WIFI;
    
    case SelectionStrategy::PREFER_BLE:
        return TRANSPORT_BLE;

    case SelectionStrategy::PREFER_LORA:
        return TRANSPORT_LORA;
    
    
    case SelectionStrategy::LAST_SUCCESSFUL:
        if (wifi_stats.last_success_time > ble_stats.last_success_time) {
            return TRANSPORT_WIFI;
        }
        return TRANSPORT_BLE;

    case SelectionStrategy::FASTEST:
        if (wifi_stats.avg_connect_time_ms < ble_stats.avg_connect_time_ms) {
            return TRANSPORT_WIFI;
        }
        return TRANSPORT_BLE;
    
    case SelectionStrategy::STRONGEST_SIGNAL:
        if (wifi_stats.last_signal_strength > ble_stats.last_signal_strength) {
            return TRANSPORT_WIFI;
        }
        return TRANSPORT_BLE;
    
    case SelectionStrategy::ADAPTIVE:
    default:
        float wifi_score = calculateScore(wifi_stats, wifi_stats.last_signal_strength);
        float ble_score = calculateScore(ble_stats, ble_stats.last_signal_strength);
        return (wifi_score > ble_score) ? TRANSPORT_WIFI : TRANSPORT_BLE;
    }
}

void ProtocolSelector::getProtocolPriority(TransportType* priority_list, size_t& count)
{
    TransportType best = selectBestProtocol();
    priority_list[0] = best;
    priority_list[1] = (best == TRANSPORT_WIFI) ? TRANSPORT_BLE : TRANSPORT_WIFI;
    count = 2;
}

void ProtocolSelector::updateStats(TransportType type, bool success, int connect_time_ms, int signal_strength)
{
    ConnectionStats* stats = (type == TRANSPORT_WIFI) ? &wifi_stats : &ble_stats;
    
    stats->total_attempts++;
    
    if (success) {
        stats->success_count++;
        stats->last_success_time = millis();
        
        if (stats->avg_connect_time_ms == 0) {
            stats->avg_connect_time_ms = connect_time_ms;
        } else {
            stats->avg_connect_time_ms = (stats->avg_connect_time_ms * 7 + connect_time_ms) / 8;
        }
    } else {
        stats->failure_count++;
    }
    
    stats->last_signal_strength = signal_strength;
    
    if (persist_stats) {
        saveStatsToNVRAM();
    }
}

int ProtocolSelector::quickScanWiFi()
{
    return -1;
}

int ProtocolSelector::quickScanBLE()
{
    return -1;
}

float ProtocolSelector::calculateScore(const ConnectionStats& stats, int current_signal) const
{
    float score = 0.0f;
    score += stats.getSuccessRate() * 40.0f;
    
    if (stats.isRecentlySuccessful(millis(), 300000)) {
        score += 20.0f;
    }
    
    float signal_norm = (current_signal + 100) / 100.0f;
    score += signal_norm * 20.0f;
    
    if (stats.avg_connect_time_ms > 0) {
        float speed_score = 1.0f - (stats.avg_connect_time_ms / 10000.0f);
        if (speed_score < 0) speed_score = 0;
        score += speed_score * 20.0f;
    }
    
    return score;
}

void ProtocolSelector::printStats()
{
    ESP_LOGI(TAG, "=== Protocol Statistics ===");
    ESP_LOGI(TAG, "WiFi: Success=%lu/%lu (%.1f%%)", wifi_stats.success_count, wifi_stats.total_attempts, wifi_stats.getSuccessRate() * 100.0f);
    ESP_LOGI(TAG, "BLE: Success=%lu/%lu (%.1f%%)", ble_stats.success_count, ble_stats.total_attempts, ble_stats.getSuccessRate() * 100.0f);
}

void ProtocolSelector::setStrategy(SelectionStrategy new_strategy)
{
    strategy = new_strategy;
}

SelectionStrategy ProtocolSelector::getStrategy() const
{
    return strategy;
}

void ProtocolSelector::resetStats()
{
    memset(&wifi_stats, 0, sizeof(ConnectionStats));
    memset(&ble_stats, 0, sizeof(ConnectionStats));
    
    if (persist_stats) {
        saveStatsToNVRAM();
    }
}
