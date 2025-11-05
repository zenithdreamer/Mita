#pragma once

#include "database/models.hpp"
#include <memory>
#include <string>
#include <cstdio>
#include <optional>

namespace mita {

class SettingsService {
private:
    std::shared_ptr<db::Storage> storage_;

    void initializeDefaultSettings() {
        try {
            using namespace sqlite_orm;

            // Check if settings row exists
            auto settingsCount = storage_->count<db::Settings>();

            if (settingsCount == 0) {
                printf("[SETTINGS] No settings found. Creating default settings...\n");
                fflush(stdout);

                // Create default settings with WiFi enabled
                db::Settings settings;
                settings.id = 1;
                settings.wifi_enabled = 1;  // Enable WiFi by default
                settings.ble_enabled = 0;
                settings.zigbee_enabled = 0;
                settings.monitor_enabled = 0;  // Packet monitor disabled by default
                settings.updated_at = db::getCurrentTimestamp();

                storage_->insert(settings);

                printf("[SETTINGS] Default settings created (WiFi enabled, BLE/Zigbee/Monitor disabled)\n");
                fflush(stdout);
            } else {
                printf("[SETTINGS] Settings already exist\n");
                fflush(stdout);
            }
        } catch (const std::exception& e) {
            printf("[SETTINGS] ERROR: Failed to initialize default settings: %s\n", e.what());
            fflush(stdout);
        }
    }

public:
    explicit SettingsService(std::shared_ptr<db::Storage> storage)
        : storage_(storage) {
        try {
            // Initialize default settings if needed
            initializeDefaultSettings();

            printf("[SETTINGS] Settings service initialized successfully\n");
            fflush(stdout);
        } catch (const std::exception& e) {
            printf("[SETTINGS] ERROR: Failed to initialize settings service: %s\n", e.what());
            fflush(stdout);
            throw;
        }
    }

    ~SettingsService() = default;

    db::Settings getSettings() {
        using namespace sqlite_orm;

        auto settings = storage_->get_all<db::Settings>(
            where(c(&db::Settings::id) == 1)
        );

        if (settings.empty()) {
            throw std::runtime_error("Settings not found");
        }

        return settings[0];
    }

    void updateSettings(bool wifiEnabled, bool bleEnabled, bool zigbeeEnabled, bool monitorEnabled) {
        using namespace sqlite_orm;

        auto settings = getSettings();
        settings.wifi_enabled = wifiEnabled ? 1 : 0;
        settings.ble_enabled = bleEnabled ? 1 : 0;
        settings.zigbee_enabled = zigbeeEnabled ? 1 : 0;
        settings.monitor_enabled = monitorEnabled ? 1 : 0;
        settings.updated_at = db::getCurrentTimestamp();

        storage_->update(settings);

        printf("[SETTINGS] Settings updated: WiFi=%d, BLE=%d, Zigbee=%d, Monitor=%d\n",
               settings.wifi_enabled, settings.ble_enabled, settings.zigbee_enabled,
               settings.monitor_enabled);
        fflush(stdout);
    }

    bool isWifiEnabled() {
        return getSettings().wifi_enabled != 0;
    }

    bool isBleEnabled() {
        return getSettings().ble_enabled != 0;
    }

    bool isZigbeeEnabled() {
        return getSettings().zigbee_enabled != 0;
    }

    bool isMonitorEnabled() {
        return getSettings().monitor_enabled != 0;
    }

    void setMonitorEnabled(bool enabled) {
        using namespace sqlite_orm;

        auto settings = getSettings();
        settings.monitor_enabled = enabled ? 1 : 0;
        settings.updated_at = db::getCurrentTimestamp();

        storage_->update(settings);

        printf("[SETTINGS] Packet monitor %s\n", enabled ? "enabled" : "disabled");
        fflush(stdout);
    }
};

} // namespace mita
