#pragma once

#include "orm.hpp"
#include <chrono>

namespace mita {
namespace db {

// Settings entity
struct Settings {
    int64_t id;
    bool wifiEnabled;
    bool bleEnabled;
    bool zigbeeEnabled;
    int64_t updatedAt;

    Settings()
        : id(1), wifiEnabled(false), bleEnabled(false), zigbeeEnabled(false), updatedAt(0) {}

    Settings(int64_t id, bool wifiEnabled, bool bleEnabled, bool zigbeeEnabled, int64_t updatedAt)
        : id(id), wifiEnabled(wifiEnabled), bleEnabled(bleEnabled),
          zigbeeEnabled(zigbeeEnabled), updatedAt(updatedAt) {}
};

// Settings model definition
class SettingsModel : public Model {
public:
    std::string tableName() const override {
        return "settings";
    }

    std::vector<Field> fields() const override {
        return {
            Field("id", FieldType::INTEGER, FieldConstraints::PRIMARY_KEY),
            Field("wifi_enabled", FieldType::INTEGER, FieldConstraints::NOT_NULL, "0"),
            Field("ble_enabled", FieldType::INTEGER, FieldConstraints::NOT_NULL, "0"),
            Field("zigbee_enabled", FieldType::INTEGER, FieldConstraints::NOT_NULL, "0"),
            Field("updated_at", FieldType::INTEGER, FieldConstraints::NOT_NULL)
        };
    }
};

// Settings repository for database operations
class SettingsRepository {
private:
    Database* db_;

    int64_t getCurrentTimestamp() const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

public:
    explicit SettingsRepository(Database* db) : db_(db) {}

    void initializeTables() {
        SettingsModel settingsModel;
        db_->createTable(settingsModel);

        // Check if settings row exists, if not create default
        auto result = db_->query()
            .from("settings")
            .select()
            .where("id", "1")
            .execute();

        if (result.empty()) {
            // Create default settings row with all transports disabled
            int64_t now = getCurrentTimestamp();
            db_->query()
                .from("settings")
                .insert("id", "1")
                .insert("wifi_enabled", "0")
                .insert("ble_enabled", "0")
                .insert("zigbee_enabled", "0")
                .insert("updated_at", std::to_string(now))
                .executeInsert();
        }
    }

    Settings getSettings() {
        auto result = db_->query()
            .from("settings")
            .select()
            .where("id", "1")
            .execute();

        if (result.empty()) {
            throw DatabaseException("Settings not found");
        }

        const auto& row = result[0];
        Settings settings;
        settings.id = row.getInt("id").value_or(1);
        settings.wifiEnabled = row.getInt("wifi_enabled").value_or(0) != 0;
        settings.bleEnabled = row.getInt("ble_enabled").value_or(0) != 0;
        settings.zigbeeEnabled = row.getInt("zigbee_enabled").value_or(0) != 0;
        settings.updatedAt = row.getInt("updated_at").value_or(0);

        return settings;
    }

    void updateSettings(bool wifiEnabled, bool bleEnabled, bool zigbeeEnabled) {
        int64_t now = getCurrentTimestamp();

        db_->query()
            .from("settings")
            .update("wifi_enabled", wifiEnabled ? "1" : "0")
            .update("ble_enabled", bleEnabled ? "1" : "0")
            .update("zigbee_enabled", zigbeeEnabled ? "1" : "0")
            .update("updated_at", std::to_string(now))
            .where("id", "1")
            .executeUpdate();
    }

    void updateWifiEnabled(bool enabled) {
        int64_t now = getCurrentTimestamp();

        db_->query()
            .from("settings")
            .update("wifi_enabled", enabled ? "1" : "0")
            .update("updated_at", std::to_string(now))
            .where("id", "1")
            .executeUpdate();
    }

    void updateBleEnabled(bool enabled) {
        int64_t now = getCurrentTimestamp();

        db_->query()
            .from("settings")
            .update("ble_enabled", enabled ? "1" : "0")
            .update("updated_at", std::to_string(now))
            .where("id", "1")
            .executeUpdate();
    }

    void updateZigbeeEnabled(bool enabled) {
        int64_t now = getCurrentTimestamp();

        db_->query()
            .from("settings")
            .update("zigbee_enabled", enabled ? "1" : "0")
            .update("updated_at", std::to_string(now))
            .where("id", "1")
            .executeUpdate();
    }
};

} // namespace db
} // namespace mita
