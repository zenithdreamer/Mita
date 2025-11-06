#pragma once

#include <sqlite_orm/sqlite_orm.h>
#include <string>
#include <cstdint>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <chrono>

namespace mita {
namespace db {

// User entity for sqlite_orm
struct User {
    int64_t id;
    std::string username;
    std::string password_hash;
    std::string salt;
    int64_t created_at;
    int64_t updated_at;

    // Default constructor
    User() : id(0), created_at(0), updated_at(0) {}

    // Constructor with parameters
    User(int64_t id, const std::string& username, const std::string& password_hash,
         const std::string& salt, int64_t created_at, int64_t updated_at)
        : id(id), username(username), password_hash(password_hash),
          salt(salt), created_at(created_at), updated_at(updated_at) {}
};

// Session entity for sqlite_orm
struct Session {
    int64_t id;
    int64_t user_id;
    std::string session_token;
    int64_t expires_at;
    int64_t created_at;

    // Default constructor
    Session() : id(0), user_id(0), expires_at(0), created_at(0) {}

    // Constructor with parameters
    Session(int64_t id, int64_t user_id, const std::string& session_token,
            int64_t expires_at, int64_t created_at)
        : id(id), user_id(user_id), session_token(session_token),
          expires_at(expires_at), created_at(created_at) {}
};

// Monitored packet entity for sqlite_orm
struct MonitoredPacket {
    int64_t id;
    std::string packet_id;  // e.g., "pkt_1234567890_0"
    int64_t timestamp;      // Unix timestamp in milliseconds
    std::string direction;  // "inbound", "outbound", "forwarded"
    int source_addr;
    int dest_addr;
    std::string message_type;
    int payload_size;
    std::string transport;  // "wifi" or "ble"
    int encrypted;          // 0 or 1
    std::string raw_data;   // Hex-encoded raw packet data
    std::string decoded_header;
    std::string decoded_payload;
    std::string decrypted_payload; // Decrypted payload (if encrypted)
    int is_valid;           // 0 = invalid/failed, 1 = valid
    std::string error_flags; // e.g., "CHECKSUM_FAIL", "MALFORMED", "INVALID_VERSION"

    // Default constructor
    MonitoredPacket() : id(0), timestamp(0), source_addr(0), dest_addr(0),
                        payload_size(0), encrypted(0), decrypted_payload(""), is_valid(1), error_flags("") {}

    // Constructor with parameters
    MonitoredPacket(int64_t id, const std::string& packet_id, int64_t timestamp,
                   const std::string& direction, int source_addr, int dest_addr,
                   const std::string& message_type, int payload_size,
                   const std::string& transport, int encrypted,
                   const std::string& raw_data, const std::string& decoded_header,
                   const std::string& decoded_payload, int is_valid, const std::string& error_flags)
        : id(id), packet_id(packet_id), timestamp(timestamp), direction(direction),
          source_addr(source_addr), dest_addr(dest_addr), message_type(message_type),
          payload_size(payload_size), transport(transport), encrypted(encrypted),
          raw_data(raw_data), decoded_header(decoded_header), decoded_payload(decoded_payload),
          is_valid(is_valid), error_flags(error_flags) {}
};

// Settings entity for sqlite_orm
struct Settings {
    int64_t id;
    int wifi_enabled;
    int ble_enabled;
    int zigbee_enabled;
    int monitor_enabled;  // Packet monitor enabled/disabled
    int64_t updated_at;

    // Default constructor - WiFi enabled by default, monitor disabled
    Settings() : id(1), wifi_enabled(1), ble_enabled(0), zigbee_enabled(0),
                 monitor_enabled(0), updated_at(0) {}

    // Constructor with parameters
    Settings(int64_t id, int wifi_enabled, int ble_enabled, int zigbee_enabled,
             int monitor_enabled, int64_t updated_at)
        : id(id), wifi_enabled(wifi_enabled), ble_enabled(ble_enabled),
          zigbee_enabled(zigbee_enabled), monitor_enabled(monitor_enabled),
          updated_at(updated_at) {}
};

// Define the storage schema using sqlite_orm
inline auto initStorage(const std::string& path) {
    using namespace sqlite_orm;

    return make_storage(
        path,
        make_table(
            "users",
            make_column("id", &User::id, primary_key().autoincrement()),
            make_column("username", &User::username, unique()),
            make_column("password_hash", &User::password_hash),
            make_column("salt", &User::salt),
            make_column("created_at", &User::created_at),
            make_column("updated_at", &User::updated_at)
        ),
        make_table(
            "sessions",
            make_column("id", &Session::id, primary_key().autoincrement()),
            make_column("user_id", &Session::user_id),
            make_column("session_token", &Session::session_token, unique()),
            make_column("expires_at", &Session::expires_at),
            make_column("created_at", &Session::created_at)
        ),
        make_table(
            "settings",
            make_column("id", &Settings::id, primary_key()),
            make_column("wifi_enabled", &Settings::wifi_enabled, default_value(0)),
            make_column("ble_enabled", &Settings::ble_enabled, default_value(0)),
            make_column("zigbee_enabled", &Settings::zigbee_enabled, default_value(0)),
            make_column("monitor_enabled", &Settings::monitor_enabled, default_value(0)),
            make_column("updated_at", &Settings::updated_at)
        ),
        make_table(
            "monitored_packets",
            make_column("id", &MonitoredPacket::id, primary_key().autoincrement()),
            make_column("packet_id", &MonitoredPacket::packet_id, unique()),
            make_column("timestamp", &MonitoredPacket::timestamp),
            make_column("direction", &MonitoredPacket::direction),
            make_column("source_addr", &MonitoredPacket::source_addr),
            make_column("dest_addr", &MonitoredPacket::dest_addr),
            make_column("message_type", &MonitoredPacket::message_type),
            make_column("payload_size", &MonitoredPacket::payload_size),
            make_column("transport", &MonitoredPacket::transport),
            make_column("encrypted", &MonitoredPacket::encrypted),
            make_column("raw_data", &MonitoredPacket::raw_data),
            make_column("decoded_header", &MonitoredPacket::decoded_header),
            make_column("decoded_payload", &MonitoredPacket::decoded_payload),
            make_column("decrypted_payload", &MonitoredPacket::decrypted_payload, default_value("")),
            make_column("is_valid", &MonitoredPacket::is_valid, default_value(1)),
            make_column("error_flags", &MonitoredPacket::error_flags, default_value(""))
        )
    );
}

// Define storage type for convenience
using Storage = decltype(initStorage(""));

// Helper function to get current timestamp
inline int64_t getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

// Password hashing utility class
class PasswordHasher {
public:
    static std::string generateSalt(size_t length = 32) {
        std::vector<unsigned char> salt_bytes(length);
        if (RAND_bytes(salt_bytes.data(), length) != 1) {
            throw std::runtime_error("Failed to generate random salt");
        }

        std::ostringstream oss;
        for (size_t i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(salt_bytes[i]);
        }

        return oss.str();
    }

    static std::string hashPassword(const std::string& password, const std::string& salt) {
        std::string salted_password = password + salt;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(salted_password.c_str()),
               salted_password.length(), hash);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
        }

        return oss.str();
    }

    static bool verifyPassword(const std::string& password, const std::string& salt,
                              const std::string& hash) {
        return hashPassword(password, salt) == hash;
    }
};

} // namespace db
} // namespace mita
