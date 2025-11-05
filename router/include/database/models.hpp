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
