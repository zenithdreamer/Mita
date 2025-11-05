#pragma once

#include "orm.hpp"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <chrono>

namespace mita {
namespace db {

// User entity
struct User {
    int64_t id;
    std::string username;
    std::string passwordHash;
    std::string salt;
    int64_t createdAt;
    int64_t updatedAt;

    User() : id(0), createdAt(0), updatedAt(0) {}

    User(int64_t id, const std::string& username, const std::string& passwordHash,
         const std::string& salt, int64_t createdAt, int64_t updatedAt)
        : id(id), username(username), passwordHash(passwordHash),
          salt(salt), createdAt(createdAt), updatedAt(updatedAt) {}
};

// Password hashing utility
class PasswordHasher {
public:
    static std::string generateSalt(size_t length = 32) {
        std::vector<unsigned char> salt(length);
        if (RAND_bytes(salt.data(), length) != 1) {
            throw DatabaseException("Failed to generate random salt");
        }

        std::ostringstream oss;
        for (size_t i = 0; i < length; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(salt[i]);
        }

        return oss.str();
    }

    static std::string hashPassword(const std::string& password, const std::string& salt) {
        std::string saltedPassword = password + salt;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(saltedPassword.c_str()),
               saltedPassword.length(), hash);

        std::ostringstream oss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        return oss.str();
    }

    static bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
        std::string computedHash = hashPassword(password, salt);
        return computedHash == hash;
    }
};

// User model definition
class UserModel : public Model {
public:
    std::string tableName() const override {
        return "users";
    }

    std::vector<Field> fields() const override {
        return {
            Field("id", FieldType::INTEGER, FieldConstraints::PRIMARY_KEY | FieldConstraints::AUTO_INCREMENT),
            Field("username", FieldType::TEXT, FieldConstraints::NOT_NULL | FieldConstraints::UNIQUE),
            Field("password_hash", FieldType::TEXT, FieldConstraints::NOT_NULL),
            Field("salt", FieldType::TEXT, FieldConstraints::NOT_NULL),
            Field("created_at", FieldType::INTEGER, FieldConstraints::NOT_NULL),
            Field("updated_at", FieldType::INTEGER, FieldConstraints::NOT_NULL)
        };
    }
};

// Session entity
struct Session {
    int64_t id;
    int64_t userId;
    std::string sessionToken;
    int64_t expiresAt;
    int64_t createdAt;

    Session() : id(0), userId(0), expiresAt(0), createdAt(0) {}

    Session(int64_t id, int64_t userId, const std::string& sessionToken,
            int64_t expiresAt, int64_t createdAt)
        : id(id), userId(userId), sessionToken(sessionToken),
          expiresAt(expiresAt), createdAt(createdAt) {}
};

// Session model definition
class SessionModel : public Model {
public:
    std::string tableName() const override {
        return "sessions";
    }

    std::vector<Field> fields() const override {
        return {
            Field("id", FieldType::INTEGER, FieldConstraints::PRIMARY_KEY | FieldConstraints::AUTO_INCREMENT),
            Field("user_id", FieldType::INTEGER, FieldConstraints::NOT_NULL),
            Field("session_token", FieldType::TEXT, FieldConstraints::NOT_NULL | FieldConstraints::UNIQUE),
            Field("expires_at", FieldType::INTEGER, FieldConstraints::NOT_NULL),
            Field("created_at", FieldType::INTEGER, FieldConstraints::NOT_NULL)
        };
    }
};

// User repository for database operations
class UserRepository {
private:
    Database* db_;

    int64_t getCurrentTimestamp() const {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

public:
    explicit UserRepository(Database* db) : db_(db) {}

    void initializeTables() {
        UserModel userModel;
        SessionModel sessionModel;
        db_->createTable(userModel);
        db_->createTable(sessionModel);
    }

    std::optional<User> findByUsername(const std::string& username) {
        auto result = db_->query()
            .from("users")
            .select()
            .where("username", username)
            .execute();

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        User user;
        user.id = row.getInt("id").value_or(0);
        user.username = row.getString("username");
        user.passwordHash = row.getString("password_hash");
        user.salt = row.getString("salt");
        user.createdAt = row.getInt("created_at").value_or(0);
        user.updatedAt = row.getInt("updated_at").value_or(0);

        return user;
    }

    std::optional<User> findById(int64_t id) {
        auto result = db_->query()
            .from("users")
            .select()
            .where("id", std::to_string(id))
            .execute();

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        User user;
        user.id = row.getInt("id").value_or(0);
        user.username = row.getString("username");
        user.passwordHash = row.getString("password_hash");
        user.salt = row.getString("salt");
        user.createdAt = row.getInt("created_at").value_or(0);
        user.updatedAt = row.getInt("updated_at").value_or(0);

        return user;
    }

    int64_t createUser(const std::string& username, const std::string& password) {
        // Check if user already exists
        if (findByUsername(username).has_value()) {
            throw DatabaseException("User already exists");
        }

        // Generate salt and hash password
        std::string salt = PasswordHasher::generateSalt();
        std::string passwordHash = PasswordHasher::hashPassword(password, salt);

        int64_t now = getCurrentTimestamp();

        return db_->query()
            .from("users")
            .insert("username", username)
            .insert("password_hash", passwordHash)
            .insert("salt", salt)
            .insert("created_at", std::to_string(now))
            .insert("updated_at", std::to_string(now))
            .executeInsert();
    }

    bool verifyCredentials(const std::string& username, const std::string& password) {
        auto user = findByUsername(username);
        if (!user.has_value()) {
            return false;
        }

        return PasswordHasher::verifyPassword(password, user->passwordHash, user->salt);
    }

    int64_t countUsers() {
        auto result = db_->execute("SELECT COUNT(*) as count FROM users");
        if (!result.empty()) {
            return result[0].getInt("count").value_or(0);
        }
        return 0;
    }

    // Session management
    std::string createSession(int64_t userId, int64_t expiresInSeconds = 86400) {
        // Generate secure random session token
        std::string sessionToken = PasswordHasher::generateSalt(64);

        int64_t now = getCurrentTimestamp();
        int64_t expiresAt = now + expiresInSeconds;

        db_->query()
            .from("sessions")
            .insert("user_id", std::to_string(userId))
            .insert("session_token", sessionToken)
            .insert("expires_at", std::to_string(expiresAt))
            .insert("created_at", std::to_string(now))
            .executeInsert();

        return sessionToken;
    }

    std::optional<Session> findSessionByToken(const std::string& sessionToken) {
        auto result = db_->query()
            .from("sessions")
            .select()
            .where("session_token", sessionToken)
            .execute();

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        Session session;
        session.id = row.getInt("id").value_or(0);
        session.userId = row.getInt("user_id").value_or(0);
        session.sessionToken = row.getString("session_token");
        session.expiresAt = row.getInt("expires_at").value_or(0);
        session.createdAt = row.getInt("created_at").value_or(0);

        // Check if session is expired
        int64_t now = getCurrentTimestamp();
        if (session.expiresAt < now) {
            // Delete expired session
            db_->query()
                .from("sessions")
                .where("id", std::to_string(session.id))
                .executeDelete();
            return std::nullopt;
        }

        return session;
    }

    bool deleteSession(const std::string& sessionToken) {
        int deleted = db_->query()
            .from("sessions")
            .where("session_token", sessionToken)
            .executeDelete();

        return deleted > 0;
    }

    void deleteExpiredSessions() {
        int64_t now = getCurrentTimestamp();
        db_->execute("DELETE FROM sessions WHERE expires_at < " + std::to_string(now));
    }

    void deleteUserSessions(int64_t userId) {
        db_->query()
            .from("sessions")
            .where("user_id", std::to_string(userId))
            .executeDelete();
    }
};

} // namespace db
} // namespace mita
