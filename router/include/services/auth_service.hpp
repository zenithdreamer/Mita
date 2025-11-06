#pragma once

#include "database/models.hpp"
#include <memory>
#include <string>
#include <cstdio>
#include <optional>
#include <mutex>

namespace mita {

class AuthService {
private:
    std::shared_ptr<db::Storage> storage_;
    mutable std::mutex session_mutex_;  // Protect session operations

    void bootstrapAdminUser() {
        try {
            using namespace sqlite_orm;
            
            // Check if any users exist
            auto userCount = storage_->count<db::User>();

            if (userCount == 0) {
                printf("[AUTH] No users found. Creating default admin user...\n");
                fflush(stdout);

                // Create default admin user with username: admin, password: admin
                int64_t adminId = createUser("admin", "admin");

                if (adminId > 0) {
                    printf("[AUTH] Default admin user created successfully (ID: %ld)\n", adminId);
                    printf("[AUTH] SECURITY WARNING: Default admin credentials are 'admin/admin'. Please change them immediately!\n");
                    fflush(stdout);
                } else {
                    printf("[AUTH] ERROR: Failed to create default admin user\n");
                    fflush(stdout);
                }
            } else {
                printf("[AUTH] Database already contains %d user(s). Skipping bootstrap.\n", userCount);
                fflush(stdout);
            }
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Failed to bootstrap admin user: %s\n", e.what());
            fflush(stdout);
        }
    }

    int64_t createUser(const std::string& username, const std::string& password) {
        using namespace sqlite_orm;
        
        // Check if user already exists
        auto existing = storage_->get_all<db::User>(
            where(c(&db::User::username) == username)
        );
        
        if (!existing.empty()) {
            throw std::runtime_error("User already exists");
        }

        // Generate salt and hash password
        std::string salt = db::PasswordHasher::generateSalt();
        std::string password_hash = db::PasswordHasher::hashPassword(password, salt);

        int64_t now = db::getCurrentTimestamp();

        db::User user;
        user.username = username;
        user.password_hash = password_hash;
        user.salt = salt;
        user.created_at = now;
        user.updated_at = now;

        return storage_->insert(user);
    }

public:
    explicit AuthService(const std::string& dbPath = "data/router.db") {
        try {
            // Initialize storage
            storage_ = std::make_shared<db::Storage>(db::initStorage(dbPath));
            
            // Sync schema (create tables if they don't exist)
            storage_->sync_schema();

            // Bootstrap admin user if needed
            bootstrapAdminUser();

            // Clean up expired sessions on startup
            deleteExpiredSessions();

            printf("[AUTH] Authentication service initialized successfully\n");
            fflush(stdout);
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Failed to initialize authentication service: %s\n", e.what());
            fflush(stdout);
            throw;
        }
    }

    ~AuthService() = default;

    // Get shared storage instance
    std::shared_ptr<db::Storage> getStorage() const {
        return storage_;
    }

    // Authenticate user and create session
    struct AuthResult {
        bool success;
        std::string message;
        std::string sessionToken;
        int64_t userId;

        AuthResult() : success(false), userId(0) {}
    };

    AuthResult authenticate(const std::string& username, const std::string& password) {
        AuthResult result;

        try {
            using namespace sqlite_orm;
            
            // Find user by username
            auto users = storage_->get_all<db::User>(
                where(c(&db::User::username) == username)
            );
            
            if (users.empty()) {
                result.success = false;
                result.message = "Invalid username or password";
                return result;
            }

            const auto& user = users[0];

            // Verify password
            if (!db::PasswordHasher::verifyPassword(password, user.salt, user.password_hash)) {
                result.success = false;
                result.message = "Invalid username or password";
                return result;
            }

            // Create session (24 hours expiry)
            std::string sessionToken = createSession(user.id, 86400);

            result.success = true;
            result.message = "Authentication successful";
            result.sessionToken = sessionToken;
            result.userId = user.id;

            printf("[AUTH] User '%s' authenticated successfully\n", username.c_str());
            fflush(stdout);

            return result;
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Authentication error: %s\n", e.what());
            fflush(stdout);
            result.success = false;
            result.message = "Authentication failed";
            return result;
        }
    }

    // Validate session token
    struct ValidateResult {
        bool valid;
        int64_t userId;
        std::string username;

        ValidateResult() : valid(false), userId(0) {}
    };

    ValidateResult validateSession(const std::string& sessionToken) {
        std::lock_guard<std::mutex> lock(session_mutex_);  // Thread-safe session access
        ValidateResult result;

        try {
            using namespace sqlite_orm;

            // Find session by token
            auto sessions = storage_->get_all<db::Session>(
                where(c(&db::Session::session_token) == sessionToken)
            );

            if (sessions.empty()) {
                result.valid = false;
                return result;
            }

            const auto& session = sessions[0];

            // Check if session is expired
            int64_t now = db::getCurrentTimestamp();
            if (session.expires_at < now) {
                // Don't delete here to avoid race conditions
                // Let background cleanup handle it
                result.valid = false;
                printf("[AUTH] Session expired (token: %s...)\n",
                       sessionToken.substr(0, 8).c_str());
                fflush(stdout);
                return result;
            }

            // Get user
            auto user = storage_->get<db::User>(session.user_id);

            result.valid = true;
            result.userId = user.id;
            result.username = user.username;

            return result;
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Session validation error: %s\n", e.what());
            fflush(stdout);
            result.valid = false;
            return result;
        }
    }

    // Logout (delete session)
    bool logout(const std::string& sessionToken) {
        std::lock_guard<std::mutex> lock(session_mutex_);  // Thread-safe
        try {
            using namespace sqlite_orm;

            auto sessions = storage_->get_all<db::Session>(
                where(c(&db::Session::session_token) == sessionToken)
            );

            if (!sessions.empty()) {
                storage_->remove<db::Session>(sessions[0].id);
                return true;
            }

            return false;
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Logout error: %s\n", e.what());
            fflush(stdout);
            return false;
        }
    }

    // Get user info by session token
    struct UserInfo {
        bool found;
        int64_t userId;
        std::string username;

        UserInfo() : found(false), userId(0) {}
    };

    UserInfo getUserInfo(const std::string& sessionToken) {
        auto validateResult = validateSession(sessionToken);
        
        UserInfo info;
        info.found = validateResult.valid;
        info.userId = validateResult.userId;
        info.username = validateResult.username;
        
        return info;
    }

private:
    // Create session
    std::string createSession(int64_t userId, int64_t expiresInSeconds = 86400) {
        std::lock_guard<std::mutex> lock(session_mutex_);  // Thread-safe
        // Generate secure random session token
        std::string sessionToken = db::PasswordHasher::generateSalt(64);

        int64_t now = db::getCurrentTimestamp();
        int64_t expiresAt = now + expiresInSeconds;

        db::Session session;
        session.user_id = userId;
        session.session_token = sessionToken;
        session.expires_at = expiresAt;
        session.created_at = now;

        storage_->insert(session);

        return sessionToken;
    }

    // Delete expired sessions
    void deleteExpiredSessions() {
        std::lock_guard<std::mutex> lock(session_mutex_);  // Thread-safe
        try {
            using namespace sqlite_orm;

            int64_t now = db::getCurrentTimestamp();
            storage_->remove_all<db::Session>(
                where(c(&db::Session::expires_at) < now)
            );

            printf("[AUTH] Cleaned up expired sessions\n");
            fflush(stdout);
        } catch (const std::exception& e) {
            printf("[AUTH] ERROR: Failed to delete expired sessions: %s\n", e.what());
            fflush(stdout);
        }
    }

public:
    // Public method to manually cleanup expired sessions
    void cleanupExpiredSessions() {
        deleteExpiredSessions();
    }
};

} // namespace mita
