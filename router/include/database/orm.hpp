#pragma once

#include <sqlite3.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <optional>
#include <type_traits>

namespace mita {
namespace db {

class DatabaseException : public std::runtime_error {
public:
    explicit DatabaseException(const std::string& msg) : std::runtime_error(msg) {}
};

// Forward declarations
class Database;
class QueryBuilder;

// Field type enumeration
enum class FieldType {
    INTEGER,
    TEXT,
    REAL,
    BLOB,
    TIMESTAMP
};

// Field constraint flags
enum FieldConstraints {
    NONE = 0,
    PRIMARY_KEY = 1 << 0,
    NOT_NULL = 1 << 1,
    UNIQUE = 1 << 2,
    AUTO_INCREMENT = 1 << 3
};

inline FieldConstraints operator|(FieldConstraints a, FieldConstraints b) {
    return static_cast<FieldConstraints>(static_cast<int>(a) | static_cast<int>(b));
}

inline bool operator&(FieldConstraints a, FieldConstraints b) {
    return (static_cast<int>(a) & static_cast<int>(b)) != 0;
}

// Field definition
struct Field {
    std::string name;
    FieldType type;
    FieldConstraints constraints;
    std::optional<std::string> defaultValue;

    Field(const std::string& name, FieldType type,
          FieldConstraints constraints = FieldConstraints::NONE,
          const std::optional<std::string>& defaultValue = std::nullopt)
        : name(name), type(type), constraints(constraints), defaultValue(defaultValue) {}

    std::string toSQL() const {
        std::ostringstream oss;
        oss << name << " ";

        switch (type) {
            case FieldType::INTEGER:
                oss << "INTEGER";
                break;
            case FieldType::TEXT:
                oss << "TEXT";
                break;
            case FieldType::REAL:
                oss << "REAL";
                break;
            case FieldType::BLOB:
                oss << "BLOB";
                break;
            case FieldType::TIMESTAMP:
                oss << "TIMESTAMP";
                break;
        }

        if (constraints & FieldConstraints::PRIMARY_KEY) {
            oss << " PRIMARY KEY";
        }
        if (constraints & FieldConstraints::AUTO_INCREMENT) {
            oss << " AUTOINCREMENT";
        }
        if (constraints & FieldConstraints::NOT_NULL) {
            oss << " NOT NULL";
        }
        if (constraints & FieldConstraints::UNIQUE) {
            oss << " UNIQUE";
        }
        if (defaultValue.has_value()) {
            oss << " DEFAULT " << defaultValue.value();
        }

        return oss.str();
    }
};

// Model base class
class Model {
public:
    virtual ~Model() = default;
    virtual std::string tableName() const = 0;
    virtual std::vector<Field> fields() const = 0;

    std::string createTableSQL() const {
        std::ostringstream oss;
        oss << "CREATE TABLE IF NOT EXISTS " << tableName() << " (";

        const auto fieldList = fields();
        for (size_t i = 0; i < fieldList.size(); ++i) {
            oss << fieldList[i].toSQL();
            if (i < fieldList.size() - 1) {
                oss << ", ";
            }
        }

        oss << ")";
        return oss.str();
    }
};

// Result row wrapper
class Row {
private:
    std::vector<std::pair<std::string, std::string>> data_;

public:
    void addColumn(const std::string& name, const std::string& value) {
        data_.emplace_back(name, value);
    }

    std::optional<std::string> get(const std::string& columnName) const {
        for (const auto& [name, value] : data_) {
            if (name == columnName) {
                return value;
            }
        }
        return std::nullopt;
    }

    std::optional<int64_t> getInt(const std::string& columnName) const {
        auto val = get(columnName);
        if (val.has_value()) {
            try {
                return std::stoll(val.value());
            } catch (...) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::string getString(const std::string& columnName, const std::string& defaultValue = "") const {
        return get(columnName).value_or(defaultValue);
    }

    const std::vector<std::pair<std::string, std::string>>& columns() const {
        return data_;
    }
};

// Query result
class QueryResult {
private:
    std::vector<Row> rows_;

public:
    void addRow(Row&& row) {
        rows_.emplace_back(std::move(row));
    }

    const std::vector<Row>& rows() const {
        return rows_;
    }

    size_t size() const {
        return rows_.size();
    }

    bool empty() const {
        return rows_.empty();
    }

    const Row& operator[](size_t index) const {
        return rows_.at(index);
    }

    std::optional<Row> first() const {
        if (!rows_.empty()) {
            return rows_[0];
        }
        return std::nullopt;
    }
};

// Query builder for type-safe queries
class QueryBuilder {
private:
    std::string table_;
    std::vector<std::string> selectColumns_;
    std::vector<std::pair<std::string, std::string>> whereConditions_;
    std::vector<std::pair<std::string, std::string>> insertValues_;
    std::vector<std::pair<std::string, std::string>> updateValues_;
    std::optional<std::string> orderBy_;
    std::optional<int> limit_;
    std::optional<int> offset_;
    Database* db_;

public:
    explicit QueryBuilder(Database* db) : db_(db) {}

    QueryBuilder& from(const std::string& table) {
        table_ = table;
        return *this;
    }

    QueryBuilder& select(const std::vector<std::string>& columns = {}) {
        selectColumns_ = columns;
        return *this;
    }

    QueryBuilder& where(const std::string& column, const std::string& value) {
        whereConditions_.emplace_back(column, value);
        return *this;
    }

    QueryBuilder& insert(const std::string& column, const std::string& value) {
        insertValues_.emplace_back(column, value);
        return *this;
    }

    QueryBuilder& update(const std::string& column, const std::string& value) {
        updateValues_.emplace_back(column, value);
        return *this;
    }

    QueryBuilder& orderBy(const std::string& column, bool ascending = true) {
        orderBy_ = column + (ascending ? " ASC" : " DESC");
        return *this;
    }

    QueryBuilder& limit(int count) {
        limit_ = count;
        return *this;
    }

    QueryBuilder& offset(int count) {
        offset_ = count;
        return *this;
    }

    QueryResult execute();
    int64_t executeInsert();
    int executeUpdate();
    int executeDelete();

    std::string buildSelectSQL() const {
        std::ostringstream oss;
        oss << "SELECT ";

        if (selectColumns_.empty()) {
            oss << "*";
        } else {
            for (size_t i = 0; i < selectColumns_.size(); ++i) {
                oss << selectColumns_[i];
                if (i < selectColumns_.size() - 1) oss << ", ";
            }
        }

        oss << " FROM " << table_;

        if (!whereConditions_.empty()) {
            oss << " WHERE ";
            for (size_t i = 0; i < whereConditions_.size(); ++i) {
                oss << whereConditions_[i].first << " = ?";
                if (i < whereConditions_.size() - 1) oss << " AND ";
            }
        }

        if (orderBy_.has_value()) {
            oss << " ORDER BY " << orderBy_.value();
        }

        if (limit_.has_value()) {
            oss << " LIMIT " << limit_.value();
        }

        if (offset_.has_value()) {
            oss << " OFFSET " << offset_.value();
        }

        return oss.str();
    }

    std::string buildInsertSQL() const {
        std::ostringstream oss;
        oss << "INSERT INTO " << table_ << " (";

        for (size_t i = 0; i < insertValues_.size(); ++i) {
            oss << insertValues_[i].first;
            if (i < insertValues_.size() - 1) oss << ", ";
        }

        oss << ") VALUES (";

        for (size_t i = 0; i < insertValues_.size(); ++i) {
            oss << "?";
            if (i < insertValues_.size() - 1) oss << ", ";
        }

        oss << ")";
        return oss.str();
    }

    std::string buildUpdateSQL() const {
        std::ostringstream oss;
        oss << "UPDATE " << table_ << " SET ";

        for (size_t i = 0; i < updateValues_.size(); ++i) {
            oss << updateValues_[i].first << " = ?";
            if (i < updateValues_.size() - 1) oss << ", ";
        }

        if (!whereConditions_.empty()) {
            oss << " WHERE ";
            for (size_t i = 0; i < whereConditions_.size(); ++i) {
                oss << whereConditions_[i].first << " = ?";
                if (i < whereConditions_.size() - 1) oss << " AND ";
            }
        }

        return oss.str();
    }

    std::string buildDeleteSQL() const {
        std::ostringstream oss;
        oss << "DELETE FROM " << table_;

        if (!whereConditions_.empty()) {
            oss << " WHERE ";
            for (size_t i = 0; i < whereConditions_.size(); ++i) {
                oss << whereConditions_[i].first << " = ?";
                if (i < whereConditions_.size() - 1) oss << " AND ";
            }
        }

        return oss.str();
    }

    const std::vector<std::pair<std::string, std::string>>& getWhereConditions() const {
        return whereConditions_;
    }

    const std::vector<std::pair<std::string, std::string>>& getInsertValues() const {
        return insertValues_;
    }

    const std::vector<std::pair<std::string, std::string>>& getUpdateValues() const {
        return updateValues_;
    }
};

// Database connection manager
class Database {
private:
    sqlite3* db_;
    std::string dbPath_;
    bool isOpen_;

public:
    explicit Database(const std::string& path)
        : db_(nullptr), dbPath_(path), isOpen_(false) {}

    ~Database() {
        close();
    }

    // Disable copy
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    bool open() {
        if (isOpen_) {
            return true;
        }

        int rc = sqlite3_open(dbPath_.c_str(), &db_);
        if (rc != SQLITE_OK) {
            throw DatabaseException("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
        }

        isOpen_ = true;

        // Enable foreign keys
        execute("PRAGMA foreign_keys = ON");

        return true;
    }

    void close() {
        if (isOpen_ && db_) {
            sqlite3_close(db_);
            db_ = nullptr;
            isOpen_ = false;
        }
    }

    bool isOpen() const {
        return isOpen_;
    }

    void createTable(const Model& model) {
        execute(model.createTableSQL());
    }

    QueryResult execute(const std::string& sql) {
        if (!isOpen_) {
            throw DatabaseException("Database is not open");
        }

        QueryResult result;
        char* errMsg = nullptr;

        auto callback = [](void* data, int argc, char** argv, char** colNames) -> int {
            auto* result = static_cast<QueryResult*>(data);
            Row row;
            for (int i = 0; i < argc; ++i) {
                row.addColumn(colNames[i], argv[i] ? argv[i] : "");
            }
            result->addRow(std::move(row));
            return 0;
        };

        int rc = sqlite3_exec(db_, sql.c_str(), callback, &result, &errMsg);

        if (rc != SQLITE_OK) {
            std::string error = errMsg ? errMsg : "Unknown error";
            sqlite3_free(errMsg);
            throw DatabaseException("SQL error: " + error);
        }

        return result;
    }

    QueryResult executeQuery(const std::string& sql, const std::vector<std::string>& params) {
        if (!isOpen_) {
            throw DatabaseException("Database is not open");
        }

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            throw DatabaseException("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
        }

        // Bind parameters
        for (size_t i = 0; i < params.size(); ++i) {
            sqlite3_bind_text(stmt, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT);
        }

        QueryResult result;

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            Row row;
            int columnCount = sqlite3_column_count(stmt);
            for (int i = 0; i < columnCount; ++i) {
                std::string columnName = sqlite3_column_name(stmt, i);
                const unsigned char* text = sqlite3_column_text(stmt, i);
                std::string value = text ? reinterpret_cast<const char*>(text) : "";
                row.addColumn(columnName, value);
            }
            result.addRow(std::move(row));
        }

        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw DatabaseException("Query execution error: " + std::string(sqlite3_errmsg(db_)));
        }

        sqlite3_finalize(stmt);
        return result;
    }

    int64_t executeInsert(const std::string& sql, const std::vector<std::string>& params) {
        if (!isOpen_) {
            throw DatabaseException("Database is not open");
        }

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            throw DatabaseException("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
        }

        // Bind parameters
        for (size_t i = 0; i < params.size(); ++i) {
            sqlite3_bind_text(stmt, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT);
        }

        rc = sqlite3_step(stmt);

        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw DatabaseException("Insert execution error: " + std::string(sqlite3_errmsg(db_)));
        }

        int64_t lastId = sqlite3_last_insert_rowid(db_);
        sqlite3_finalize(stmt);

        return lastId;
    }

    int executeUpdate(const std::string& sql, const std::vector<std::string>& params) {
        if (!isOpen_) {
            throw DatabaseException("Database is not open");
        }

        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            throw DatabaseException("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
        }

        // Bind parameters
        for (size_t i = 0; i < params.size(); ++i) {
            sqlite3_bind_text(stmt, static_cast<int>(i + 1), params[i].c_str(), -1, SQLITE_TRANSIENT);
        }

        rc = sqlite3_step(stmt);

        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw DatabaseException("Update execution error: " + std::string(sqlite3_errmsg(db_)));
        }

        int changes = sqlite3_changes(db_);
        sqlite3_finalize(stmt);

        return changes;
    }

    QueryBuilder query() {
        return QueryBuilder(this);
    }

    int64_t lastInsertId() const {
        return sqlite3_last_insert_rowid(db_);
    }

    void beginTransaction() {
        execute("BEGIN TRANSACTION");
    }

    void commit() {
        execute("COMMIT");
    }

    void rollback() {
        execute("ROLLBACK");
    }
};

// QueryBuilder implementations
inline QueryResult QueryBuilder::execute() {
    std::vector<std::string> params;
    for (const auto& [col, val] : whereConditions_) {
        params.push_back(val);
    }
    return db_->executeQuery(buildSelectSQL(), params);
}

inline int64_t QueryBuilder::executeInsert() {
    std::vector<std::string> params;
    for (const auto& [col, val] : insertValues_) {
        params.push_back(val);
    }
    return db_->executeInsert(buildInsertSQL(), params);
}

inline int QueryBuilder::executeUpdate() {
    std::vector<std::string> params;
    for (const auto& [col, val] : updateValues_) {
        params.push_back(val);
    }
    for (const auto& [col, val] : whereConditions_) {
        params.push_back(val);
    }
    return db_->executeUpdate(buildUpdateSQL(), params);
}

inline int QueryBuilder::executeDelete() {
    std::vector<std::string> params;
    for (const auto& [col, val] : whereConditions_) {
        params.push_back(val);
    }
    return db_->executeUpdate(buildDeleteSQL(), params);
}

} // namespace db
} // namespace mita
