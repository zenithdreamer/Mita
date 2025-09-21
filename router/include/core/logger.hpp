#ifndef MITA_ROUTER_LOGGER_HPP
#define MITA_ROUTER_LOGGER_HPP

#include <string>
#include <memory>
#include <fstream>
#include <mutex>
#include <chrono>
#include <sstream>
#include <map>
#include <algorithm>

namespace mita
{
    namespace core
    {

        /**
         * Log levels
         */
        enum class LogLevel
        {
            DEBUG = 0,
            INFO = 1,
            WARNING = 2,
            ERROR = 3,
            CRITICAL = 4
        };

        /**
         * Structured logging context for key-value pairs
         */
        class LogContext
        {
        public:
            LogContext() = default;

            template <typename T>
            LogContext &add(const std::string &key, const T &value)
            {
                std::stringstream ss;
                ss << value;
                context_[key] = ss.str();
                return *this;
            }

            std::string format() const;
            bool empty() const { return context_.empty(); }

        private:
            std::map<std::string, std::string> context_;
        };

        /**
         * Logger (Thread-safe) implementation
         */
        class Logger
        {
        public:
            Logger(const std::string &name, LogLevel level = LogLevel::INFO);
            ~Logger();

            void set_level(LogLevel level) { level_ = level; }
            void set_output_file(const std::string &filename);
            void set_console_output(bool enabled) { console_output_ = enabled; }

            void debug(const std::string &message, const LogContext &context = LogContext{});
            void info(const std::string &message, const LogContext &context = LogContext{});
            void warning(const std::string &message, const LogContext &context = LogContext{});
            void error(const std::string &message, const LogContext &context = LogContext{});
            void critical(const std::string &message, const LogContext &context = LogContext{});

            bool is_enabled(LogLevel level) const { return level >= level_; }

            const std::string &name() const { return name_; }

        private:
            void log(LogLevel level, const std::string &message, const LogContext &context);
            std::string format_message(LogLevel level, const std::string &message, const LogContext &context);
            std::string level_to_string(LogLevel level);
            std::string current_timestamp();

            std::string name_;
            LogLevel level_;
            bool console_output_;
            std::unique_ptr<std::ofstream> file_output_;
            mutable std::mutex mutex_;
        };

        /**
         * Logger factory and management
         */
        class LoggerManager
        {
        public:
            static LoggerManager &instance();

            void setup_logging(LogLevel level = LogLevel::INFO,
                               const std::string &log_file = "",
                               bool console_output = true);

            std::shared_ptr<Logger> get_logger(const std::string &name);

            static LogLevel string_to_level(const std::string &level_str);

        private:
            LoggerManager() = default;

            LogLevel default_level_;
            std::string default_log_file_;
            bool default_console_output_;
            std::map<std::string, std::shared_ptr<Logger>> loggers_;
            std::mutex mutex_;
        };

        std::shared_ptr<Logger> get_logger(const std::string &name);
        void setup_logging(LogLevel level = LogLevel::INFO,
                           const std::string &log_file = "",
                           bool console_output = true);

#define LOG_DEBUG(logger, message, ...)           \
    if ((logger)->is_enabled(LogLevel::DEBUG))    \
    {                                             \
        LogContext ctx;                           \
        __VA_ARGS__(logger)->debug(message, ctx); \
    }

#define LOG_INFO(logger, message, ...)           \
    if ((logger)->is_enabled(LogLevel::INFO))    \
    {                                            \
        LogContext ctx;                          \
        __VA_ARGS__(logger)->info(message, ctx); \
    }

#define LOG_WARNING(logger, message, ...)           \
    if ((logger)->is_enabled(LogLevel::WARNING))    \
    {                                               \
        LogContext ctx;                             \
        __VA_ARGS__(logger)->warning(message, ctx); \
    }

#define LOG_ERROR(logger, message, ...)           \
    if ((logger)->is_enabled(LogLevel::ERROR))    \
    {                                             \
        LogContext ctx;                           \
        __VA_ARGS__(logger)->error(message, ctx); \
    }

    } // namespace core
} // namespace mita

#endif // MITA_ROUTER_LOGGER_HPP
