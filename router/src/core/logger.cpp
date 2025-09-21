#include "core/logger.hpp"
#include <iostream>
#include <iomanip>
#include <map>

namespace mita
{
    namespace core
    {

        // LogContext implementation
        std::string LogContext::format() const
        {
            if (context_.empty())
            {
                return "";
            }

            std::stringstream ss;
            bool first = true;
            for (const auto &[key, value] : context_)
            {
                if (!first)
                {
                    ss << " ";
                }
                ss << key << "=" << value;
                first = false;
            }
            return ss.str();
        }

        // Logger implementation
        Logger::Logger(const std::string &name, LogLevel level)
            : name_(name), level_(level), console_output_(true)
        {
        }

        Logger::~Logger()
        {
            if (file_output_)
            {
                file_output_->close();
            }
        }

        void Logger::set_output_file(const std::string &filename)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (file_output_)
            {
                file_output_->close();
            }

            if (!filename.empty())
            {
                file_output_ = std::make_unique<std::ofstream>(filename, std::ios::app);
                if (!file_output_->is_open())
                {
                    std::cerr << "Failed to open log file: " << filename << std::endl;
                    file_output_.reset();
                }
            }
        }

        void Logger::debug(const std::string &message, const LogContext &context)
        {
            if (is_enabled(LogLevel::DEBUG))
            {
                log(LogLevel::DEBUG, message, context);
            }
        }

        void Logger::info(const std::string &message, const LogContext &context)
        {
            if (is_enabled(LogLevel::INFO))
            {
                log(LogLevel::INFO, message, context);
            }
        }

        void Logger::warning(const std::string &message, const LogContext &context)
        {
            if (is_enabled(LogLevel::WARNING))
            {
                log(LogLevel::WARNING, message, context);
            }
        }

        void Logger::error(const std::string &message, const LogContext &context)
        {
            if (is_enabled(LogLevel::ERROR))
            {
                log(LogLevel::ERROR, message, context);
            }
        }

        void Logger::critical(const std::string &message, const LogContext &context)
        {
            if (is_enabled(LogLevel::CRITICAL))
            {
                log(LogLevel::CRITICAL, message, context);
            }
        }

        void Logger::log(LogLevel level, const std::string &message, const LogContext &context)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            std::string formatted_message = format_message(level, message, context);

            // Console output
            if (console_output_)
            {
                if (level >= LogLevel::ERROR)
                {
                    std::cerr << formatted_message << std::endl;
                }
                else
                {
                    std::cout << formatted_message << std::endl;
                }
            }

            // File output
            if (file_output_ && file_output_->is_open())
            {
                *file_output_ << formatted_message << std::endl;
                file_output_->flush();
            }
        }

        std::string Logger::format_message(LogLevel level, const std::string &message, const LogContext &context)
        {
            std::stringstream ss;

            // Timestamp
            ss << current_timestamp() << " ";

            // Log level
            ss << "[" << level_to_string(level) << "] ";

            // Logger name
            ss << name_ << ": ";

            // Message
            ss << message;

            // Context
            if (!context.empty())
            {
                ss << " " << context.format();
            }

            return ss.str();
        }

        std::string Logger::level_to_string(LogLevel level)
        {
            switch (level)
            {
            case LogLevel::DEBUG:
                return "DEBUG";
            case LogLevel::INFO:
                return "INFO";
            case LogLevel::WARNING:
                return "WARN";
            case LogLevel::ERROR:
                return "ERROR";
            case LogLevel::CRITICAL:
                return "CRIT";
            }
            return "UNKNOWN";
        }

        std::string Logger::current_timestamp()
        {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          now.time_since_epoch()) %
                      1000;

            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            ss << "." << std::setfill('0') << std::setw(3) << ms.count();

            return ss.str();
        }

        // LoggerManager implementation
        LoggerManager &LoggerManager::instance()
        {
            static LoggerManager instance;
            return instance;
        }

        void LoggerManager::setup_logging(LogLevel level, const std::string &log_file, bool console_output)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            default_level_ = level;
            default_log_file_ = log_file;
            default_console_output_ = console_output;

            // Update existing loggers
            for (auto &[name, logger] : loggers_)
            {
                logger->set_level(level);
                logger->set_console_output(console_output);
                if (!log_file.empty())
                {
                    logger->set_output_file(log_file);
                }
            }
        }

        std::shared_ptr<Logger> LoggerManager::get_logger(const std::string &name)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            auto it = loggers_.find(name);
            if (it != loggers_.end())
            {
                return it->second;
            }

            // Create new logger
            auto logger = std::make_shared<Logger>(name, default_level_);
            logger->set_console_output(default_console_output_);
            if (!default_log_file_.empty())
            {
                logger->set_output_file(default_log_file_);
            }

            loggers_[name] = logger;
            return logger;
        }

        LogLevel LoggerManager::string_to_level(const std::string &level_str)
        {
            std::string upper_level = level_str;
            std::transform(upper_level.begin(), upper_level.end(), upper_level.begin(), ::toupper);

            if (upper_level == "DEBUG")
                return LogLevel::DEBUG;
            if (upper_level == "INFO")
                return LogLevel::INFO;
            if (upper_level == "WARNING" || upper_level == "WARN")
                return LogLevel::WARNING;
            if (upper_level == "ERROR")
                return LogLevel::ERROR;
            if (upper_level == "CRITICAL" || upper_level == "CRIT")
                return LogLevel::CRITICAL;

            return LogLevel::INFO; // Default
        }

        // Convenience functions
        std::shared_ptr<Logger> get_logger(const std::string &name)
        {
            return LoggerManager::instance().get_logger(name);
        }

        void setup_logging(LogLevel level, const std::string &log_file, bool console_output)
        {
            LoggerManager::instance().setup_logging(level, log_file, console_output);
        }

    } // namespace core
} // namespace mita