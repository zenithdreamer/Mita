/**
 * DHCP Server Manager Implementation
 * Handles DHCP server setup and management using dnsmasq for the WiFi access point
 */

#include "infrastructure/dhcp_server.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"

#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>

namespace mita
{
    namespace infrastructure
    {

        DHCPServerManager::DHCPServerManager(const std::shared_ptr<core::RouterConfig> &config)
            : config_(config), logger_(core::get_logger("DHCPServerManager"))
        {

            // DHCP settings
            server_ip_ = config->wifi.server_host;

            // Calculate network range (assuming /24 subnet)
            auto base_ip = server_ip_.substr(0, server_ip_.find_last_of('.'));
            dhcp_start_ = base_ip + ".10";
            dhcp_end_ = base_ip + ".100";

            // Configuration files
            config_dir_ = "/etc/dnsmasq.d";
            config_file_ = config_dir_ / ("mita-router-" + config->router_id + ".conf");
            pid_file_ = "/var/run/dnsmasq-mita-" + config->router_id + ".pid";

            logger_->info("DHCP Server Manager initialized",
                          core::LogContext()
                              .add("server_ip", server_ip_)
                              .add("dhcp_range", dhcp_start_ + "-" + dhcp_end_)
                              .add("config_file", config_file_.string()));
        }

        DHCPServerManager::~DHCPServerManager()
        {
            if (running_)
            {
                teardown_dhcp_server();
            }
        }

        bool DHCPServerManager::setup_dhcp_server()
        {
            logger_->info("Setting up DHCP server...");

            // Check if running as root
            if (geteuid() != 0)
            {
                logger_->error("Root privileges required for DHCP server setup");
                return false;
            }

            try
            {
                // Stop any existing dnsmasq processes first
                logger_->debug("Stopping any existing dnsmasq processes...");
                stop_all_dnsmasq_processes();

                // Detect the WiFi interface
                interface_ = detect_wifi_interface();
                if (interface_.empty())
                {
                    logger_->warning("Could not detect WiFi interface, using fallback mode");
                }
                else
                {
                    logger_->info("Using WiFi interface", core::LogContext().add("interface", interface_));
                }

                // Create configuration file
                if (!create_config_file())
                {
                    logger_->error("Failed to create DHCP configuration file");
                    return false;
                }

                // Start dnsmasq process
                if (!start_dnsmasq_process())
                {
                    logger_->error("Failed to start dnsmasq process");
                    remove_config_file();
                    return false;
                }

                // Wait for process to start
                std::this_thread::sleep_for(std::chrono::seconds(2));

                // Verify DHCP server is running
                if (!verify_dhcp_server())
                {
                    logger_->error("DHCP server verification failed");
                    stop_dnsmasq_process();
                    remove_config_file();
                    return false;
                }

                running_ = true;
                logger_->info("DHCP server setup successful",
                              core::LogContext()
                                  .add("interface", interface_)
                                  .add("dhcp_range", dhcp_start_ + "-" + dhcp_end_));
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error setting up DHCP server", core::LogContext().add("error", e.what()));
                teardown_dhcp_server();
                return false;
            }
        }

        bool DHCPServerManager::teardown_dhcp_server()
        {
            if (!running_)
            {
                return true;
            }

            logger_->info("Tearing down DHCP server...");

            try
            {
                // Stop dnsmasq process
                stop_dnsmasq_process();

                // Remove configuration file
                remove_config_file();

                running_ = false;
                interface_.clear();
                dnsmasq_pid_ = -1;

                logger_->info("DHCP server teardown completed");
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error tearing down DHCP server", core::LogContext().add("error", e.what()));
                return false;
            }
        }

        bool DHCPServerManager::verify_dhcp_server() const
        {
            // Check if dnsmasq process is running
            if (!check_dhcp_process())
            {
                logger_->warning("DHCP process not found");
                return false;
            }

            // Check if configuration file exists
            if (!std::filesystem::exists(config_file_))
            {
                logger_->warning("DHCP configuration file missing");
                return false;
            }

            logger_->debug("DHCP server verification successful");
            return true;
        }

        std::string DHCPServerManager::get_status() const
        {
            std::ostringstream status;
            status << "DHCP Server Status:\n";
            status << "  Running: " << (running_ ? "Yes" : "No") << "\n";
            status << "  Interface: " << interface_ << "\n";
            status << "  Server IP: " << server_ip_ << "\n";
            status << "  DHCP Range: " << dhcp_start_ << " - " << dhcp_end_ << "\n";
            status << "  Config File: " << config_file_ << "\n";
            status << "  PID File: " << pid_file_;
            return status.str();
        }

        std::string DHCPServerManager::detect_wifi_interface() const
        {
            std::string output;
            if (!run_command({"ip", "addr", "show"}, &output))
            {
                logger_->error("Failed to get network interfaces");
                return "";
            }

            // Parse output to find interface with our server IP
            std::istringstream stream(output);
            std::string line;
            std::string current_interface;

            std::regex interface_regex(R"(\d+:\s+(\w+):.*UP)");
            std::regex ip_regex(R"(inet\s+)" + server_ip_ + R"(/\d+)");

            while (std::getline(stream, line))
            {
                std::smatch match;

                // Check for interface line
                if (std::regex_search(line, match, interface_regex))
                {
                    current_interface = match[1].str();
                }
                // Check for our IP address on current interface
                else if (!current_interface.empty() && std::regex_search(line, ip_regex))
                {
                    logger_->info("Detected WiFi interface", core::LogContext().add("interface", current_interface));
                    return current_interface;
                }
            }

            logger_->error("No interface found with IP", core::LogContext().add("ip", server_ip_));
            return "";
        }

        bool DHCPServerManager::create_config_file()
        {
            try
            {
                // Ensure config directory exists
                std::filesystem::create_directories(config_dir_);

                std::ofstream config_stream(config_file_);
                if (!config_stream)
                {
                    logger_->error("Cannot create DHCP config file", core::LogContext().add("file", config_file_.string()));
                    return false;
                }

                // Write dnsmasq configuration
                config_stream << "# Mita Router DHCP Configuration for " << config_->router_id << "\n";
                config_stream << "# Auto-generated - do not edit manually\n\n";

                // Basic settings
                if (!interface_.empty())
                {
                    config_stream << "interface=" << interface_ << "\n";
                }
                config_stream << "bind-interfaces\n";
                config_stream << "dhcp-range=" << dhcp_start_ << "," << dhcp_end_ << ",255.255.255.0,12h\n";
                config_stream << "dhcp-option=option:router," << server_ip_ << "\n";
                config_stream << "dhcp-option=option:dns-server," << server_ip_ << "\n";

                // Additional options
                config_stream << "dhcp-authoritative\n";
                config_stream << "dhcp-rapid-commit\n";
                config_stream << "no-resolv\n";
                config_stream << "no-poll\n";
                config_stream << "log-facility=/var/log/dnsmasq-mita-" << config_->router_id << ".log\n";
                config_stream << "pid-file=" << pid_file_ << "\n";

                config_stream.close();

                logger_->debug("DHCP configuration file created", core::LogContext().add("file", config_file_.string()));
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error creating DHCP config file", core::LogContext().add("error", e.what()));
                return false;
            }
        }

        bool DHCPServerManager::remove_config_file()
        {
            try
            {
                if (std::filesystem::exists(config_file_))
                {
                    std::filesystem::remove(config_file_);
                    logger_->debug("DHCP configuration file removed");
                }
                return true;
            }
            catch (const std::exception &e)
            {
                logger_->error("Error removing DHCP config file", core::LogContext().add("error", e.what()));
                return false;
            }
        }

        bool DHCPServerManager::start_dnsmasq_process()
        {
            std::vector<std::string> command = {
                "dnsmasq",
                "--conf-file=" + config_file_.string(),
                "--no-daemon"};

            logger_->debug("Starting dnsmasq process...");

            pid_t pid = fork();
            if (pid == 0)
            {
                // Child process
                std::vector<char *> args;
                for (const auto &arg : command)
                {
                    args.push_back(const_cast<char *>(arg.c_str()));
                }
                args.push_back(nullptr);

                execvp("dnsmasq", args.data());
                exit(1); // If execvp fails
            }
            else if (pid > 0)
            {
                // Parent process
                dnsmasq_pid_ = pid;
                logger_->debug("dnsmasq process started", core::LogContext().add("pid", std::to_string(pid)));
                return true;
            }
            else
            {
                logger_->error("Failed to fork dnsmasq process");
                return false;
            }
        }

        bool DHCPServerManager::stop_dnsmasq_process()
        {
            if (dnsmasq_pid_ > 0)
            {
                logger_->debug("Stopping dnsmasq process", core::LogContext().add("pid", std::to_string(dnsmasq_pid_)));

                if (kill(dnsmasq_pid_, SIGTERM) == 0)
                {
                    // Wait for process to terminate
                    int status;
                    waitpid(dnsmasq_pid_, &status, 0);
                    dnsmasq_pid_ = -1;
                    logger_->debug("dnsmasq process stopped");
                    return true;
                }
                else
                {
                    logger_->warning("Failed to send SIGTERM to dnsmasq process");
                }
            }

            // Try to stop via PID file if direct kill failed
            if (std::filesystem::exists(pid_file_))
            {
                std::ifstream pid_stream(pid_file_);
                std::string pid_str;
                if (std::getline(pid_stream, pid_str))
                {
                    pid_t file_pid = std::stoi(pid_str);
                    if (kill(file_pid, SIGTERM) == 0)
                    {
                        logger_->debug("Stopped dnsmasq via PID file", core::LogContext().add("pid", pid_str));
                        return true;
                    }
                }
            }

            return false;
        }

        void DHCPServerManager::stop_all_dnsmasq_processes()
        {
            std::string output;
            if (run_command({"pgrep", "-f", "dnsmasq.*mita-router"}, &output))
            {
                std::istringstream stream(output);
                std::string pid_str;
                while (std::getline(stream, pid_str))
                {
                    if (!pid_str.empty())
                    {
                        pid_t pid = std::stoi(pid_str);
                        logger_->debug("Stopping existing dnsmasq process", core::LogContext().add("pid", std::to_string(pid)));
                        kill(pid, SIGTERM);
                    }
                }
                // Give processes time to terminate
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        bool DHCPServerManager::check_dhcp_process() const
        {
            std::string output;
            return run_command({"pgrep", "-f", "dnsmasq.*" + config_->router_id}, &output) && !output.empty();
        }

        bool DHCPServerManager::run_command(const std::vector<std::string> &command, std::string *output) const
        {
            std::ostringstream cmd;
            for (size_t i = 0; i < command.size(); ++i)
            {
                if (i > 0)
                    cmd << " ";
                cmd << command[i];
            }

            FILE *pipe = popen((cmd.str() + " 2>/dev/null").c_str(), "r");
            if (!pipe)
            {
                return false;
            }

            if (output)
            {
                output->clear();
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe))
                {
                    *output += buffer;
                }
            }

            int result = pclose(pipe);
            return WIFEXITED(result) && WEXITSTATUS(result) == 0;
        }

    } // namespace infrastructure
} // namespace mita