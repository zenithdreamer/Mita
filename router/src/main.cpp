/**
 * Mita Network Router
 * Main entry point for the C++ router application
 */

#include <iostream>
#include <csignal>
#include <unistd.h>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include "core/router.hpp"
#include "core/config.hpp"
#include "core/logger.hpp"
#include "api/server.hpp"

// Command line argument parsing
#include <getopt.h>

namespace mita {

/**
 * Global router instance for signal handling
 */
std::unique_ptr<core::MitaRouter> g_router;

/**
 * Global API server instance
 */
std::unique_ptr<ApiServer> g_apiServer;

/**
 * Signal handler for graceful shutdown
 */
void signal_handler(int signum) {
    auto logger = core::get_logger("main");
    logger->info("Received signal, shutting down gracefully...",
                core::LogContext().add("signal", signum));

    if (g_apiServer) {
        g_apiServer->stop();
    }

    if (g_router) {
        g_router->stop();
    }

    exit(0);
}

/**
 * Setup signal handlers
 */
void setup_signal_handlers() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
}

/**
 * Check if running with required privileges
 */
bool check_root_privileges() {
    if (geteuid() != 0) {
        std::cerr << "ERROR: This router must be run as root to create WiFi Access Points." << std::endl;
        std::cerr << "Please run with: sudo ./mita_router" << std::endl;
        return false;
    }
    return true;
}

/**
 * Print usage information
 */
void print_usage(const char* program_name) {
    std::cout << "Mita Network Router\n\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config FILE        Configuration file path (default: router_config.json)\n";
    std::cout << "  -v, --verbose            Increase verbosity (-v for INFO, -vv for DEBUG)\n";
    std::cout << "  -l, --log-file FILE      Log to file instead of console\n";
    std::cout << "  -W, --wifi-only          Enable only WiFi transport\n";
    std::cout << "  -B, --ble-only           Enable only BLE transport\n";
    std::cout << "  -D, --no-setup           Skip WiFi AP setup (for development)\n";
    std::cout << "  -s, --status-interval N  Status reporting interval in seconds\n";
    std::cout << "  -h, --help               Show this help message\n";
    std::cout << "  --version                Show version information\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << "                          # Run with default config\n";
    std::cout << "  " << program_name << " -c custom_config.json    # Use custom configuration\n";
    std::cout << "  " << program_name << " -v                       # Verbose logging\n";
    std::cout << "  " << program_name << " -vv                      # Debug logging\n";
    std::cout << "  " << program_name << " --wifi-only              # Enable only WiFi transport\n";
    std::cout << "  " << program_name << " --ble-only               # Enable only BLE transport\n";
    std::cout << std::endl;
}

/**
 * Print version information
 */
void print_version() {
    std::cout << "Mita Router v0.0.1" << std::endl;
    std::cout << "Built for Linux/Raspberry Pi OS" << std::endl;
    std::cout << "Features: WiFi, BLE, Multi-Protocol Routing" << std::endl;
}

/**
 * Parse command line arguments
 */
struct Arguments {
    std::string config_file = "router_config.json";
    int verbosity = 0;
    std::string log_file;
    bool wifi_only = false;
    bool ble_only = false;
    bool no_setup = false;
    int status_interval = -1;
    bool help = false;
    bool version = false;
};

Arguments parse_arguments(int argc, char* argv[]) {
    Arguments args;

    static struct option long_options[] = {
        {"config",          required_argument, 0, 'c'},
        {"verbose",         no_argument,       0, 'v'},
        {"log-file",        required_argument, 0, 'l'},
        {"wifi-only",       no_argument,       0, 'W'},
        {"ble-only",        no_argument,       0, 'B'},
        {"no-setup",        no_argument,       0, 'D'},
        {"status-interval", required_argument, 0, 's'},
        {"help",            no_argument,       0, 'h'},
        {"version",         no_argument,       0, 0},
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "c:vl:WBDs:h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                args.config_file = optarg;
                break;
            case 'v':
                args.verbosity++;
                break;
            case 'l':
                args.log_file = optarg;
                break;
            case 'W':
                args.wifi_only = true;
                break;
            case 'B':
                args.ble_only = true;
                break;
            case 'D':
                args.no_setup = true;
                break;
            case 's':
                args.status_interval = std::stoi(optarg);
                break;
            case 'h':
                args.help = true;
                break;
            case 0:
                if (option_index == 9) { // --version
                    args.version = true;
                }
                break;
            case '?':
                // getopt_long already printed an error message
                exit(1);
                break;
            default:
                std::cerr << "Unknown option: " << c << std::endl;
                exit(1);
        }
    }

    return args;
}

} // namespace mita

/**
 * Main entry point
 *

                                        ███████████████████████████████████████████████████████████████
                                       ██████████████████████████████████████████████████████████████
                                     █████████████████████████████████████████████████████████████████
                                    ███████████████████████████████████████████████████████████████████
                                   █████████████████████████████████████████████████████████████████████
                                  ███████████████████████████████████████████████████████████████████████
                                ██████████████████████████████████████████████████████████████████████████
                             ██████████████████████████████████████████████████████████████████████████████
                              ██████████████████████████████████████████████████████████████████████████████████
                                █████████████████████████████████████████████████████████████████████████ █████
                                █████████████████████████████████████████████████████████████████████████    ██
                               ██████████████████████████████████████████████████████████████████████████
                              ████████████████████████████████████████████████████████████████████████████
                              ████████████████████████▒███████████████████████████████████████████████████
                             ██████████████████████▓▒▒▒███████████████████████▓▓██████████████████████████
                            ███████████████████████▓▓▓▓████████████████████████▓▓▓█████████████████████████
                            ███████████████████████▒▓▒▒▒█████████████████▓█▓▓███▓▓▓▓███████████████████████
                           ███████████████████████▓▒▒▒▒▓██████████████████▓▓▓▓▓▓▓▓▓▓▓██▓███████████████████
                           ███████████████████████▒▓██▓█████████████████▓▓▓▓▓▓█████▓▓█▓▓███████████████████
                          █████████████████████████████████████████████▓▓▓▓▓▓█████▓▓▓█▓█▓███████████████████
                         ██████████████████████▓███▓██████▓████████████▓▓█▓█▓▓▓██████▓█▓▓███████████████████
                         █████████████████████████▓▒██████████████████▓▓▓▓█▓▓▓▓▓▓▓████▓▓▓███████████████████
                        ██████████████████████▓█▓█▓▒▓█▓▓███▓██▒███████▓▓▓▓█▓▓▓▓▓▓▓▓██▓▓▓████████████████████
                       ███████████████████████▓█▒█▒▒▓▒▓███▒▓▒▒▒▒█▒██▓█▒▓▓▓█▓▓▓▓▓▓▓██▓▓▓▓████████████████████
                       █████████████████████████▒▓▒▒▒▒▒▓██▒▒▒▒▒▒▒█▒▒▓█▒▓▓▓▓██▓▓▓▓██▓▓▓▓▓████████████████████
                      ██████████████████████████▒▓▒▒▒▒▒██▒▒▒▒▒▒▒▒▒█▒▒▒▒▓▓▓▓▓▓▓▒▒▒▓▓▓▓▓▓▓█▓██████████████████
                      ███████████████████████████▓▒▒▒▒▓█▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓██████████████████
                     █████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▓▓▓▓▓▓█▓▒▓▓████████████████████
                     ████████████████████████████▒▒█▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▓███████████████████████
                     █████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▓▓▓▒▓██████████████████████████
                    ███████████████████████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▓▒███████████████████████████ ████
                    █████████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓████████████████████████████  ████
                    ███████████████████████████████████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒████████████████████████████    █
                     ██████████████████████████████████▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒███████████████████████████████
                     ██████████████████████████████████▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓█████████▓▓▓████████████████████
                      ████████████████████████████████▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▓▓█████████▓▓▓▓████████████████████
                      ████ ██ ██████████████████████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█████████▓▓▓███████████████████
                       ████      █████████████████████████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████▓▓▓▓▓▓████████████████████
                         ████ █   ██ ██ ██        ██▓████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓████▓▓▓████████████████████
                          █████ ███             ███▓▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▓██▓▓▓▓█████ ██████████████
                             ██  █            ███▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███▓███▓▓▓▓▓██████    ███████
                                          █████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████▓▓▓██ ██        █████
                                    ███████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓████▓▓▓██          █████
                       ██████████████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▓████████████████
                    ████▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▓▓▓██████
                   ██▓▓▓████▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▓▓▓▓█▓▓██


 */
int main(int argc, char* argv[]) {
    using namespace mita;

    try {
        // Parse command line arguments
        auto args = parse_arguments(argc, argv);

        if (args.help) {
            print_usage(argv[0]);
            return 0;
        }

        if (args.version) {
            print_version();
            return 0;
        }

        // Setup logging
        core::LogLevel log_level = core::LogLevel::WARNING;
        if (args.verbosity == 1) {
            log_level = core::LogLevel::INFO;
        } else if (args.verbosity >= 2) {
            log_level = core::LogLevel::DEBUG;
        }

        core::setup_logging(log_level, args.log_file, args.log_file.empty());
        auto logger = core::get_logger("main");

        // Check privileges (unless skipping AP setup)
        if (!args.no_setup && !check_root_privileges()) {
            return 1;
        }

        // Load configuration
        std::unique_ptr<core::RouterConfig> config;
        try {
            config = core::RouterConfig::from_file(args.config_file);
        } catch (const std::exception& e) {
            logger->error("Failed to load configuration",
                         core::LogContext().add("config_file", args.config_file)
                                          .add("error", e.what()));
            return 1;
        }

        // Apply command-line overrides
        if (args.wifi_only) {
            config->wifi.enabled = true;
            config->ble.enabled = false;
            logger->info("WiFi-only mode enabled");
        }

        if (args.ble_only) {
            config->wifi.enabled = false;
            config->ble.enabled = true;
            logger->info("BLE-only mode enabled");
        }

        if (args.no_setup) {
            config->development.skip_ap_setup = true;
            logger->info("Skipping WiFi AP setup (development mode)");
        }

        if (args.status_interval > 0) {
            config->logging.status_interval = args.status_interval;
        }

        // Validate configuration
        if (!config->validate()) {
            logger->error("Configuration validation failed");
            return 1;
        }

        // Setup signal handlers
        setup_signal_handlers();

        // Create and start router
        logger->info("Starting Mita Router...",
                     core::LogContext().add("router_id", config->router_id).add("config_file", args.config_file));

        g_router = std::make_unique<core::MitaRouter>(std::move(config));

        if (!g_router->start()) {
            logger->error("Failed to start router");
            return 1;
        }

        // Start HTTP API server
        logger->info("Starting HTTP API server...");
        g_apiServer = std::make_unique<ApiServer>(
            g_router->get_packet_monitor(),
            g_router->get_device_manager()
        );
        g_apiServer->start("0.0.0.0", 8080);

        // Router runs until stopped by signal
        logger->info("Router started successfully");

        // Keep main thread alive
        while (g_router->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        logger->info("Router stopped");
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}