#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <thread>
#include <chrono>
#include <csignal>

#include <core/settings.hpp>
#include <core/fileconfig.hpp>
#include <core/pack.hpp>
#include <core/filesystem.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  --help                 Show this help message\n"
              << "  --web_server=IP:PORT   Start web server on IP:PORT (e.g., 0.0.0.0:8083)\n"
              << "                         Provides HTTP/JSON-RPC mining interface for miners\n"
              << "                         Supported methods: getwork, submitwork, getblocktemplate,\n"
              << "                         submitblock, getinfo, getstats, mining.subscribe,\n"
              << "                         mining.authorize, mining.submit\n"
              << "  --ui_config            Show UI configuration interface\n"
              << "  --testnet              Enable testnet mode\n"
              << "  --fee=VALUE            Set fee percentage (0.0-100.0)\n"
              << "  --network=NAME         Add network (e.g., LTC, BTC, DGB)\n"
              << std::endl;
}

std::map<std::string, std::string> parse_args(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            args["help"] = "true";
        } else if (arg == "--ui_config") {
            args["ui_config"] = "true";
        } else if (arg == "--testnet") {
            args["testnet"] = "true";
        } else if (arg.find("--web_server=") == 0) {
            args["web_server"] = arg.substr(13);
        } else if (arg.find("--fee=") == 0) {
            args["fee"] = arg.substr(6);
        } else if (arg.find("--network=") == 0) {
            args["network"] = arg.substr(10);
        }
    }
    
    return args;
}

int main(int argc, char *argv[])
{
    // Parse command line arguments
    auto args = parse_args(argc, argv);
    
    if (args.find("help") != args.end()) {
        print_usage(argv[0]);
        return 0;
    }
    
    // Initialize logging
    core::log::Logger::init();
    
    LOG_INFO << "c2pool - p2pool rebirth in C++";
    LOG_INFO << "Starting c2pool node...";
    
    // Load settings
    auto settings = core::Fileconfig::load_file<core::Settings>();
    
    // Apply command line overrides
    if (args.find("testnet") != args.end()) {
        settings->m_testnet = true;
        LOG_INFO << "Testnet mode enabled";
    }
    
    if (args.find("fee") != args.end()) {
        try {
            float fee_val = std::stof(args["fee"]);
            settings->m_fee = fee_val;
            LOG_INFO << "Fee set to: " << fee_val << "%";
        } catch (...) {
            LOG_ERROR << "Invalid fee value: " << args["fee"];
            return 1;
        }
    }
    
    // Show configuration
    LOG_INFO << "Configuration:";
    LOG_INFO << "  Testnet: " << (settings->m_testnet ? "Yes" : "No");
    LOG_INFO << "  Fee: " << settings->m_fee << "%";
    LOG_INFO << "  Networks:";
    for (const auto& net : settings->m_networks) {
        LOG_INFO << "    - " << net;
    }
    
    if (args.find("ui_config") != args.end()) {
        std::cout << "\n=== c2pool Configuration Interface ===\n";
        std::cout << "Current settings loaded from: " << core::filesystem::config_path() / "settings.yaml" << "\n";
        std::cout << "Testnet: " << (settings->m_testnet ? "Yes" : "No") << "\n";
        std::cout << "Fee: " << settings->m_fee << "%\n";
        std::cout << "Networks: ";
        for (size_t i = 0; i < settings->m_networks.size(); i++) {
            std::cout << settings->m_networks[i];
            if (i < settings->m_networks.size() - 1) std::cout << ", ";
        }
        std::cout << "\n\nTo modify settings, edit: " << core::filesystem::config_path() / "settings.yaml" << "\n";
        return 0;
    }
    
    if (args.find("web_server") != args.end()) {
        std::string server_addr = args["web_server"];
        LOG_INFO << "Starting web server on: " << server_addr;
        
        // Parse IP and port
        size_t colon_pos = server_addr.find(':');
        if (colon_pos == std::string::npos) {
            LOG_ERROR << "Invalid web_server format. Use IP:PORT (e.g., 0.0.0.0:8083)";
            return 1;
        }
        
        std::string ip = server_addr.substr(0, colon_pos);
        std::string port_str = server_addr.substr(colon_pos + 1);
        
        try {
            int port = std::stoi(port_str);
            
            // Create boost::asio context
            boost::asio::io_context ioc;
            
            // Create and start web server
            core::WebServer web_server(ioc, ip, static_cast<uint16_t>(port));
            
            if (!web_server.start()) {
                LOG_ERROR << "Failed to start web server on " << ip << ":" << port;
                return 1;
            }
            
            LOG_INFO << "Web server started successfully on " << ip << ":" << port;
            LOG_INFO << "Mining interface available at http://" << ip << ":" << port;
            LOG_INFO << "Supported methods: getwork, submitwork, getblocktemplate, submitblock, getinfo, getstats";
            
            // Create a MiningInterface to check sync status
            auto mining_interface = std::make_shared<core::MiningInterface>();
            
            // Check and log initial sync status
            LOG_INFO << "Checking Litecoin Core synchronization status...";
            mining_interface->log_sync_progress();
            
            bool stratum_started = false;
            if (!mining_interface->is_blockchain_synced()) {
                LOG_WARNING << "Blockchain is not synchronized - Stratum server will start when sync completes";
                LOG_INFO << "HTTP interface is available, but mining will be rejected until synchronized";
            } else {
                LOG_INFO << "Blockchain is synchronized - Starting Stratum server for mining!";
                if (web_server.start_stratum_server()) {
                    stratum_started = true;
                }
            }
            
            // Set up periodic sync status logging and Stratum server management
            boost::asio::steady_timer sync_timer(ioc);
            std::function<void()> check_sync_status = [&]() {
                bool is_synced = mining_interface->is_blockchain_synced();
                
                if (!is_synced) {
                    mining_interface->log_sync_progress();
                } else if (!stratum_started) {
                    // Blockchain just became synced - start Stratum server
                    LOG_INFO << "Blockchain sync complete! Starting Stratum server...";
                    if (web_server.start_stratum_server()) {
                        stratum_started = true;
                        LOG_INFO << "Pool is now ready for mining!";
                    }
                }
                
                sync_timer.expires_after(std::chrono::seconds(10)); // Check every 10 seconds during sync
                sync_timer.async_wait([&](const boost::system::error_code&) {
                    check_sync_status();
                });
            };
            check_sync_status();
            
            LOG_INFO << "Press Ctrl+C to stop.";
            
            // Install signal handler for graceful shutdown
            boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
            signals.async_wait([&](const boost::system::error_code&, int) {
                LOG_INFO << "Shutdown signal received, stopping web server...";
                web_server.stop();
                ioc.stop();
            });
            
            // Run the I/O context
            ioc.run();
            
            LOG_INFO << "Web server shutdown complete";
            return 0;
            
        } catch (...) {
            LOG_ERROR << "Invalid port number: " << port_str;
            return 1;
        }
    }
    
    LOG_INFO << "c2pool node initialized successfully";
    LOG_INFO << "Use --help for available options";
    
    return 0;
}