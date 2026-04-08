#include "web_server.hpp"
#include "stratum_server.hpp"
#include "address_utils.hpp"

// Real coin daemon RPC (optional - only linked when set_coin_rpc() is called)
#include <impl/ltc/coin/rpc.hpp>
#include <impl/ltc/coin/node_interface.hpp>
// Phase 4: embedded coin node interface
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/share_messages.hpp>

#include <core/hash.hpp>   // Hash(a,b) double-SHA256 for merkle computation
#include <core/random.hpp> // core::random::random_float for probabilistic fee
#include <core/target_utils.hpp> // chain::bits_to_target
#include <btclibs/util/strencodings.h>  // ParseHex, HexStr
#include <crypto/scrypt.h>  // scrypt_1024_1_1_256 for Litecoin PoW
#include <crypto/sha256.h>      // CSHA256 for P2PK→P2PKH conversion
#include <crypto/ripemd160.h>   // CRIPEMD160 for Hash160
#include <c2pool/merged/merged_mining.hpp>  // Integrated merged mining
#include <impl/ltc/config_pool.hpp>          // PoolConfig::is_testnet for donation addr

#include <iomanip>
#include <sstream>
#include <set>
#include <ctime>
#include <chrono>
#include <cmath>
#include <fstream>
#include <boost/process.hpp>
#include <boost/algorithm/string.hpp>
#include "btclibs/base58.h"
#include "btclibs/bech32.h"
#include "filesystem.hpp"

namespace core {

static std::string to_hex(const std::vector<unsigned char>& data)
{
    return HexStr(std::span<const unsigned char>(data.data(), data.size()));
}

// ── Security helpers ───────────────────────────────────────────────────
// URL-decode percent-encoded strings (%20 → space, etc.)
static std::string url_decode(const std::string& str)
{
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int hi = 0, lo = 0;
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            hi = hexval(str[i + 1]);
            lo = hexval(str[i + 2]);
            if (hi >= 0 && lo >= 0) {
                result += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        } else if (str[i] == '+') {
            result += ' ';
            continue;
        }
        result += str[i];
    }
    return result;
}

// Validate that a string is a hex hash (exactly 64 hex chars)
static bool is_valid_hex_hash(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

// Validate that a string looks like a cryptocurrency address (base58/bech32 charset, reasonable length)
static bool is_valid_address_chars(const std::string& s)
{
    if (s.empty() || s.size() > 128) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            return false;
    }
    return true;
}

// Validate graph source/view against allowed charset (alphanumeric + underscore, max 64 chars)
static bool is_valid_graph_param(const std::string& s)
{
    if (s.empty() || s.size() > 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'))
            return false;
    }
    return true;
}

/// HttpSession Implementation
HttpSession::HttpSession(tcp::socket socket, std::shared_ptr<MiningInterface> mining_interface)
    : socket_(std::move(socket))
    , mining_interface_(mining_interface)
{
}

void HttpSession::run()
{
    read_request();
}

void HttpSession::read_request()
{
    auto self = shared_from_this();
    
    http::async_read(socket_, buffer_, request_,
        [self](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec == http::error::end_of_stream)
                return self->handle_error(ec, "read_request");
                
            if(ec)
                return self->handle_error(ec, "read_request");
                
            self->process_request();
        });
}

void HttpSession::process_request()
{
    // Create HTTP response
    http::response<http::string_body> response{http::status::ok, request_.version()};
    response.set(http::field::server, "c2pool/0.0.1");
    response.set(http::field::content_type, "application/json");

    // CORS — only set if operator configured an origin
    const auto& cors_origin = mining_interface_->get_cors_origin();
    if (!cors_origin.empty()) {
        response.set(http::field::access_control_allow_origin, cors_origin);
        response.set(http::field::access_control_allow_methods, "GET, POST, OPTIONS");
        response.set(http::field::access_control_allow_headers, "Content-Type");
    }

    // Security headers
    response.set("X-Content-Type-Options", "nosniff");
    response.set("X-Frame-Options", "DENY");
    response.set("Referrer-Policy", "no-referrer");

    try {
        std::string response_body;
        
        if (request_.method() == http::verb::options) {
            // Handle CORS preflight
            response_body = "";
        }
        else if (request_.method() == http::verb::get) {
            // Path-based REST routing for p2pool-compatible endpoints
            std::string raw_target(request_.target());
            std::string target(raw_target);
            // Strip query string
            auto qpos = target.find('?');
            if (qpos != std::string::npos) target = target.substr(0, qpos);

            auto getQueryParam = [&raw_target](const std::string& key) -> std::string {
                const auto qp = raw_target.find('?');
                if (qp == std::string::npos) {
                    return {};
                }
                const std::string query = raw_target.substr(qp + 1);
                const std::string prefix = key + "=";
                auto pos = query.find(prefix);
                if (pos == std::string::npos) {
                    return {};
                }
                pos += prefix.size();
                auto end = query.find('&', pos);
                if (end == std::string::npos) {
                    end = query.size();
                }
                return url_decode(query.substr(pos, end - pos));
            };

            // ── Auth gate for sensitive endpoints ──────────────────────
            if (mining_interface_->auth_required()) {
                bool needs_auth = (target.substr(0, 9) == "/control/"
                                || target == "/web/log"
                                || target == "/logs/export");
                if (needs_auth) {
                    const std::string token = getQueryParam("token");
                    if (!mining_interface_->verify_auth_token(token)) {
                        response.result(http::status::unauthorized);
                        response.body() = R"({"error":"Unauthorized – supply ?token=<auth_token>"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }
                }
            }

            nlohmann::json rest_result;
            if (target == "/local_rate")
                rest_result = mining_interface_->rest_local_rate();
            else if (target == "/global_rate")
                rest_result = mining_interface_->rest_global_rate();
            else if (target == "/current_payouts")
                rest_result = mining_interface_->rest_current_payouts();
            else if (target == "/users")
                rest_result = mining_interface_->rest_users();
            else if (target == "/fee")
                rest_result = mining_interface_->rest_fee();
            else if (target == "/recent_blocks")
                rest_result = mining_interface_->rest_recent_blocks();
            else if (target == "/checkpoint")
                rest_result = mining_interface_->rest_checkpoint();
            else if (target == "/checkpoints")
                rest_result = mining_interface_->rest_checkpoints();
            else if (target == "/uptime")
                rest_result = mining_interface_->rest_uptime();
            else if (target == "/connected_miners")
                rest_result = mining_interface_->rest_connected_miners();
            else if (target == "/stratum_stats")
                rest_result = mining_interface_->rest_stratum_stats();
            else if (target == "/global_stats")
                rest_result = mining_interface_->rest_global_stats();
            else if (target == "/sharechain/stats")
                rest_result = mining_interface_->rest_sharechain_stats();
            else if (target == "/sharechain/window")
                rest_result = mining_interface_->rest_sharechain_window();
            else if (target == "/sharechain/tip")
                rest_result = mining_interface_->rest_sharechain_tip();
            else if (target == "/sharechain/delta") {
                rest_result = mining_interface_->rest_sharechain_delta(getQueryParam("since"));
            }
            else if (target == "/control/mining/start")
                rest_result = mining_interface_->rest_control_mining_start();
            else if (target == "/control/mining/stop")
                rest_result = mining_interface_->rest_control_mining_stop();
            else if (target == "/control/mining/restart")
                rest_result = mining_interface_->rest_control_mining_restart();
            else if (target == "/control/mining/ban")
                rest_result = mining_interface_->rest_control_mining_ban(getQueryParam("target"));
            else if (target == "/control/mining/unban")
                rest_result = mining_interface_->rest_control_mining_unban(getQueryParam("target"));
            else if (target == "/web/log") {
                // Return plain text log (not JSON)
                response.set(http::field::content_type, "text/plain; charset=utf-8");
                response.body() = mining_interface_->rest_web_log();
                response.prepare_payload();
                send_response(std::move(response));
                return;
            }
            else if (target == "/logs/export") {
                const std::string scope = getQueryParam("scope");
                int64_t from_ts = 0, to_ts = 0;
                try { from_ts = std::stoll(getQueryParam("from")); } catch (...) {}
                try { to_ts = std::stoll(getQueryParam("to")); } catch (...) {}
                const std::string fmt = getQueryParam("format");
                response.set(http::field::content_type,
                    (fmt == "csv") ? "text/csv; charset=utf-8" :
                    (fmt == "jsonl") ? "application/x-ndjson; charset=utf-8" :
                    "text/plain; charset=utf-8");
                response.body() = mining_interface_->rest_logs_export(scope, from_ts, to_ts, fmt);
                response.prepare_payload();
                send_response(std::move(response));
                return;
            }
            // ── p2pool legacy compatibility endpoints ──────────────────────
            else if (target == "/local_stats")
                rest_result = mining_interface_->rest_local_stats();
            else if (target == "/miner_thresholds")
                rest_result = mining_interface_->rest_miner_thresholds();
            else if (target == "/web/version")
                rest_result = mining_interface_->rest_web_version();
            else if (target == "/web/currency_info")
                rest_result = mining_interface_->rest_web_currency_info();
            else if (target == "/payout_addr")
                rest_result = mining_interface_->rest_payout_addr();
            else if (target == "/payout_addrs")
                rest_result = mining_interface_->rest_payout_addrs();
            else if (target == "/web/best_share_hash")
                rest_result = mining_interface_->rest_web_best_share_hash();
            else if (target == "/p2pool_global_stats")
                rest_result = mining_interface_->rest_p2pool_global_stats();

            // ── Additional p2pool-compatible REST endpoints ────────────────
            else if (target == "/rate")
                rest_result = mining_interface_->rest_rate();
            else if (target == "/difficulty")
                rest_result = mining_interface_->rest_difficulty();
            else if (target == "/user_stales")
                rest_result = mining_interface_->rest_user_stales();
            else if (target == "/peer_addresses") {
                response.set(http::field::content_type, "text/plain; charset=utf-8");
                response.body() = mining_interface_->rest_peer_addresses();
                response.prepare_payload();
                send_response(std::move(response));
                return;
            }
            else if (target == "/peer_versions")
                rest_result = mining_interface_->rest_peer_versions();
            else if (target == "/peer_txpool_sizes")
                rest_result = mining_interface_->rest_peer_txpool_sizes();
            else if (target == "/peer_list")
                rest_result = mining_interface_->rest_peer_list();
            else if (target == "/pings")
                rest_result = mining_interface_->rest_pings();
            else if (target == "/stale_rates")
                rest_result = mining_interface_->rest_stale_rates();
            else if (target == "/node_info")
                rest_result = mining_interface_->rest_node_info();
            else if (target == "/luck_stats")
                rest_result = mining_interface_->rest_luck_stats();
            else if (target == "/ban_stats")
                rest_result = mining_interface_->rest_ban_stats();
            else if (target == "/stratum_security")
                rest_result = mining_interface_->rest_stratum_security();
            else if (target == "/best_share")
                rest_result = mining_interface_->rest_best_share();
            else if (target == "/version_signaling")
                rest_result = mining_interface_->rest_version_signaling();
            else if (target == "/v36_status")
                rest_result = mining_interface_->rest_v36_status();
            else if (target == "/tracker_debug")
                rest_result = mining_interface_->rest_tracker_debug();

            // Merged mining endpoints
            else if (target == "/merged_stats")
                rest_result = mining_interface_->rest_merged_stats();
            else if (target == "/current_merged_payouts")
                rest_result = mining_interface_->rest_current_merged_payouts();
            else if (target == "/recent_merged_blocks")
                rest_result = mining_interface_->rest_recent_merged_blocks();
            else if (target == "/all_merged_blocks")
                rest_result = mining_interface_->rest_all_merged_blocks();
            else if (target == "/discovered_merged_blocks")
                rest_result = mining_interface_->rest_discovered_merged_blocks();
            else if (target == "/broadcaster_status")
                rest_result = mining_interface_->rest_broadcaster_status();
            else if (target == "/merged_broadcaster_status")
                rest_result = mining_interface_->rest_merged_broadcaster_status();
            else if (target == "/network_difficulty")
                rest_result = mining_interface_->rest_network_difficulty();

            // /web/ sub-endpoints (share chain inspection)
            else if (target == "/web/heads")
                rest_result = mining_interface_->rest_web_heads();
            else if (target == "/web/verified_heads")
                rest_result = mining_interface_->rest_web_verified_heads();
            else if (target == "/web/tails")
                rest_result = mining_interface_->rest_web_tails();
            else if (target == "/web/verified_tails")
                rest_result = mining_interface_->rest_web_verified_tails();
            else if (target == "/web/my_share_hashes")
                rest_result = mining_interface_->rest_web_my_share_hashes();
            else if (target == "/web/my_share_hashes50")
                rest_result = mining_interface_->rest_web_my_share_hashes50();
            else if (target == "/web/log_json")
                rest_result = mining_interface_->rest_web_log_json();

            // Path-parameterised endpoints (starts_with matching)
            // Each path parameter is URL-decoded and validated before use.
            else if (target.substr(0, 13) == "/miner_stats/") {
                std::string addr = url_decode(target.substr(13));
                if (!is_valid_address_chars(addr)) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid address parameter"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                rest_result = mining_interface_->rest_miner_stats(addr);
            }
            else if (target.substr(0, 15) == "/miner_payouts/") {
                std::string addr = url_decode(target.substr(15));
                if (!is_valid_address_chars(addr)) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid address parameter"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                rest_result = mining_interface_->rest_miner_payouts(addr);
            }
            else if (target.substr(0, 18) == "/patron_sendmany/") {
                std::string total = url_decode(target.substr(18));
                if (!is_valid_address_chars(total)) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid parameter"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                response.set(http::field::content_type, "text/plain; charset=utf-8");
                response.body() = mining_interface_->rest_patron_sendmany(total).dump();
                response.prepare_payload();
                send_response(std::move(response));
                return;
            }
            else if (target.substr(0, 11) == "/web/share/") {
                std::string hash = url_decode(target.substr(11));
                if (!is_valid_hex_hash(hash)) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid hash – expected 64 hex characters"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                rest_result = mining_interface_->rest_web_share(hash);
            }
            else if (target.substr(0, 20) == "/web/payout_address/") {
                std::string hash = url_decode(target.substr(20));
                if (!is_valid_hex_hash(hash)) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid hash – expected 64 hex characters"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                rest_result = mining_interface_->rest_web_payout_address(hash);
            }
            else if (target.substr(0, 16) == "/web/graph_data/") {
                // /web/graph_data/<source>/<view>
                std::string rest_path = url_decode(target.substr(16));
                auto slash_pos = rest_path.find('/');
                std::string source = (slash_pos != std::string::npos) ? rest_path.substr(0, slash_pos) : rest_path;
                std::string view   = (slash_pos != std::string::npos) ? rest_path.substr(slash_pos + 1) : "";
                if (!is_valid_graph_param(source) || (!view.empty() && !is_valid_graph_param(view))) {
                    response.result(http::status::bad_request);
                    response.body() = R"({"error":"Invalid graph source/view parameter"})";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                rest_result = mining_interface_->rest_web_graph_data(source, view);
            }

            else {
                // ── Explorer API endpoints (loopback-only) ────────────────
                if (target.substr(0, 14) == "/api/explorer/") {
                    // Loopback guard: only accept requests from 127.0.0.1 / ::1
                    auto remote_addr = socket_.remote_endpoint().address();
                    if (!remote_addr.is_loopback()) {
                        response.result(http::status::forbidden);
                        response.body() = R"({"error":"Explorer API is local-only"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }

                    if (!mining_interface_->is_explorer_enabled()) {
                        response.result(http::status::not_found);
                        response.body() = R"({"error":"Explorer not enabled"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }

                    std::string chain = getQueryParam("chain");
                    if (chain.empty()) chain = "ltc";

                    std::string ep = target.substr(14);

                    if (ep == "getblockchaininfo" && mining_interface_->has_explorer_chaininfo_fn()) {
                        rest_result = mining_interface_->call_explorer_chaininfo(chain);
                    } else if (ep == "getblockhash" && mining_interface_->has_explorer_blockhash_fn()) {
                        std::string height_str = getQueryParam("height");
                        uint32_t h = 0;
                        try { h = static_cast<uint32_t>(std::stoul(height_str)); } catch (...) {}
                        auto hash = mining_interface_->call_explorer_blockhash(h, chain);
                        if (hash.empty()) {
                            rest_result = nlohmann::json{{"error", "Block not found"}};
                        } else {
                            rest_result = nlohmann::json{{"result", hash}};
                        }
                    } else if (ep == "getblock" && mining_interface_->has_explorer_getblock_fn()) {
                        std::string hash = getQueryParam("hash");
                        // Also support height lookup
                        if (hash.empty()) {
                            std::string h_str = getQueryParam("height");
                            if (!h_str.empty() && mining_interface_->has_explorer_blockhash_fn()) {
                                uint32_t h = 0;
                                try { h = static_cast<uint32_t>(std::stoul(h_str)); } catch (...) {}
                                hash = mining_interface_->call_explorer_blockhash(h, chain);
                            }
                        }
                        if (hash.empty()) {
                            rest_result = nlohmann::json{{"error", "Missing hash or height parameter"}};
                        } else {
                            rest_result = mining_interface_->call_explorer_getblock(hash, chain);
                        }
                    } else if (ep == "getmempoolinfo" && mining_interface_->has_explorer_mempoolinfo_fn()) {
                        rest_result = mining_interface_->call_explorer_mempoolinfo(chain);
                    } else if (ep == "getrawmempool" && mining_interface_->has_explorer_rawmempool_fn()) {
                        bool verbose = getQueryParam("verbose") == "true";
                        uint32_t limit = 500;
                        try { auto ls = getQueryParam("limit"); if (!ls.empty()) limit = std::min(5000u, static_cast<uint32_t>(std::stoul(ls))); } catch (...) {}
                        rest_result = mining_interface_->call_explorer_rawmempool(chain, verbose, limit);
                    } else if (ep == "getmempoolentry" && mining_interface_->has_explorer_mempoolentry_fn()) {
                        std::string txid_param = getQueryParam("txid");
                        if (txid_param.empty()) {
                            rest_result = nlohmann::json{{"error", "Missing txid parameter"}};
                        } else {
                            rest_result = mining_interface_->call_explorer_mempoolentry(txid_param, chain);
                        }
                    } else {
                        rest_result = nlohmann::json{{"error", "Unknown explorer endpoint"}};
                    }
                }
                else {
                // ── Static file serving (dashboard gate) ───────────────────
                const auto& dashboard_dir = mining_interface_->get_dashboard_dir();
                if (!dashboard_dir.empty()) {
                    std::string file_path = target;
                    if (file_path == "/" || file_path.empty()) file_path = "/dashboard.html";

                    std::error_code fec;
                    std::filesystem::path base = std::filesystem::weakly_canonical(dashboard_dir);
                    std::filesystem::path requested = base / file_path.substr(1);
                    auto resolved = std::filesystem::canonical(requested, fec);

                    if (!fec && resolved.string().substr(0, base.string().size()) == base.string()
                             && std::filesystem::is_regular_file(resolved))
                    {
                        // MIME type detection
                        std::string ext = resolved.extension().string();
                        std::string mime = "application/octet-stream";
                        if (ext == ".html" || ext == ".htm") mime = "text/html; charset=utf-8";
                        else if (ext == ".js")   mime = "application/javascript; charset=utf-8";
                        else if (ext == ".css")  mime = "text/css; charset=utf-8";
                        else if (ext == ".json") mime = "application/json; charset=utf-8";
                        else if (ext == ".ico")  mime = "image/x-icon";
                        else if (ext == ".png")  mime = "image/png";
                        else if (ext == ".svg")  mime = "image/svg+xml";
                        else if (ext == ".txt")  mime = "text/plain; charset=utf-8";
                        else if (ext == ".woff2") mime = "font/woff2";
                        else if (ext == ".woff") mime = "font/woff";
                        else if (ext == ".map")  mime = "application/json";

                        std::ifstream file(resolved, std::ios::binary);
                        std::string contents((std::istreambuf_iterator<char>(file)),
                                             std::istreambuf_iterator<char>());

                        // Inject analytics tag into HTML pages if configured
                        const auto& analytics_id = mining_interface_->get_analytics_id();
                        if (!analytics_id.empty() && (ext == ".html" || ext == ".htm")) {
                            auto pos = contents.find("</head>");
                            if (pos == std::string::npos) pos = contents.find("</HEAD>");
                            if (pos != std::string::npos) {
                                std::string tag =
                                    "<!-- analytics -->\n"
                                    "<script async src=\"https://www.googletagmanager.com/gtag/js?id=" + analytics_id + "\"></script>\n"
                                    "<script>\n"
                                    "window.dataLayer=window.dataLayer||[];\n"
                                    "function gtag(){dataLayer.push(arguments);}\n"
                                    "gtag('js',new Date());\n"
                                    "gtag('config','" + analytics_id + "');\n"
                                    "</script>\n";
                                contents.insert(pos, tag);
                            }
                        }

                        // Inject explorer nav link if configured
                        const auto& explorer_url = mining_interface_->get_explorer_url();
                        if (!explorer_url.empty() && mining_interface_->is_explorer_enabled()
                            && (ext == ".html" || ext == ".htm"))
                        {
                            // Find "Classic" nav link and insert Explorer after it
                            auto pos = contents.find(R"(>Classic</a>)");
                            if (pos != std::string::npos) {
                                pos += 12;  // skip ">Classic</a>"
                                std::string link = "\n        <a href=\"" + explorer_url + "\" target=\"_blank\">Explorer</a>";
                                contents.insert(pos, link);
                            }
                        }

                        response.set(http::field::content_type, mime);
                        response.set(http::field::cache_control, "public, max-age=3600");
                        response.body() = std::move(contents);
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }
                }
                // Fallback to getinfo JSON
                rest_result = mining_interface_->getinfo();
                }  // end static file serving else
            }  // end explorer/static dispatch

            response_body = rest_result.dump();
        }
        else if (request_.method() == http::verb::post) {
            // Handle JSON-RPC POST request
            std::string request_body = request_.body();
            LOG_INFO << "Received JSON-RPC request: " << request_body;
            
            response_body = mining_interface_->HandleRequest(request_body);
            
            LOG_INFO << "Sending JSON-RPC response: " << response_body;
        }
        else {
            response.result(http::status::method_not_allowed);
            response_body = R"({"error":"Method not allowed"})";
        }
        
        response.body() = response_body;
        response.prepare_payload();
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Error processing request: " << e.what();
        response.result(http::status::internal_server_error);
        response.body() = R"({"error":"Internal server error"})";
        response.prepare_payload();
    }
    
    send_response(std::move(response));
}

void HttpSession::send_response(http::response<http::string_body> response)
{
    auto self = shared_from_this();
    
    auto response_ptr = std::make_shared<http::response<http::string_body>>(std::move(response));
    
    http::async_write(socket_, *response_ptr,
        [self, response_ptr](beast::error_code ec, std::size_t bytes_transferred)
        {
            boost::ignore_unused(bytes_transferred);
            
            if(ec)
                return self->handle_error(ec, "send_response");
                
            // Gracefully close the connection
            beast::error_code close_ec;
            self->socket_.shutdown(tcp::socket::shutdown_send, close_ec);
        });
}

void HttpSession::handle_error(beast::error_code ec, char const* what)
{
    if (ec != beast::errc::operation_canceled && ec != beast::errc::broken_pipe) {
        LOG_WARNING << "HTTP Session error in " << what << ": " << ec.message();
    }
}

/// MiningInterface Implementation
MiningInterface::MiningInterface(bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : m_work_id_counter(1)
    , m_rpc_client(std::make_unique<LitecoinRpcClient>(testnet))
    , m_testnet(testnet)
    , m_blockchain(blockchain)
    , m_node(node)
    , m_address_validator(blockchain, testnet ? Network::TESTNET : Network::MAINNET)
    , m_payout_manager(std::make_unique<c2pool::payout::PayoutManager>(1.0, 86400)) // 1% fee, 24h window
    , m_solo_mode(false)
    , m_solo_address("")
{
    setup_methods();
}

void MiningInterface::setup_methods()
{
    // Core mining methods - explicitly cast to MethodHandle
    Add("getwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getwork();
    }));
    
    Add("submitwork", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 3) {
            throw jsonrpccxx::JsonRpcException(-1, "submitwork requires 3 parameters");
        }
        return submitwork(params[0], params[1], params[2]);
    }));
    
    Add("getblocktemplate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        nlohmann::json template_params = params.empty() ? nlohmann::json::array() : params;
        return getblocktemplate(template_params);
    }));
    
    Add("submitblock", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "submitblock requires hex data parameter");
        }
        return submitblock(params[0]);
    }));
    
    // Pool info methods
    Add("getinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getinfo();
    }));
    
    Add("getstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getstats();
    }));
    
    Add("getpeerinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpeerinfo();
    }));
    
    // Stratum methods
    Add("mining.subscribe", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        std::string user_agent = params.empty() ? "" : params[0];
        return mining_subscribe(user_agent);
    }));
    
    Add("mining.authorize", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 2) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.authorize requires username and password");
        }
        return mining_authorize(params[0], params[1]);
    }));
    
    Add("mining.submit", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.size() < 5) {
            throw jsonrpccxx::JsonRpcException(-1, "mining.submit requires 5 parameters");
        }
        return mining_submit(params[0], params[1], "", params[2], params[3], params[4]);
    }));
    
    // Enhanced payout and coinbase methods
    Add("validate_address", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_address requires address parameter");
        }
        return validate_address(params[0]);
    }));
    
    Add("build_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "build_coinbase requires parameters object");
        }
        return build_coinbase(params);
    }));
    
    Add("validate_coinbase", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "validate_coinbase requires coinbase hex parameter");
        }
        return validate_coinbase(params[0]);
    }));
    
    Add("getblockcandidate", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getblockcandidate(params);
    }));
    
    Add("getpayoutinfo", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getpayoutinfo();
    }));
    
    Add("getminerstats", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getminerstats();
    }));

    Add("setmessageblob", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        if (params.empty()) {
            throw jsonrpccxx::JsonRpcException(-1, "setmessageblob requires hex blob parameter");
        }
        return setmessageblob(params[0]);
    }));

    Add("getmessageblob", jsonrpccxx::MethodHandle([this](const nlohmann::json& params) -> nlohmann::json {
        return getmessageblob();
    }));
}

void MiningInterface::load_transition_blobs(const std::string& dir_path)
{
    namespace fs = std::filesystem;
    if (!fs::is_directory(dir_path)) return;

    int loaded = 0;
    for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".hex") continue;

        // Read hex file
        std::ifstream f(entry.path());
        if (!f) continue;
        std::string hex_str;
        std::getline(f, hex_str);
        // Trim whitespace
        while (!hex_str.empty() && (hex_str.back() == '\n' || hex_str.back() == '\r' || hex_str.back() == ' '))
            hex_str.pop_back();
        if (hex_str.empty()) continue;

        auto blob = ParseHex(hex_str);
        if (blob.empty()) continue;

        auto unpacked = ltc::unpack_share_messages(blob.data(), blob.size());
        if (!unpacked.decrypted) continue;

        auto now = static_cast<uint32_t>(std::time(nullptr));
        for (const auto& msg : unpacked.messages) {
            // Decode payload as UTF-8 text, try JSON
            std::string payload_text(msg.payload.begin(), msg.payload.end());
            nlohmann::json payload_json;
            try { payload_json = nlohmann::json::parse(payload_text); } catch (...) {}

            if (msg.msg_type == ltc::MSG_TRANSITION_SIGNAL && m_cached_transition_message.is_null()) {
                nlohmann::json tmsg = nlohmann::json::object();
                if (payload_json.is_object()) {
                    tmsg["msg"] = payload_json.value("msg", "");
                    tmsg["url"] = payload_json.value("url", "");
                    tmsg["urgency"] = payload_json.value("urg", "info");
                    tmsg["from_ver"] = payload_json.value("from", "");
                    tmsg["to_ver"] = payload_json.value("to", "");
                } else {
                    tmsg["msg"] = payload_text;
                    tmsg["urgency"] = "info";
                }
                tmsg["timestamp"] = msg.timestamp;
                tmsg["verified"] = true;
                tmsg["authority"] = (msg.wire_flags & ltc::FLAG_PROTOCOL_AUTHORITY) != 0;
                m_cached_transition_message = tmsg;
                ++loaded;
            } else if (msg.msg_type == ltc::MSG_POOL_ANNOUNCE || msg.msg_type == ltc::MSG_EMERGENCY) {
                nlohmann::json ann = nlohmann::json::object();
                ann["type"] = (msg.msg_type == ltc::MSG_EMERGENCY) ? "EMERGENCY" : "POOL_ANNOUNCE";
                ann["type_id"] = msg.msg_type;
                ann["timestamp"] = msg.timestamp;
                ann["age"] = (now > msg.timestamp) ? static_cast<int>(now - msg.timestamp) : 0;
                ann["verified"] = true;
                ann["authority"] = (msg.wire_flags & ltc::FLAG_PROTOCOL_AUTHORITY) != 0;
                if (payload_json.is_object()) {
                    ann["text"] = payload_json.value("msg", payload_json.value("text", ""));
                    ann["urgency"] = payload_json.value("urg", payload_json.value("urgency", "info"));
                    ann["url"] = payload_json.value("url", "");
                } else {
                    ann["text"] = payload_text;
                    ann["urgency"] = (msg.msg_type == ltc::MSG_EMERGENCY) ? "alert" : "info";
                }
                m_cached_authority_announcements.push_back(ann);
                ++loaded;
            }
        }
    }
    if (loaded > 0)
        LOG_INFO << "Messaging: loaded " << loaded << " transition message(s) from " << dir_path;
}

void MiningInterface::set_operator_message_blob(const std::vector<unsigned char>& blob)
{
    std::lock_guard<std::mutex> lock(m_message_blob_mutex);
    m_operator_message_blob = blob;
}

std::vector<unsigned char> MiningInterface::get_operator_message_blob() const
{
    std::lock_guard<std::mutex> lock(m_message_blob_mutex);
    return m_operator_message_blob;
}

// ─── Live coin-daemon integration ────────────────────────────────────────────

void MiningInterface::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc  = rpc;
    m_coin_node = coin;
    LOG_INFO << "MiningInterface: coin RPC " << (rpc ? "connected" : "disconnected");
}

void MiningInterface::set_embedded_node(ltc::coin::CoinNodeInterface* node)
{
    m_embedded_node = node;
    LOG_INFO << "MiningInterface: embedded coin node " << (node ? "connected" : "disconnected");
}

void MiningInterface::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    m_on_block_submitted = std::move(fn);
}

void MiningInterface::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    m_on_block_relay = std::move(fn);
}

void MiningInterface::set_rpc_submit_fallback(std::function<std::string(const std::string&)> fn)
{
    m_rpc_submit_fallback = std::move(fn);
}

bool MiningInterface::has_merged_chain(uint32_t chain_id) const
{
    if (!m_mm_manager) return false;
    return m_mm_manager->get_chain_rpc(chain_id) != nullptr;
}

std::string MiningInterface::get_node_fee_hash160() const
{
    // Extract hash160 from scriptPubKey (P2PKH, P2SH, or P2WPKH)
    int h160_off = -1;
    auto sz = m_node_fee_script.size();
    if (sz == 25 && m_node_fee_script[0] == 0x76 &&
        m_node_fee_script[1] == 0xa9 && m_node_fee_script[2] == 0x14)
        h160_off = 3;   // P2PKH
    else if (sz == 23 && m_node_fee_script[0] == 0xa9 &&
             m_node_fee_script[1] == 0x14)
        h160_off = 2;   // P2SH
    else if (sz == 22 && m_node_fee_script[0] == 0x00 &&
             m_node_fee_script[1] == 0x14)
        h160_off = 2;   // P2WPKH
    if (h160_off < 0) return {};
    static const char* HEX = "0123456789abcdef";
    std::string h160;
    h160.reserve(40);
    for (int i = h160_off; i < h160_off + 20; ++i) {
        h160 += HEX[m_node_fee_script[i] >> 4];
        h160 += HEX[m_node_fee_script[i] & 0x0f];
    }
    return h160;
}

bool MiningInterface::check_merged_mining(const std::string& block_hex,
                                          const std::string& extranonce1,
                                          const std::string& extranonce2,
                                          const JobSnapshot* job)
{
    if (!m_mm_manager) return false;

    // Extract 80-byte parent header (first 160 hex chars)
    if (block_hex.size() < 160) return false;
    std::string parent_header_hex = block_hex.substr(0, 160);

    // Compute parent block hash (scrypt for LTC)
    auto hdr_bytes = ParseHex(parent_header_hex);
    uint256 parent_hash;
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(hdr_bytes.data()),
                        reinterpret_cast<char*>(parent_hash.data()));

    // Build stripped coinbase tx (no witness) — use per-job parts when available
    std::string coinbase_hex;
    std::vector<std::string> merkle_branches_copy;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
        const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
        coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
        merkle_branches_copy = job ? job->merkle_branches : m_cached_merkle_branches;
    }

    auto before = m_mm_manager->get_discovered_blocks().size();
    m_mm_manager->try_submit_merged_blocks(
        parent_header_hex,
        coinbase_hex,
        merkle_branches_copy,
        0,  // coinbase is always at index 0
        parent_hash);
    auto after = m_mm_manager->get_discovered_blocks().size();
    return after > before; // true if a merged block was found
}

// ─── Witness merkle root computation ──────────────────────────────────────────
// Compute the merkle root of a list of hashes (standard Bitcoin merkle tree).
static uint256 compute_witness_merkle_root(std::vector<uint256> hashes) {
    if (hashes.empty()) return uint256();
    while (hashes.size() > 1) {
        if (hashes.size() % 2 == 1)
            hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i + 1 < hashes.size(); i += 2)
            next.push_back(Hash(hashes[i], hashes[i + 1]));
        hashes = std::move(next);
    }
    return hashes[0];
}

// P2Pool witness nonce: '[Pool]' repeated 4 times = 32 bytes
static const unsigned char P2POOL_WITNESS_NONCE_BYTES[32] = {
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
};

// Compute the P2Pool witness commitment hex from a raw witness merkle root.
// Returns the full script hex: "6a24aa21a9ed" + SHA256d(root || '[Pool]'*4)
static std::string compute_p2pool_witness_commitment_hex(const uint256& witness_root) {
    uint256 nonce;
    std::memcpy(nonce.data(), P2POOL_WITNESS_NONCE_BYTES, 32);
    uint256 commitment = Hash(witness_root, nonce);
    return "6a24aa21a9ed" + HexStr(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(commitment.data()), 32));
}

// ─── Merkle branch computation ────────────────────────────────────────────────
// Given the list of transaction hashes EXCLUDING the coinbase
// (i.e. from getblocktemplate tx list), compute the Stratum merkle_branches
// array that enables the miner to reconstruct the merkle root as:
//   hash = coinbase_hash
//   for b in branches: hash = Hash(hash, b)
/*static*/ std::vector<std::string>
MiningInterface::compute_merkle_branches(std::vector<std::string> tx_hashes_hex)
{
    if (tx_hashes_hex.empty()) return {};

    // Convert hex strings to uint256
    std::vector<uint256> current;
    current.reserve(tx_hashes_hex.size());
    for (const auto& h : tx_hashes_hex) {
        uint256 u;
        u.SetHex(h);
        current.push_back(u);
    }

    std::vector<std::string> branches;

    // At each tree level: the first element of `current` is the sibling of our
    // path node. Consume it as a branch, then build the next level from the rest.
    while (!current.empty()) {
        // Store in internal byte order (Stratum format: raw SHA256d output hex)
        branches.push_back(HexStr(std::span<const unsigned char>(current[0].data(), 32)));
        current.erase(current.begin());      // remove the sibling we just used
        if (current.empty()) break;

        // If the remaining list is odd, duplicate the last entry
        if (current.size() % 2 == 1)
            current.push_back(current.back());

        // Pair and hash for the next level
        std::vector<uint256> next;
        next.reserve(current.size() / 2);
        for (size_t i = 0; i + 1 < current.size(); i += 2)
            next.push_back(Hash(current[i], current[i + 1]));
        current = std::move(next);
    }

    return branches;
}

// ─── Merkle root reconstruction ──────────────────────────────────────────────
// Given a fully-assembled coinbase transaction in hex and the Stratum merkle
// branches, reconstruct the block's merkle root.
//   coinbase_hash = dSHA256(coinbase_bytes)
//   for each branch: coinbase_hash = dSHA256(coinbase_hash || branch)
/*static*/ uint256
MiningInterface::reconstruct_merkle_root(const std::string& coinbase_hex,
                                         const std::vector<std::string>& merkle_branches)
{
    auto coinbase_bytes = ParseHex(coinbase_hex);
    uint256 hash = Hash(coinbase_bytes);

    for (const auto& branch_hex : merkle_branches) {
        // Branches are in internal byte order (Stratum format)
        uint256 branch;
        auto branch_bytes = ParseHex(branch_hex);
        if (branch_bytes.size() == 32)
            memcpy(branch.begin(), branch_bytes.data(), 32);
        hash = Hash(hash, branch);
    }
    return hash;
}

// ─── Build full block from Stratum parameters ────────────────────────────────
// Assembles the block header + full transaction list from the cached template
// and the miner's Stratum submit data.
std::string
MiningInterface::build_block_from_stratum(const std::string& extranonce1,
                                          const std::string& extranonce2,
                                          const std::string& ntime,
                                          const std::string& nonce,
                                          const JobSnapshot* job) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    // When a JobSnapshot is provided, use its frozen template data.
    // Otherwise fall back to the live m_cached_template (legacy/solo path).
    const std::string& coinb1 = job ? job->coinb1 : m_cached_coinb1;
    const std::string& coinb2 = job ? job->coinb2 : m_cached_coinb2;

    if (coinb1.empty())
        return {};

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;

    // Reconstruct merkle root using the job's branches (or the live cache)
    const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, branches);

    // Block header fields — from the job snapshot or the live template
    uint32_t version;
    uint256 prev_hash;
    std::string bits_hex;
    bool segwit;
    if (job) {
        version = job->version ? job->version : 536870912U;
        prev_hash.SetHex(job->gbt_prevhash.empty() ? std::string(64, '0') : job->gbt_prevhash);
        bits_hex = job->nbits.empty() ? "1d00ffff" : job->nbits;
        segwit = job->segwit_active;
    } else {
        if (!m_work_valid || m_cached_template.is_null())
            return {};
        version = m_cached_template.value("version", 536870912U);
        prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));
        bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
        segwit = m_segwit_active;
    }

    // ntime and nonce from miner (hex strings, 4 bytes each, BE from Stratum)
    auto ntime_bytes = ParseHex(ntime);
    auto nonce_bytes = ParseHex(nonce);
    auto bits_bytes  = ParseHex(bits_hex);

    // Stratum/GBT sends these as big-endian hex; block header needs little-endian
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    std::reverse(bits_bytes.begin(),  bits_bytes.end());

    std::ostringstream block;
    // version LE
    block << std::hex << std::setfill('0')
          << std::setw(2) << ((version      ) & 0xff)
          << std::setw(2) << ((version >>  8) & 0xff)
          << std::setw(2) << ((version >> 16) & 0xff)
          << std::setw(2) << ((version >> 24) & 0xff);
    // prev_hash (already internal byte order in uint256)
    block << HexStr(std::span<const unsigned char>(prev_hash.data(), 32));
    // merkle_root
    block << HexStr(std::span<const unsigned char>(merkle_root.data(), 32));
    // ntime LE
    block << HexStr(std::span<const unsigned char>(ntime_bytes.data(), ntime_bytes.size()));
    // nbits LE
    block << HexStr(std::span<const unsigned char>(bits_bytes.data(), bits_bytes.size()));
    // nonce LE
    block << HexStr(std::span<const unsigned char>(nonce_bytes.data(), nonce_bytes.size()));

    // Transaction count (varint) + coinbase + rest of transactions
    const auto& tx_list = job ? job->tx_data : std::vector<std::string>{};
    // If no job snapshot, collect tx data from the live template
    std::vector<std::string> live_tx_data;
    if (!job && m_cached_template.contains("transactions")) {
        for (const auto& tx : m_cached_template["transactions"])
            if (tx.contains("data"))
                live_tx_data.push_back(tx["data"].get<std::string>());
    }
    const auto& txs_hex = job ? tx_list : live_tx_data;
    uint64_t tx_count = 1 + txs_hex.size(); // coinbase + template txs
    // Simple varint encoding
    if (tx_count < 0xfd)
        block << std::hex << std::setfill('0') << std::setw(2) << tx_count;
    else
        block << "fd" << std::hex << std::setfill('0')
              << std::setw(2) << (tx_count & 0xff)
              << std::setw(2) << ((tx_count >> 8) & 0xff);

    // Coinbase transaction: coinb1 + extranonce1 + extranonce2 + coinb2 is the
    // non-witness (stripped) serialization used for txid computation and the
    // Stratum merkle tree.  For segwit blocks the block body must contain the
    // witness serialization which wraps the same data with marker/flag bytes
    // and a coinbase witness stack (BIP141: 1 item of 32 bytes = P2Pool nonce).
    if (segwit) {
        // Non-witness: [version 4B][input_count 1B][inputs…][outputs…][locktime 4B]
        // Witness:     [version 4B][00 01][input_count 1B][inputs…][outputs…]
        //              [witness_stack][locktime 4B]
        block << coinbase_hex.substr(0, 8)    // version (4 bytes = 8 hex)
              << "0001"                        // segwit marker + flag
              << coinbase_hex.substr(8, coinbase_hex.size() - 16) // inputs + outputs
              << "01"                          // 1 stack item for the single coinbase input
              << "20"                          // 32 bytes
              // P2Pool witness nonce: '[Pool]' * 4
              << "5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d5b5032506f6f6c5d"
              << coinbase_hex.substr(coinbase_hex.size() - 8); // locktime
    } else {
        block << coinbase_hex;
    }

    // Remaining transactions from the template
    for (const auto& tx_hex : txs_hex) {
        block << tx_hex;
    }

    // MWEB extension block (Litecoin): append HogEx flag + MWEB data
    const std::string& mweb_data = job ? job->mweb : m_cached_mweb;
    if (!mweb_data.empty()) {
        block << "01" << mweb_data;
    } else if (segwit) {
        // MWEB not yet bootstrapped — litecoind will reject with "mweb-missing".
        // Return empty string to signal invalid block — caller should skip submission.
        LOG_WARNING << "[EMB-LTC] Block built WITHOUT MWEB — skipping submission"
                    << " (MWEB state not yet bootstrapped from P2P full block)";
        return {};
    }

    return block.str();
}

// ─── Coinbase parts construction ─────────────────────────────────────────────
// Encode an integer as a minimal CScriptNum (sign-magnitude, little-endian)
// prefixed by a 1-byte push-data length. Used for BIP34 block height.
static std::string encode_height_pushdata(int height)
{
    std::ostringstream os;
    if (height == 0) {
        os << "0100";  // PUSH1 [0x00]
        return os.str();
    }
    std::vector<uint8_t> bytes;
    uint32_t v = static_cast<uint32_t>(height);
    while (v > 0) {
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
        v >>= 8;
    }
    // If MSB is set, add a 0x00 sign byte (positive)
    if (bytes.back() & 0x80)
        bytes.push_back(0x00);

    // PUSHDATA opcode = len, then the data bytes (already little-endian)
    os << std::hex << std::setfill('0') << std::setw(2) << bytes.size();
    for (uint8_t b : bytes)
        os << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return os.str();
}

// Encode a uint64 amount as 8 little-endian hex bytes
static std::string encode_le64(uint64_t v)
{
    std::ostringstream os;
    for (int i = 0; i < 8; ++i)
        os << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>((v >> (i * 8)) & 0xFF);
    return os.str();
}

// Build a P2PKH output script OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG
// `hash160_hex` must be 40 hex chars (20 bytes).
// Returns the (length-prefixed) complete output script hex.
static std::string p2pkh_script(const std::string& hash160_hex)
{
    // 1976a914{hash160}88ac
    std::ostringstream s;
    s << "19" << "76a914" << hash160_hex << "88ac";
    return s.str();
}

/*static*/ uint256 MiningInterface::compute_the_state_root(
    const std::vector<std::pair<std::string,uint64_t>>& pplns_outputs,
    uint32_t chain_length, uint32_t block_height, uint32_t bits)
{
    // THE State Root = MerkleRoot(L-1, L0, L+1, epoch_meta)
    // L-1 and L+1 are zero placeholders until THE activates.

    // Layer 0: SHA256d of sorted PPLNS output table
    uint256 layer_0;
    {
        PackStream ps;
        for (const auto& [script, amount] : pplns_outputs)
        {
            ps << static_cast<uint64_t>(amount);
            uint8_t len = static_cast<uint8_t>(std::min(script.size() / 2, size_t(255)));
            ps << len;
        }
        auto span = ps.get_span();
        if (span.size() > 0)
            layer_0 = Hash(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(span.data()), span.size()));
    }

    // Epoch metadata: SHA256d(chain_length || block_height || bits)
    uint256 epoch_meta;
    {
        PackStream ps;
        ps << chain_length;
        ps << block_height;
        ps << bits;
        auto span = ps.get_span();
        epoch_meta = Hash(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(span.data()), span.size()));
    }

    // Layer -1 and +1: zero (placeholders)
    uint256 layer_m1; // zero
    uint256 layer_p1; // zero

    // 4-leaf Merkle tree: hash pairs, then hash the pair of pairs
    // Concatenate each pair into a 64-byte buffer and SHA256d
    auto hash_pair = [](const uint256& a, const uint256& b) -> uint256 {
        unsigned char buf[64];
        std::memcpy(buf, a.data(), 32);
        std::memcpy(buf + 32, b.data(), 32);
        return Hash(std::span<const unsigned char>(buf, 64));
    };
    uint256 left = hash_pair(layer_m1, layer_0);
    uint256 right = hash_pair(layer_p1, epoch_meta);
    return hash_pair(left, right);
}

/*static*/ std::pair<std::string, std::string>
MiningInterface::build_coinbase_parts(
    const nlohmann::json& tmpl,
    uint64_t coinbase_value,
    const std::vector<std::pair<std::string,uint64_t>>& outputs,
    bool raw_scripts,
    const std::vector<uint8_t>& mm_commitment,
    const std::string& witness_commitment_hex,
    const std::string& ref_hash_hex,
    const uint256& the_state_root,
    const std::string& coinbase_text)
{
    // P2Pool-compatible coinbase split: extranonce goes into last_txout_nonce,
    // NOT into the scriptSig.  This way:
    //   - scriptSig is fixed (no miner-variable data) → share.m_coinbase is deterministic
    //   - hash_link prefix (everything before last 44 bytes) matches generate_transaction
    //   - en1+en2 fill the 8-byte last_txout_nonce in OP_RETURN (part of hash_link suffix)
    //
    // coinb1 = everything up to and including ref_hash in the OP_RETURN output
    // coinb2 = locktime only ("00000000")
    // coinbase = coinb1 + extranonce1(4B) + extranonce2(4B) + coinb2
    //
    // The en1+en2 become the P2Pool last_txout_nonce (8 bytes).
    //
    // Output ordering (must match generate_share_transaction()):
    //   1. Segwit witness commitment (if present) — value=0
    //   2. PPLNS payout outputs (sorted by amount asc, script asc) + donation last
    //   3. OP_RETURN commitment (0x6a28 + ref_hash + last_txout_nonce) — value=0

    const int height = tmpl.value("height", 1);
    const std::string height_hex = encode_height_pushdata(height);
    const int height_bytes = static_cast<int>(height_hex.size()) / 2;

    // Dynamic tag: "/c2pool/" (default) or operator --coinbase-text
    // When operator provides text, /c2pool/ tag is replaced — c2pool is
    // always identified by the combined donation address in coinbase outputs.
    const std::string default_tag = "/c2pool/";
    const std::string& tag_text = coinbase_text.empty() ? default_tag : coinbase_text;
    static const char* HEXC = "0123456789abcdef";
    std::string tag_hex;
    tag_hex.reserve(tag_text.size() * 2);
    for (char c : tag_text) {
        uint8_t b = static_cast<uint8_t>(c);
        tag_hex += HEXC[b >> 4];
        tag_hex += HEXC[b & 0x0f];
    }
    const int tag_bytes = static_cast<int>(tag_text.size());

    // AuxPoW merged mining commitment
    std::string mm_hex;
    if (!mm_commitment.empty()) {
        static const char* HEX = "0123456789abcdef";
        mm_hex.reserve(mm_commitment.size() * 2);
        for (uint8_t b : mm_commitment) {
            mm_hex += HEX[b >> 4];
            mm_hex += HEX[b & 0x0f];
        }
    }
    const int mm_bytes = static_cast<int>(mm_commitment.size());

    // THE state root: 32 bytes embedded in scriptSig (V37 prep — zero cost)
    // Layout: [height][mm_commit]["/c2pool/"][the_state_root(32)][optional operator text]
    std::string state_root_hex;
    const int state_root_bytes = the_state_root.IsNull() ? 0 : 32;
    if (state_root_bytes > 0) {
        static const char* HEX = "0123456789abcdef";
        state_root_hex.reserve(64);
        for (int i = 0; i < 32; ++i) {
            unsigned char c = the_state_root.data()[i];
            state_root_hex += HEX[c >> 4];
            state_root_hex += HEX[c & 0x0f];
        }
    }

    // ScriptSig: height + mm_commitment + tag + state_root (NO extranonce!)
    // Each element (mm, tag) gets a 1-byte push opcode prefix (matching create_push_script)
    // state_root is raw (no push opcode, like coinbaseflags in p2pool)
    const int mm_push_overhead = (mm_bytes > 0) ? 1 : 0;
    const int tag_push_overhead = (tag_bytes > 0) ? 1 : 0;
    const int script_total = height_bytes + mm_push_overhead + mm_bytes
                           + tag_push_overhead + tag_bytes + state_root_bytes;

    // Build coinb1: entire coinbase TX up to and including ref_hash in OP_RETURN
    std::ostringstream coinb1;
    coinb1 << "01000000"   // version
           << "01"         // 1 input
           << "0000000000000000000000000000000000000000000000000000000000000000"
           << "ffffffff"   // previous index
           << std::hex << std::setfill('0') << std::setw(2) << script_total
           << height_hex;

    // scriptSig elements with push opcodes (matching p2pool's create_push_script):
    // Each datum gets its own length-prefix push opcode.
    auto emit_push = [&](std::ostringstream& os, const std::string& data_hex) {
        size_t len = data_hex.size() / 2;
        if (len > 0 && len < 76)
            os << std::hex << std::setfill('0') << std::setw(2) << len;
        os << data_hex;
    };
    if (!mm_hex.empty()) emit_push(coinb1, mm_hex);
    if (!tag_hex.empty()) emit_push(coinb1, tag_hex);
    // state_root appended raw (like p2pool's coinbaseflags)
    if (!state_root_hex.empty())
        coinb1 << state_root_hex;
    coinb1 << "ffffffff";  // sequence = 0xFFFFFFFF

    // Count outputs: [segwit?] + PPLNS + OP_RETURN
    size_t num_outputs = outputs.size();
    if (!witness_commitment_hex.empty()) ++num_outputs;
    if (!ref_hash_hex.empty()) ++num_outputs;

    // Varint-encode output count
    if (num_outputs < 0xfd)
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << num_outputs;
    else
        coinb1 << "fd" << std::hex << std::setfill('0')
               << std::setw(2) << (num_outputs & 0xff)
               << std::setw(2) << ((num_outputs >> 8) & 0xff);

    // Output 1: Segwit witness commitment (FIRST, matching generate_share_transaction)
    if (!witness_commitment_hex.empty()) {
        coinb1 << encode_le64(0);   // 0 satoshis
        size_t wc_len = witness_commitment_hex.size() / 2;
        coinb1 << std::hex << std::setfill('0') << std::setw(2) << wc_len;
        coinb1 << witness_commitment_hex;
        {
            static int wc_log = 0;
            if (wc_log++ < 5)
                LOG_INFO << "[WC-COINBASE] witness_commitment(" << wc_len << ")=" << witness_commitment_hex.substr(0, 80);
        }
    }

    // Outputs 2..N: PPLNS payouts + donation (already sorted by caller)
    for (const auto& [addr, amount] : outputs) {
        coinb1 << encode_le64(amount);
        if (raw_scripts) {
            size_t script_len = addr.size() / 2;
            coinb1 << std::hex << std::setfill('0') << std::setw(2) << script_len;
            coinb1 << addr;
        } else {
            coinb1 << p2pkh_script(addr);
        }
    }

    // Output N+1: OP_RETURN commitment (LAST, matching generate_share_transaction)
    // Script = 6a(OP_RETURN) + 28(PUSH_40) + ref_hash(32) + nonce(8)
    // Total script = 42 bytes = 0x2a
    // The nonce(8) bytes are filled by en1+en2 (between coinb1 and coinb2)
    if (!ref_hash_hex.empty()) {
        coinb1 << encode_le64(0);   // 0 satoshis
        coinb1 << "2a";             // script length = 42
        coinb1 << "6a28";           // OP_RETURN + PUSH_40
        coinb1 << ref_hash_hex;     // 32 bytes = 64 hex chars
        // nonce (8 bytes) = en1+en2 goes HERE (between coinb1 and coinb2)
    }

    // coinb2 is just locktime
    std::string coinb2 = "00000000";

    return { coinb1.str(), coinb2 };
}

MiningInterface::CoinbaseResult
MiningInterface::build_connection_coinbase(
    const uint256& prev_share_hash,
    const std::string& extranonce1_hex,
    const std::vector<unsigned char>& payout_script,
    const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged_addrs) const
{
    // ── Lock hierarchy: m_work_mutex (1) > sessions_mutex_ (2) > MM::m_mutex (3) ──
    //
    // This function is called from StratumSession::send_notify_work which may be
    // invoked by notify_all() after it releases sessions_mutex_.
    // Internally, ref_hash_fn needs get_local_addr_rates() (sessions_mutex_) and
    // MM needs its own m_mutex.
    //
    // Architecture: snapshot-then-compute (matches p2pool's single-threaded model).
    //   Phase 1: Snapshot all work state under m_work_mutex (brief hold)
    //   Phase 2: Gather external data WITHOUT any lock (addr_rates, MM commitment)
    //   Phase 3: Compute everything from snapshot (ref_hash, coinbase parts) — lock-free
    //   Phase 4: Brief re-lock to write back PPLNS cache + build final result

    // ── Phase 1: Snapshot work state under m_work_mutex ──
    // All reads from m_cached_* fields happen here.  The lock is released before
    // any callback that might acquire other mutexes.

    struct WorkStateSnapshot {
        nlohmann::json tmpl;
        std::vector<std::pair<std::string, uint64_t>> pplns_outputs;
        uint256 pplns_best_share;
        bool raw_scripts{false};
        std::string witness_commitment;
        uint256 witness_root;
        std::vector<uint8_t> mm_commitment;
        std::vector<CachedMergedHeaderInfo> merged_header_infos;
        bool segwit_active{false};
        std::string mweb;
        std::string coinbase_text;
        std::vector<unsigned char> donation_script;
        std::vector<std::string> merkle_branches;
        pplns_fn_t pplns_fn;
        ref_hash_fn_t ref_hash_fn;
        bool needs_pplns_recompute{false};
        int64_t share_version{36};
    };

    WorkStateSnapshot ws;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_work_valid || m_cached_template.is_null())
            return {};

        ws.tmpl = m_cached_template;
        ws.pplns_outputs = m_cached_pplns_outputs;
        ws.pplns_best_share = m_cached_pplns_best_share;
        ws.raw_scripts = m_cached_raw_scripts;
        ws.witness_commitment = m_cached_witness_commitment;
        ws.witness_root = m_cached_witness_root;
        ws.mm_commitment = m_cached_mm_commitment;
        ws.merged_header_infos = m_last_merged_header_infos;
        ws.segwit_active = m_segwit_active;
        ws.mweb = m_cached_mweb;
        ws.coinbase_text = m_coinbase_text;
        ws.donation_script = m_donation_script;
        ws.share_version = m_cached_share_version;
        ws.merkle_branches = m_cached_merkle_branches;
        ws.pplns_fn = m_pplns_fn;
        ws.ref_hash_fn = m_ref_hash_fn;
        ws.needs_pplns_recompute = !prev_share_hash.IsNull()
            && ws.pplns_fn
            && prev_share_hash != ws.pplns_best_share;
    }
    // ── m_work_mutex RELEASED ──
    // From here on, NO mutex is held. All callbacks (PPLNS, ref_hash, MM, addr_rates)
    // can freely acquire their own locks without deadlock risk.

    if (!ws.ref_hash_fn)
        return {};

    // ── Phase 2: PPLNS recomputation (lock-free — callbacks may acquire their own locks) ──
    // CRITICAL: If frozen prev_share_hash differs from the share used for cached PPLNS,
    // recompute PPLNS from the frozen share. This ensures the coinbase amounts match
    // what generate_share_transaction will compute during verification.
    // (Matches p2pool's closure pattern: coinbase is frozen at template time.)
    static const char* HX = "0123456789abcdef";

    if (prev_share_hash.IsNull())
    {
        // Genesis: no PPLNS walk possible. p2pool puts 100% of subsidy to donation.
        ws.pplns_outputs.clear();
        uint64_t subsidy = ws.tmpl.value("coinbasevalue", uint64_t(0));
        std::string donation_hex;
        for (unsigned char b : ws.donation_script) { donation_hex += HX[b >> 4]; donation_hex += HX[b & 0x0f]; }
        ws.pplns_outputs.push_back({donation_hex, subsidy});
        ws.raw_scripts = true;
        ws.pplns_best_share = prev_share_hash;
    }
    else if (ws.needs_pplns_recompute)
    {
        uint32_t nbits = 0;
        if (ws.tmpl.contains("bits"))
            nbits = static_cast<uint32_t>(std::stoul(
                ws.tmpl["bits"].get<std::string>(), nullptr, 16));
        uint256 block_target = chain::bits_to_target(nbits);
        uint64_t subsidy = ws.tmpl.value("coinbasevalue", uint64_t(0));

        auto expected = ws.pplns_fn(prev_share_hash, block_target, subsidy, ws.donation_script);

        if (!expected.empty()) {
            ws.pplns_outputs.clear();
            std::string donation_hex;
            for (unsigned char b : ws.donation_script) { donation_hex += HX[b >> 4]; donation_hex += HX[b & 0x0f]; }

            std::pair<std::string, uint64_t> donation_entry;
            bool found_donation = false;

            for (const auto& [script_bytes, amount] : expected) {
                uint64_t sat = static_cast<uint64_t>(amount);
                std::string hex;
                for (unsigned char b : script_bytes) { hex += HX[b >> 4]; hex += HX[b & 0x0f]; }
                if (hex == donation_hex) { donation_entry = {hex, sat}; found_donation = true; }
                else if (sat > 0) { ws.pplns_outputs.push_back({std::move(hex), sat}); }
            }
            std::sort(ws.pplns_outputs.begin(), ws.pplns_outputs.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (found_donation) ws.pplns_outputs.push_back(donation_entry);
            ws.pplns_best_share = prev_share_hash;
            LOG_INFO << "[build_connection_cb] PPLNS recomputed for frozen prev_share="
                     << prev_share_hash.ToString().substr(0, 16)
                     << " outputs=" << ws.pplns_outputs.size();
        }
    }

    // ── Phase 2a: V35 finder fee (per-connection adjustment) ──
    // V35 PPLNS returns 99.5% to miners + remainder to donation.
    // The finder (this connection's miner) gets subsidy/200 (0.5%) moved
    // from the donation output to their payout script.
    // Reference: p2pool data.py lines 945-948
    if (ws.share_version < 36 && !ws.pplns_outputs.empty() && !payout_script.empty())
    {
        uint64_t subsidy_for_fee = ws.tmpl.value("coinbasevalue", uint64_t(0));
        uint64_t finder_fee = subsidy_for_fee / 200;

        if (finder_fee > 0) {
            // Build finder's script hex
            std::string finder_hex;
            finder_hex.reserve(payout_script.size() * 2);
            for (unsigned char b : payout_script) {
                finder_hex += HX[b >> 4]; finder_hex += HX[b & 0x0f];
            }

            // Subtract finder fee from donation (last entry)
            auto& donation_out = ws.pplns_outputs.back();
            uint64_t taken = std::min(donation_out.second, finder_fee);
            donation_out.second -= taken;

            // Add to finder's script (may already exist in PPLNS outputs)
            bool found_finder = false;
            for (auto& [hex, amt] : ws.pplns_outputs) {
                if (hex == finder_hex) { amt += taken; found_finder = true; break; }
            }
            if (!found_finder) {
                // Insert before donation (last entry) to maintain sort invariant
                ws.pplns_outputs.insert(ws.pplns_outputs.end() - 1, {finder_hex, taken});
            }

            // Re-sort PPLNS entries (excluding donation at the end)
            if (ws.pplns_outputs.size() > 1) {
                auto donation_save = ws.pplns_outputs.back();
                ws.pplns_outputs.pop_back();
                std::sort(ws.pplns_outputs.begin(), ws.pplns_outputs.end(),
                    [](const auto& a, const auto& b) {
                        if (a.second != b.second) return a.second < b.second;
                        return a.first < b.first;
                    });
                ws.pplns_outputs.push_back(donation_save);
            }
        }
    }

    // ── Phase 2b: MM commitment (lock-free — MM acquires its own m_mutex) ──
    std::vector<uint8_t> atomic_mm_commitment;
    if (m_mm_manager) {
        auto [header_infos, fresh_commit] =
            m_mm_manager->build_merged_header_info_with_commitment();
        LOG_TRACE << "[build_cb] MM returned, commit_size=" << fresh_commit.size()
                  << " infos=" << header_infos.size();
        atomic_mm_commitment = std::move(fresh_commit);
        ws.merged_header_infos.clear();
        ws.merged_header_infos.reserve(header_infos.size());
        for (auto& hi : header_infos) {
            CachedMergedHeaderInfo c;
            c.chain_id = hi.chain_id;
            c.coinbase_value = hi.coinbase_value;
            c.block_height = hi.block_height;
            c.block_header = std::move(hi.block_header);
            c.coinbase_merkle_branches = std::move(hi.coinbase_merkle_branches);
            c.coinbase_script = std::move(hi.coinbase_script);
            c.coinbase_hex = std::move(hi.coinbase_hex);
            ws.merged_header_infos.push_back(std::move(c));
        }
    }

    // Write merged header infos so ref_hash_fn (which captures MiningInterface*)
    // reads the FRESH infos from this MM build, not stale ones from last refresh_work.
    // m_last_merged_header_infos is mutable and only consumed by ref_hash_fn (single caller).
    if (!ws.merged_header_infos.empty()) {
        auto& self = const_cast<MiningInterface&>(*this);
        self.m_last_merged_header_infos = ws.merged_header_infos;
    }

    // ── Phase 3: Pure computation from snapshot (NO locks held) ──
    LOG_TRACE << "[build_cb] Phase 3: building coinbase from snapshot...";

    const int height = ws.tmpl.value("height", 1);
    std::string height_hex = encode_height_pushdata(height);

    static const char* HEX = "0123456789abcdef";
    const std::string default_tag2 = "/c2pool/";
    const std::string& tag_src = ws.coinbase_text.empty() ? default_tag2 : ws.coinbase_text;
    std::string tag_hex;
    for (char c : tag_src) {
        uint8_t b = static_cast<uint8_t>(c);
        tag_hex += HEX[b >> 4];
        tag_hex += HEX[b & 0x0f];
    }

    const auto& mm_for_scriptsig = atomic_mm_commitment.empty()
        ? ws.mm_commitment : atomic_mm_commitment;

    std::string mm_hex;
    for (uint8_t b : mm_for_scriptsig) {
        mm_hex += HEX[b >> 4];
        mm_hex += HEX[b & 0x0f];
    }

    // THE state root
    std::string state_root_hex;
    {
        uint32_t tmpl_height = ws.tmpl.value("height", uint32_t(0));
        uint32_t tmpl_bits = 0;
        if (ws.tmpl.contains("bits"))
            tmpl_bits = static_cast<uint32_t>(std::stoul(
                ws.tmpl["bits"].get<std::string>(), nullptr, 16));
        uint256 the_root = compute_the_state_root(
            ws.pplns_outputs,
            static_cast<uint32_t>(ws.pplns_outputs.size()),
            tmpl_height, tmpl_bits);
        if (!the_root.IsNull()) {
            state_root_hex.reserve(64);
            for (int i = 0; i < 32; ++i) {
                unsigned char c = the_root.data()[i];
                state_root_hex += HEX[c >> 4];
                state_root_hex += HEX[c & 0x0f];
            }
        }
    }

    // ScriptSig
    auto push_prefix = [&](const std::string& data_hex) -> std::string {
        size_t len = data_hex.size() / 2;
        if (len == 0) return "";
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(len));
        return std::string(buf) + data_hex;
    };
    std::string scriptsig_hex = height_hex;
    if (!mm_hex.empty()) scriptsig_hex += push_prefix(mm_hex);
    if (!tag_hex.empty()) scriptsig_hex += push_prefix(tag_hex);
    scriptsig_hex += state_root_hex;

    std::vector<unsigned char> scriptsig_bytes;
    scriptsig_bytes.reserve(scriptsig_hex.size() / 2);
    for (size_t i = 0; i + 1 < scriptsig_hex.size(); i += 2)
        scriptsig_bytes.push_back(static_cast<unsigned char>(
            std::stoul(scriptsig_hex.substr(i, 2), nullptr, 16)));

    LOG_TRACE << "[build_cb] scriptsig built, len=" << scriptsig_hex.size()/2;

    uint64_t subsidy = ws.tmpl.value("coinbasevalue", uint64_t(0));
    uint32_t bits = 0;
    if (ws.tmpl.contains("bits"))
        bits = static_cast<uint32_t>(std::stoul(
            ws.tmpl["bits"].get<std::string>(), nullptr, 16));
    uint32_t timestamp = ws.tmpl.value("curtime", uint32_t(0));

    std::vector<uint256> branches_u256;
    branches_u256.reserve(ws.merkle_branches.size());
    for (const auto& hex : ws.merkle_branches) {
        uint256 h;
        auto bytes = ParseHex(hex);
        if (bytes.size() == 32)
            memcpy(h.begin(), bytes.data(), 32);
        branches_u256.push_back(h);
    }

    LOG_TRACE << "[build_cb] calling ref_hash_fn (lock-free)...";
    // Safety: if witness_root lost in transit (race with refresh_work),
    // recompute from the snapshotted template transactions — matches
    // p2pool's approach of computing segwit_data from known_txs.
    uint256 effective_witness_root = ws.witness_root;
    if (effective_witness_root.IsNull() && ws.segwit_active && ws.tmpl.contains("transactions")) {
        std::vector<uint256> wtxids;
        wtxids.push_back(uint256());  // coinbase wtxid = 0
        for (auto& tx : ws.tmpl["transactions"]) {
            uint256 wtxid;
            if (tx.is_object() && tx.contains("hash"))
                wtxid.SetHex(tx["hash"].get<std::string>());
            else if (tx.is_object() && tx.contains("txid"))
                wtxid.SetHex(tx["txid"].get<std::string>());
            wtxids.push_back(wtxid);
        }
        effective_witness_root = compute_witness_merkle_root(std::move(wtxids));
        LOG_WARNING << "[build_cb] witness_root was null, recomputed from "
                    << ws.tmpl["transactions"].size() << " txs: "
                    << effective_witness_root.GetHex();
    }
    auto rhr = ws.ref_hash_fn(
        prev_share_hash,
        scriptsig_bytes, payout_script, subsidy, bits, timestamp,
        ws.segwit_active, ws.witness_commitment, effective_witness_root,
        merged_addrs, branches_u256);
    LOG_TRACE << "[build_cb] ref_hash_fn returned, bits=" << std::hex << rhr.bits << std::dec;

    // Build ref_hash hex
    std::string ref_hash_hex;
    {
        auto ref_chars = rhr.ref_hash.GetChars();
        for (unsigned char b : ref_chars) {
            ref_hash_hex += HEX[b >> 4];
            ref_hash_hex += HEX[b & 0x0f];
        }
    }

    // THE state root for coinbase parts
    uint32_t tmpl_height = ws.tmpl.value("height", uint32_t(0));
    uint32_t tmpl_bits = 0;
    {
        auto bits_str = ws.tmpl.value("bits", std::string(""));
        if (bits_str.size() == 8)
            tmpl_bits = static_cast<uint32_t>(std::stoul(bits_str, nullptr, 16));
    }
    uint256 the_root = compute_the_state_root(
        ws.pplns_outputs,
        static_cast<uint32_t>(ws.pplns_outputs.size()),
        tmpl_height, tmpl_bits);

    const auto& mm_commitment_fresh = mm_for_scriptsig;

    LOG_INFO << "[build_connection_cb] PPLNS for frozen prev_share="
             << prev_share_hash.GetHex().substr(0, 16) << " outputs=" << ws.pplns_outputs.size();
    {
        uint64_t pplns_total = 0;
        for (auto& [script_hex, amt] : ws.pplns_outputs) {
            pplns_total += amt;
            LOG_INFO << "[PPLNS-OUT] script=" << script_hex.substr(0, 40) << " amount=" << amt;
        }
        LOG_INFO << "[build_connection_cb] subsidy=" << subsidy
                 << " pplns_total=" << pplns_total
                 << " diff=" << (int64_t(subsidy) - int64_t(pplns_total));
    }

    LOG_TRACE << "[build_cb] calling build_coinbase_parts...";
    auto [cb1, cb2] = build_coinbase_parts(
        ws.tmpl,
        subsidy,
        ws.pplns_outputs,
        ws.raw_scripts,
        mm_commitment_fresh,
        ws.witness_commitment,
        ref_hash_hex,
        the_root,
        ws.coinbase_text);
    LOG_TRACE << "[build_cb] coinbase_parts built, cb1_len=" << cb1.size();

    // ── Phase 4: Write back updated PPLNS cache ──
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        auto& self = const_cast<MiningInterface&>(*this);
        if (ws.pplns_best_share != self.m_cached_pplns_best_share) {
            self.m_cached_pplns_outputs = ws.pplns_outputs;
            self.m_cached_pplns_best_share = ws.pplns_best_share;
            self.m_cached_raw_scripts = ws.raw_scripts;
        }
    }

    WorkSnapshot snap;
    snap.segwit_active = ws.segwit_active;
    snap.mweb = ws.mweb;
    snap.subsidy = subsidy;
    snap.witness_commitment_hex = ws.witness_commitment;
    snap.witness_root = effective_witness_root;
    snap.frozen_ref = rhr;
    // Freeze block body data atomically — prevents merkle root mismatch
    // when refresh_work() updates the template between separate reads.
    snap.merkle_branches = ws.merkle_branches;
    if (ws.tmpl.contains("transactions")) {
        for (const auto& tx : ws.tmpl["transactions"])
            if (tx.contains("data"))
                snap.tx_data.push_back(tx["data"].get<std::string>());
    }
    return {std::move(cb1), std::move(cb2), std::move(snap)};
}

// base58check_to_hash160 moved to address_utils.cpp

void MiningInterface::refresh_work()
{
    if (!m_coin_rpc && !m_embedded_node) return;

    // Serialize refresh_work calls — two concurrent threads (e.g. embedded LTC
    // header callback + stratum submit) hitting build_coinbase_parts() in parallel
    // causes heap corruption ("corrupted size vs. prev_size in fastbins").
    static std::mutex s_refresh_mutex;
    std::unique_lock<std::mutex> refresh_lock(s_refresh_mutex, std::try_to_lock);
    if (!refresh_lock.owns_lock()) return;  // another refresh in progress, skip

    try {
        // Phase 4: prefer embedded node; fall back to RPC (HybridCoinNode pattern)
        auto wd = m_embedded_node ? m_embedded_node->getwork()
                                  : m_coin_rpc->getwork();

        // Update the coin node's Variable<WorkData> so submit_block() can read it
        if (m_coin_node)
            m_coin_node->work.set(wd);

        // Collect tx hashes from WorkData
        std::vector<std::string> tx_hashes_hex;
        for (const auto& h : wd.m_hashes)
            tx_hashes_hex.push_back(h.GetHex());

        // Compute Stratum merkle branches from those hashes
        auto merkle_branches = compute_merkle_branches(tx_hashes_hex);

        // Build coinbase parts with properly split payout outputs
        uint64_t coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(5000000000));
        std::pair<std::string,std::string> cb_parts;
        bool segwit_active = false;

        // Cached PPLNS data for per-connection coinbase generation
        std::vector<std::pair<std::string,uint64_t>> pplns_outputs;
        bool pplns_raw_scripts = false;
        std::string witness_commitment;
        uint256 witness_root;
        std::vector<uint8_t> mm_commitment;

        try {
            // V36 PPLNS path: use share-tracker proportional payouts directly
            // IMPORTANT: Use m_best_share_hash_fn() here for the PPLNS computation AND
            // cache it so build_connection_coinbase can verify consistency with frozen_prev_share.
            // If they diverge, build_connection_coinbase will recompute PPLNS from frozen_prev_share.
            if (m_pplns_fn && m_best_share_hash_fn) {
                auto best = m_best_share_hash_fn();
                m_cached_pplns_best_share = best;  // remember which share PPLNS was computed from
                if (!best.IsNull()) {
                    LOG_INFO << "[Pool] refresh_work: PPLNS active, best_share=" << best.GetHex()
                             << " donation_script_len=" << m_donation_script.size();
                    uint32_t nbits = std::stoul(
                        wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                    uint256 block_target = chain::bits_to_target(nbits);

                    auto expected = m_pplns_fn(best, block_target, coinbase_value, m_donation_script);

                    // Debug: log PPLNS distribution
                    {
                        static int pplns_log = 0;
                        if (pplns_log++ % 60 == 0) { // every ~5 min (60 * 5s interval)
                            LOG_INFO << "[PPLNS] " << expected.size() << " addrs, subsidy=" << coinbase_value;
                            for (const auto& [script, amount] : expected) {
                                uint64_t sat = static_cast<uint64_t>(amount);
                                LOG_INFO << "[PPLNS]   script(" << script.size() << ")="
                                         << (script.size() > 4 ? HexStr(std::span<const unsigned char>(
                                             reinterpret_cast<const unsigned char*>(script.data()),
                                             std::min(script.size(), size_t(10)))) : "?")
                                         << "... amount=" << sat;
                            }
                        }
                    }

                    if (!expected.empty()) {
                        static const char* HEX = "0123456789abcdef";

                        // Convert donation script to hex for identification
                        std::string donation_script_hex;
                        for (unsigned char b : m_donation_script) {
                            donation_script_hex += HEX[b >> 4];
                            donation_script_hex += HEX[b & 0x0f];
                        }

                        // Separate PPLNS outputs from donation output
                        std::pair<std::string, uint64_t> donation_entry;
                        bool found_donation = false;

                        for (const auto& [script_bytes, amount] : expected) {
                            uint64_t sat = static_cast<uint64_t>(amount);
                            std::string hex;
                            hex.reserve(script_bytes.size() * 2);
                            for (unsigned char b : script_bytes) {
                                hex += HEX[b >> 4];
                                hex += HEX[b & 0x0f];
                            }
                            if (hex == donation_script_hex) {
                                donation_entry = {hex, sat};
                                found_donation = true;
                            } else {
                                if (sat == 0) continue; // Only skip zero-value PPLNS outputs
                                pplns_outputs.push_back({std::move(hex), sat});
                            }
                        }

                        // Sort PPLNS by (amount ascending, script ascending)
                        // matching Python's sorted(dests, key=lambda a: (amounts[a], a))[-4000:]
                        std::sort(pplns_outputs.begin(), pplns_outputs.end(),
                            [](const auto& a, const auto& b) {
                                if (a.second != b.second) return a.second < b.second;
                                return a.first < b.first;
                            });
                        const size_t MAX_PPLNS = m_stratum_config.max_coinbase_outputs;
                        if (pplns_outputs.size() > MAX_PPLNS)
                            pplns_outputs.erase(pplns_outputs.begin(),
                                                pplns_outputs.end() - MAX_PPLNS);

                        // Donation output LAST among value outputs
                        // (matches Python's generate_transaction: payouts + [donation] + OP_RETURN)
                        if (found_donation)
                            pplns_outputs.push_back(donation_entry);

                        pplns_raw_scripts = true;
                        LOG_INFO << "[Pool] refresh_work: V" << m_cached_share_version
                                 << " PPLNS coinbase with "
                                 << pplns_outputs.size() << " outputs (donation_last="
                                 << found_donation << ")";
                    }
                }
            }

            // Fallback: single output to zero-key (burn) so coinbase is always valid
            if (pplns_outputs.empty())
                pplns_outputs.push_back({"0000000000000000000000000000000000000000", coinbase_value});

            // Get merged mining commitment if an MM manager is wired
            if (m_mm_manager)
                mm_commitment = m_mm_manager->get_auxpow_commitment();

            // BIP141: compute P2Pool witness commitment from template transactions
            if (wd.m_data.contains("rules")) {
                auto rules = wd.m_data["rules"].get<std::vector<std::string>>();
                segwit_active = std::any_of(rules.begin(), rules.end(),
                    [](const auto& r) { return r == "segwit" || r == "!segwit"; });
            }
            LOG_INFO << "[Pool] segwit_active=" << segwit_active
                     << " rules=" << (wd.m_data.contains("rules") ? wd.m_data["rules"].dump() : "none");
            if (segwit_active && wd.m_data.contains("transactions")) {
                // Compute raw wtxid merkle root from block template transactions
                std::vector<uint256> wtxids;
                uint256 zero;  // coinbase wtxid = 0x00
                wtxids.push_back(zero);
                for (auto& tx : wd.m_data["transactions"]) {
                    uint256 wtxid;
                    if (tx.is_object() && tx.contains("hash"))
                        wtxid.SetHex(tx["hash"].get<std::string>());
                    else if (tx.is_object() && tx.contains("txid"))
                        wtxid.SetHex(tx["txid"].get<std::string>());
                    wtxids.push_back(wtxid);
                }
                witness_root = compute_witness_merkle_root(std::move(wtxids));
                // P2Pool commitment: SHA256d(witness_root || '[Pool]'*4)
                witness_commitment = compute_p2pool_witness_commitment_hex(witness_root);
            }

            // Build fallback coinbase (without OP_RETURN, for non-p2pool or initial work)
            cb_parts = build_coinbase_parts(wd.m_data, coinbase_value, pplns_outputs,
                                            pplns_raw_scripts, mm_commitment, witness_commitment,
                                            {}, uint256(), m_coinbase_text);
        } catch (const std::exception& e) {
            LOG_WARNING << "refresh_work: coinbase build failed: " << e.what();
            cb_parts = { "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff", "ffffffff0100f2052a01000000434104" };
        }

        // Compute THE state root for sharechain anchoring (both LTC and merged coinbases)
        uint32_t tmpl_h = wd.m_data.value("height", 0);
        uint32_t tmpl_b = 0;
        {
            auto bs = wd.m_data.value("bits", std::string(""));
            if (bs.size() == 8) tmpl_b = static_cast<uint32_t>(std::stoul(bs, nullptr, 16));
        }
        auto the_root = compute_the_state_root(pplns_outputs,
            static_cast<uint32_t>(pplns_outputs.size()), tmpl_h, tmpl_b);

        // Commit to cache under mutex
        std::lock_guard<std::mutex> lock(m_work_mutex);
        m_cached_template         = wd.m_data;
        m_cached_merkle_branches  = std::move(merkle_branches);
        m_cached_coinb1           = std::move(cb_parts.first);
        m_cached_coinb2           = std::move(cb_parts.second);
        m_segwit_active           = segwit_active;
        m_cached_pplns_outputs    = std::move(pplns_outputs);
        m_cached_raw_scripts      = pplns_raw_scripts;
        m_cached_witness_commitment = std::move(witness_commitment);
        m_cached_witness_root       = witness_root;
        m_cached_mm_commitment    = std::move(mm_commitment);
        m_cached_the_state_root   = the_root;
        m_cached_sharechain_height = tmpl_h;
        m_cached_miner_count       = static_cast<uint16_t>(m_cached_pplns_outputs.size());
        m_cached_mweb             = wd.m_data.contains("mweb")
                                  ? wd.m_data["mweb"].get<std::string>() : "";
        m_work_valid              = true;
        ++m_work_generation;
        m_last_work_update_time   = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        LOG_INFO << "[LTC] refresh_work: height=" << wd.m_data.value("height", 0)
                 << " txs=" << wd.m_hashes.size()
                 << " latency=" << wd.m_latency << "ms"
                 << " merkle_branches=" << m_cached_merkle_branches.size();

        // Push real network difficulty to external consumers (AdjustmentEngine)
        if (m_on_network_difficulty_fn) {
            try {
                uint32_t nbits_val = std::stoul(
                    wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                double net_diff = chain::target_to_difficulty(
                    chain::bits_to_target(nbits_val));
                if (net_diff > 0) {
                    m_on_network_difficulty_fn(net_diff);
                    m_network_difficulty.store(net_diff, std::memory_order_relaxed);
                    add_netdiff_sample(net_diff, "block");
                }
            } catch (...) {}
        } else {
            // Even without callback, store network difficulty for API endpoints
            try {
                uint32_t nbits_val = std::stoul(
                    wd.m_data.value("bits", "1d00ffff"), nullptr, 16);
                double net_diff = chain::target_to_difficulty(
                    chain::bits_to_target(nbits_val));
                if (net_diff > 0) {
                    m_network_difficulty.store(net_diff, std::memory_order_relaxed);
                    add_netdiff_sample(net_diff, "block");
                }
            } catch (...) {}
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "refresh_work failed: " << e.what();
        m_work_valid = false;
    }
}

nlohmann::json MiningInterface::get_current_work_template() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_work_valid ? m_cached_template : nlohmann::json{};
}

std::vector<std::string> MiningInterface::get_stratum_merkle_branches() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_merkle_branches;
}

std::pair<std::string, std::string> MiningInterface::get_coinbase_parts() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return { m_cached_coinb1, m_cached_coinb2 };
}

bool MiningInterface::get_segwit_active() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_segwit_active;
}

std::string MiningInterface::get_cached_mweb() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_mweb;
}

std::string MiningInterface::get_cached_witness_commitment() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_witness_commitment;
}

uint256 MiningInterface::get_cached_witness_root() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    return m_cached_witness_root;
}

std::string MiningInterface::get_current_gbt_prevhash() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    if (!m_cached_template.is_null() && m_cached_template.contains("previousblockhash"))
        return m_cached_template["previousblockhash"].get<std::string>();
    return {};
}

MiningInterface::WorkSnapshot MiningInterface::get_work_snapshot() const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);
    WorkSnapshot s;
    s.segwit_active = m_segwit_active;
    s.mweb = m_cached_mweb;
    s.subsidy = m_cached_template.is_null() ? 0
                : m_cached_template.value("coinbasevalue", uint64_t(0));
    s.witness_commitment_hex = m_cached_witness_commitment;
    s.witness_root = m_cached_witness_root;
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────

nlohmann::json MiningInterface::getwork(const std::string& request_id)
{
    LOG_INFO << "getwork request received";
    
    // Get current difficulty from the c2pool node
    double current_difficulty = 1.0; // Default fallback
    std::string target_hex = "00000000ffff0000000000000000000000000000000000000000000000000000";
    
    if (m_node) {
        // Get current session difficulty and global pool difficulty
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        // Calculate target from difficulty
        // Target = max_target / difficulty
        // max_target = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
        uint256 max_target;
        max_target.SetHex("00000000FFFF0000000000000000000000000000000000000000000000000000");
        
        uint256 work_target = max_target / static_cast<uint64_t>(current_difficulty * 1000000); // Scale for precision
        target_hex = work_target.GetHex();
        
        LOG_INFO << "Using pool difficulty: " << current_difficulty << ", target: " << target_hex;
    } else {
        LOG_WARNING << "No c2pool node connected, using default difficulty: " << current_difficulty;
    }
    
    // Build work data from the cached block template if available
    std::string work_data;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.is_null()) {
            // Build an 80-byte header stub (version + prevhash + merkle_placeholder + time + bits + nonce_placeholder)
            uint32_t version = m_cached_template.value("version", 536870912U);
            std::string prevhash = m_cached_template.value("previousblockhash", std::string(64, '0'));
            std::string bits = m_cached_template.value("bits", std::string("1d00ffff"));
            uint32_t curtime = static_cast<uint32_t>(m_cached_template.value("curtime", uint64_t(std::time(nullptr))));

            std::ostringstream hdr;
            hdr << std::hex << std::setfill('0')
                << std::setw(2) << ((version      ) & 0xff)
                << std::setw(2) << ((version >>  8) & 0xff)
                << std::setw(2) << ((version >> 16) & 0xff)
                << std::setw(2) << ((version >> 24) & 0xff)
                << prevhash
                << std::string(64, '0') // merkle root placeholder — miners fill this in
                << std::setw(2) << ((curtime      ) & 0xff)
                << std::setw(2) << ((curtime >>  8) & 0xff)
                << std::setw(2) << ((curtime >> 16) & 0xff)
                << std::setw(2) << ((curtime >> 24) & 0xff)
                << bits
                << "00000000"; // nonce placeholder
            work_data = hdr.str();

            // Derive target from bits
            uint32_t nbits = static_cast<uint32_t>(std::stoul(bits, nullptr, 16));
            uint256 tmpl_target = chain::bits_to_target(nbits);
            target_hex = tmpl_target.GetHex();
        }
    }

    if (work_data.empty()) {
        // Fallback: static placeholder
        work_data = "00000001" + std::string(64, '0') + std::string(64, '0')
                    + "00000000" + "1d00ffff" + "00000000";
        LOG_WARNING << "getwork: no live template, returning placeholder work";
    }
    
    nlohmann::json work = {
        {"data", work_data},
        {"target", target_hex},
        {"difficulty", current_difficulty}
    };
    
    // Store work for later validation
    std::string work_id = std::to_string(m_work_id_counter++);
    m_active_work[work_id] = work;
    
    LOG_INFO << "Provided work to miner, work_id=" << work_id << ", difficulty=" << current_difficulty;
    return work;
}

nlohmann::json MiningInterface::submitwork(const std::string& nonce, const std::string& header, const std::string& mix, const std::string& request_id)
{
    LOG_INFO << "Work submission received - nonce: " << nonce << ", header: " << header;
    
    // Validate the submitted work by computing scrypt PoW hash
    bool work_valid = false;
    if (header.size() >= 160) { // 80 bytes = 160 hex chars
        auto header_bytes = ParseHex(header.substr(0, 160));
        if (header_bytes.size() == 80) {
            char pow_hash_bytes[32];
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_bytes.data()), pow_hash_bytes);
            uint256 pow_hash;
            memcpy(pow_hash.begin(), pow_hash_bytes, 32);

            // Check against the template target
            uint256 target;
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (m_work_valid && m_cached_template.contains("bits")) {
                    std::string bits_hex = m_cached_template["bits"].get<std::string>();
                    uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                    target = chain::bits_to_target(bits);
                } else {
                    target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
                }
            }
            work_valid = (pow_hash <= target);
            LOG_INFO << "PoW check: hash=" << pow_hash.GetHex().substr(0, 16)
                     << "... target=" << target.GetHex().substr(0, 16)
                     << "... valid=" << work_valid;
        }
    }
    
    if (work_valid && m_node) {
        // Track the mining_share submission for difficulty adjustment
        std::string session_id = "miner_" + std::to_string(m_work_id_counter);
        m_node->track_mining_share_submission(session_id, 1.0);
        
        // Create a new mining_share and add to the sharechain
        uint256 share_hash;
        share_hash.SetHex(header); // Simplified - would need proper hash calculation
        
        uint256 prev_hash = m_best_share_hash_fn ? m_best_share_hash_fn() : uint256::ZERO;
        uint256 target;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (m_work_valid && m_cached_template.contains("bits")) {
                std::string bits_hex = m_cached_template["bits"].get<std::string>();
                uint32_t bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
                target = chain::bits_to_target(bits);
            } else {
                target.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
            }
        }
        
        m_node->add_local_mining_share(share_hash, prev_hash, target);
        
        LOG_INFO << "Mining share submitted and added to sharechain: " << share_hash.ToString();
        LOG_INFO << "Work submission accepted";
        return true;
    } else if (work_valid) {
        LOG_INFO << "Work submission accepted (no node connected for tracking)";
        return true;
    } else {
        LOG_WARNING << "Work submission rejected - invalid work";
        return false;
    }
}

nlohmann::json MiningInterface::getblocktemplate(const nlohmann::json& params, const std::string& request_id)
{
    LOG_INFO << "getblocktemplate request received";

    // Return live template if available
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (m_work_valid && !m_cached_template.empty())
            return m_cached_template;
    }

    // Fallback: static placeholder so callers always get a valid JSON object
    LOG_WARNING << "getblocktemplate: no live template yet, returning placeholder";
    return {
        {"version", 536870912},
        {"previousblockhash", "0000000000000000000000000000000000000000000000000000000000000000"},
        {"transactions", nlohmann::json::array()},
        {"coinbaseaux", nlohmann::json::object()},
        {"coinbasevalue", 5000000000LL},
        {"target", "00000000ffff0000000000000000000000000000000000000000000000000000"},
        {"mintime", 1234567890},
        {"mutable", nlohmann::json::array({"time", "transactions", "prevblock"})},
        {"noncerange", "00000000ffffffff"},
        {"sigoplimit", 20000},
        {"sizelimit", 1000000},
        {"curtime", static_cast<uint64_t>(std::time(nullptr))},
        {"bits", "1d00ffff"},
        {"height", 1},
        {"rules", nlohmann::json::array({"segwit"})}
    };
}

nlohmann::json MiningInterface::submitblock(const std::string& hex_data, const std::string& request_id)
{
    LOG_TRACE << "[LTC] submitblock: received " << hex_data.length() / 2 << " bytes";

    // Block header is 80 bytes = 160 hex chars minimum
    if (hex_data.size() < 160) {
        LOG_ERROR << "[LTC] submitblock: hex data too short for a valid block header";
        return {{"error", "block data too short"}};
    }

    // Parse the 80-byte block header:
    //   bytes  0- 3: version  (uint32 LE)
    //   bytes  4-35: prev_block_hash (32 bytes, internal byte order)
    //   bytes 36-67: merkle_root     (32 bytes, internal byte order)
    //   bytes 68-71: timestamp (uint32 LE)
    //   bytes 72-75: nbits     (uint32 LE)
    //   bytes 76-79: nonce     (uint32 LE)
    auto header_bytes = ParseHex(hex_data.substr(0, 160));

    // Extract prev_block_hash (bytes 4..35), reversed for display/comparison
    uint256 submitted_prev_hash;
    std::memcpy(submitted_prev_hash.data(), header_bytes.data() + 4, 32);

    // Extract merkle_root (bytes 36..67)
    uint256 submitted_merkle_root;
    std::memcpy(submitted_merkle_root.data(), header_bytes.data() + 36, 32);

    // Validate prev_block_hash matches our cached template
    {
        bool is_stale = false;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (m_work_valid && !m_cached_template.is_null()
                && m_cached_template.contains("previousblockhash"))
            {
                uint256 expected_prev;
                expected_prev.SetHex(m_cached_template["previousblockhash"].get<std::string>());
                if (submitted_prev_hash != expected_prev) {
                    LOG_WARNING << "[LTC] submitblock: stale block — prev_hash mismatch"
                                << " submitted=" << submitted_prev_hash.GetHex()
                                << " expected=" << expected_prev.GetHex();
                    is_stale = true;
                }
            }

            // Reconstruct expected merkle_root from coinbase + merkle branches
            if (!is_stale && !m_cached_coinb1.empty() && !m_cached_coinb2.empty()) {
                LOG_TRACE << "[LTC] submitblock: merkle_root=" << submitted_merkle_root.GetHex();
            }
        }
        // Fire stale callback OUTSIDE the lock to avoid deadlock
        if (is_stale) {
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 253);
            }
            return {{"error", "stale block: previous block hash mismatch"}};
        }
    }

    if (m_coin_rpc) {
        try {
            bool accepted = m_coin_rpc->submit_block_hex(hex_data, "", false);
            LOG_INFO << "Block forwarded to coin daemon";
            if (accepted) {
                // Notify P2P layer with stale_info=0 (none — accepted)
                if (m_on_block_submitted && hex_data.size() >= 160) {
                    m_on_block_submitted(hex_data.substr(0, 160), 0);
                }
                // Relay full block via P2P for fast propagation
                if (m_on_block_relay) {
                    m_on_block_relay(hex_data);
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "submitblock failed: " << e.what();
            // Fire callback with doa stale info (254)
            if (m_on_block_submitted && hex_data.size() >= 160) {
                m_on_block_submitted(hex_data.substr(0, 160), 254);
            }
            return {{"error", std::string(e.what())}};
        }
    } else if (m_embedded_node) {
        // Phase 4 embedded mode: no daemon — relay the block directly via P2P.
        // on_block_relay is wired to CoinBroadcaster::submit_block_raw().
        size_t block_size = hex_data.size() / 2;
        LOG_INFO << "[EMB-LTC] submitblock: embedded relay " << block_size << " bytes";

        // Parse and log header fields for debugging
        if (hex_data.size() >= 160) {
            auto hdr = ParseHex(hex_data.substr(0, 160));
            uint32_t ver = hdr[0] | (hdr[1]<<8) | (hdr[2]<<16) | (hdr[3]<<24);
            LOG_INFO << "[EMB-LTC] submitblock header:"
                     << " version=0x" << std::hex << ver << std::dec
                     << " prev=" << HexStr(std::span<const unsigned char>(hdr.data()+4, 32))
                     << " merkle=" << HexStr(std::span<const unsigned char>(hdr.data()+36, 32))
                     << " bits=" << HexStr(std::span<const unsigned char>(hdr.data()+72, 4))
                     << " nonce=" << HexStr(std::span<const unsigned char>(hdr.data()+76, 4));
            // Log tx count varint
            if (hex_data.size() > 162) {
                auto txcnt_byte = ParseHex(hex_data.substr(160, 2));
                LOG_INFO << "[EMB-LTC] submitblock tx_count_byte=0x"
                         << std::hex << (int)txcnt_byte[0] << std::dec
                         << " total_hex_len=" << hex_data.size();
            }
        }

        // Save block hex to file for manual submitblock testing
        {
            std::string path = "/tmp/c2pool_block_" + std::to_string(std::time(nullptr)) + ".hex";
            std::ofstream f(path);
            if (f) {
                f << hex_data;
                LOG_INFO << "[EMB-LTC] Block hex saved to " << path
                         << " (" << block_size << " bytes)"
                         << " — test with: litecoin-cli -testnet submitblock $(cat " << path << ")";
            }
        }

        // Fire block-found callback immediately (synchronous — updates stats)
        if (m_on_block_submitted && hex_data.size() >= 160)
            m_on_block_submitted(hex_data.substr(0, 160), 0);

        // Thread the slow parts (P2P relay + RPC) so stratum isn't blocked.
        // P2P relay runs FIRST — fast propagation is critical for block acceptance.
        // RPC runs SECOND — provides accept/reject feedback but is not time-critical.
        auto rpc_fn   = m_rpc_submit_fallback;
        auto relay_fn = m_on_block_relay;
        std::string hex_copy = hex_data;
        std::thread([rpc_fn, relay_fn, hex_copy]() {
            // 1) P2P relay to all connected peers — time-critical for acceptance
            if (relay_fn) {
                try {
                    relay_fn(hex_copy);
                    LOG_INFO << "[EMB-LTC] P2P block relay dispatched";
                } catch (const std::exception& e) {
                    LOG_ERROR << "[EMB-LTC] P2P relay exception: " << e.what();
                }
            } else {
                LOG_WARNING << "[EMB-LTC] No P2P relay callback — block not broadcast!";
            }
            // 2) RPC submitblock (if configured) — accept/reject feedback
            if (rpc_fn) {
                std::string rpc_err = rpc_fn(hex_copy);
                if (rpc_err.empty()) {
                    LOG_INFO << "[EMB-LTC] submitblock via RPC: ACCEPTED";
                } else {
                    LOG_WARNING << "[EMB-LTC] submitblock via RPC: REJECTED — " << rpc_err;
                }
            }
        }).detach();
    } else {
        LOG_WARNING << "[LTC] submitblock: no coin RPC or embedded node connected, block discarded";
    }

    return nullptr; // null = accepted in getblocktemplate spec
}

nlohmann::json MiningInterface::getinfo(const std::string& request_id)
{
    double current_difficulty = 1.0;
    double pool_hashrate = 0.0;
    uint64_t total_shares = 0;
    uint64_t connections = 0;
    
    // Get stats from c2pool node if available
    if (m_node) {
        auto difficulty_stats = m_node->get_difficulty_stats();
        if (difficulty_stats.contains("global_pool_difficulty")) {
            current_difficulty = difficulty_stats["global_pool_difficulty"];
        }
        
        auto hashrate_stats = m_node->get_hashrate_stats();
        if (hashrate_stats.contains("global_hashrate")) {
            pool_hashrate = hashrate_stats["global_hashrate"];
        }
        
        total_shares = m_node->get_total_mining_shares();
        connections = m_node->get_connected_peers_count();
    }
    
    // Read block height from cached template
    uint64_t block_height = 0;
    double network_hashps = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }
    
    nlohmann::json protocol_messages = nlohmann::json::array();
    if (m_protocol_messages_fn) {
        try {
            protocol_messages = m_protocol_messages_fn();
        } catch (const std::exception& e) {
            LOG_WARNING << "protocol_messages hook failed: " << e.what();
        }
    }

    auto operator_blob = get_operator_message_blob();

    return {
        {"version", "c2pool/0.0.1"},
        {"protocolversion", 70015},
        {"blocks", block_height},
        {"connections", connections},
        {"difficulty", current_difficulty},
        {"networkhashps", network_hashps},
        {"poolhashps", pool_hashrate},
        {"poolshares", total_shares},
        {"generate", true},
        {"genproclimit", -1},
        {"testnet", m_testnet},
        {"paytxfee", 0.0},
        {"errors", ""},
        {"operator_message_blob_hex", to_hex(operator_blob)},
        {"protocol_messages", protocol_messages}
    };
}

nlohmann::json MiningInterface::getstats(const std::string& request_id)
{
    uint64_t total_mining_shares = 0;
    uint64_t connected_peers = 0;
    double pool_hashrate = 0.0;
    double difficulty = 1.0;
    uint64_t active_miners = 0;

    if (m_node) {
        total_mining_shares = m_node->get_total_mining_shares();
        connected_peers = m_node->get_connected_peers_count();
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            pool_hashrate = hs["global_hashrate"];
        auto ds = m_node->get_difficulty_stats();
        if (ds.contains("global_pool_difficulty"))
            difficulty = ds["global_pool_difficulty"];
    }

    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm)
        active_miners = pm->get_active_miners_count();

    uint64_t block_height = 0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("height"))
            block_height = m_cached_template["height"].get<uint64_t>();
    }

    nlohmann::json stale = {{"orphan_count", 0}, {"doa_count", 0}, {"stale_count", 0}, {"stale_prop", 0.0}};
    if (m_node)
        stale = m_node->get_stale_stats();

    nlohmann::json protocol_messages = nlohmann::json::array();
    if (m_protocol_messages_fn) {
        try {
            protocol_messages = m_protocol_messages_fn();
        } catch (const std::exception& e) {
            LOG_WARNING << "protocol_messages hook failed: " << e.what();
        }
    }

    auto operator_blob = get_operator_message_blob();

    return {
        {"pool_statistics", {
            {"mining_shares", total_mining_shares},
            {"pool_hashrate", pool_hashrate},
            {"difficulty", difficulty},
            {"block_height", block_height},
            {"connected_peers", connected_peers},
            {"active_miners", active_miners},
            {"orphan_shares", stale["orphan_count"]},
            {"doa_shares", stale["doa_count"]},
            {"stale_shares", stale["stale_count"]},
            {"stale_prop", stale["stale_prop"]}
        }},
        {"operator_message_blob_hex", to_hex(operator_blob)},
        {"protocol_messages", protocol_messages}
    };
}

nlohmann::json MiningInterface::setmessageblob(const std::string& message_blob_hex,
                                               const std::string& request_id)
{
    if (message_blob_hex.empty()) {
        set_operator_message_blob({});
        return {
            {"ok", true},
            {"enabled", false},
            {"size", 0},
            {"message", "operator message blob cleared"}
        };
    }

    if (message_blob_hex.size() % 2 != 0) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob hex length must be even");
    }

    std::vector<unsigned char> blob;
    try {
        blob = ParseHex(message_blob_hex);
    } catch (const std::exception& e) {
        throw jsonrpccxx::JsonRpcException(-1, std::string("invalid hex blob: ") + e.what());
    }

    if (blob.size() > 4096) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob too large (max 4096 bytes)");
    }

    // Validate encrypted authority blob using V36 consensus validation path.
    auto err = ltc::validate_message_data(blob);
    if (!err.empty()) {
        throw jsonrpccxx::JsonRpcException(-1, "message blob rejected: " + err);
    }

    set_operator_message_blob(blob);
    return {
        {"ok", true},
        {"enabled", true},
        {"size", blob.size()},
        {"hex", message_blob_hex}
    };
}

nlohmann::json MiningInterface::getmessageblob(const std::string& request_id)
{
    auto blob = get_operator_message_blob();
    return {
        {"enabled", !blob.empty()},
        {"size", blob.size()},
        {"hex", to_hex(blob)}
    };
}

nlohmann::json MiningInterface::getpeerinfo(const std::string& request_id)
{
    nlohmann::json peers = nlohmann::json::array();
    if (m_node) {
        size_t count = m_node->get_connected_peers_count();
        // Return minimal info — detailed peer data requires NodeImpl access
        peers.push_back({
            {"connected_peers", count}
        });
    }
    return peers;
}

nlohmann::json MiningInterface::getpayoutinfo(const std::string& request_id)
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (!pm)
        return {{"error", "payout manager not available"}};

    return pm->get_payout_statistics();
}

nlohmann::json MiningInterface::getminerstats(const std::string& request_id)
{
    nlohmann::json result;
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm) {
        result["active_miners"] = pm->get_active_miners_count();
        result["pplns_active"] = pm->has_pplns_data();
        result["payout_statistics"] = pm->get_payout_statistics();
    }
    if (m_node) {
        result["hashrate"] = m_node->get_hashrate_stats();
        result["difficulty"] = m_node->get_difficulty_stats();
        result["stale_stats"] = m_node->get_stale_stats();
    }
    return result;
}

// ──────────────────────── p2pool-compatible REST endpoints ────────────────────

nlohmann::json MiningInterface::rest_local_rate()
{
    double rate = 0.0;
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            rate = hs["global_hashrate"];
    }
    return rate;
}

nlohmann::json MiningInterface::rest_global_rate()
{
    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    if (net_diff > 0) {
        // network_hashrate = net_difficulty * 2^32 / block_period (150s for LTC)
        return net_diff * 4294967296.0 / 150.0;
    }
    double rate = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("networkhashps"))
            rate = m_cached_template["networkhashps"].get<double>();
    }
    return rate;
}

nlohmann::json MiningInterface::rest_current_payouts()
{
    nlohmann::json result = nlohmann::json::object();
    bool is_ltc = (m_blockchain == Blockchain::LITECOIN);

    // Primary source: cached PPLNS outputs from the coinbase builder.
    // These are always up-to-date with the latest share template and subsidy.
    auto cached = get_cached_pplns_outputs();
    if (!cached.empty()) {
        for (const auto& [script_hex, amount] : cached) {
            // script_hex is a hex-encoded scriptPubKey — decode to bytes, then to address
            auto script_bytes = ParseHex(script_hex);
            std::string addr = core::script_to_address(script_bytes, is_ltc, m_testnet);
            if (addr.empty() && script_bytes.size() > 33 && script_bytes.back() == 0xac) {
                // P2PK: PUSH<len> <pubkey> OP_CHECKSIG → hash pubkey → P2PKH address
                size_t pk_len = script_bytes[0];
                if (pk_len + 1 == script_bytes.size() - 1) {
                    // SHA256 → RIPEMD160 (Hash160)
                    unsigned char sha[32], rip[20];
                    CSHA256().Write(&script_bytes[1], pk_len).Finalize(sha);
                    CRIPEMD160().Write(sha, 32).Finalize(rip);
                    std::vector<unsigned char> p2pkh = {0x76, 0xa9, 0x14};
                    p2pkh.insert(p2pkh.end(), rip, rip + 20);
                    p2pkh.push_back(0x88);
                    p2pkh.push_back(0xac);
                    addr = core::script_to_address(p2pkh, is_ltc, m_testnet);
                }
            }
            if (addr.empty())
                addr = script_hex;
            // p2pool returns coins (not satoshis)
            result[addr] = static_cast<double>(amount) / 1e8;
        }
        return result;
    }

    // Fallback: PayoutManager (for modes without coinbase builder)
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            for (const auto& [script, amount] : outputs) {
                std::string addr = core::script_to_address(script, is_ltc, m_testnet);
                if (addr.empty() && script.size() > 33 && script.back() == 0xac) {
                    size_t pk_len = script[0];
                    if (pk_len + 1 == script.size() - 1) {
                        unsigned char sha[32], rip[20];
                        CSHA256().Write(&script[1], pk_len).Finalize(sha);
                        CRIPEMD160().Write(sha, 32).Finalize(rip);
                        std::vector<unsigned char> p2pkh = {0x76, 0xa9, 0x14};
                        p2pkh.insert(p2pkh.end(), rip, rip + 20);
                        p2pkh.push_back(0x88);
                        p2pkh.push_back(0xac);
                        addr = core::script_to_address(p2pkh, is_ltc, m_testnet);
                    }
                }
                if (addr.empty()) {
                    static const char* HEX = "0123456789abcdef";
                    addr.reserve(script.size() * 2);
                    for (unsigned char b : script) {
                        addr += HEX[b >> 4];
                        addr += HEX[b & 0x0f];
                    }
                }
                result[addr] = static_cast<double>(amount) / 1e8;
            }
        }
    }
    return result;
}

nlohmann::json MiningInterface::rest_users()
{
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    return pm ? nlohmann::json(pm->get_active_miners_count()) : nlohmann::json(0);
}

nlohmann::json MiningInterface::rest_fee()
{
    return m_pool_fee_percent;
}

nlohmann::json MiningInterface::rest_recent_blocks()
{
    static const char* status_str[] = {"pending", "confirmed", "orphaned", "stale"};
    nlohmann::json arr = nlohmann::json::array();
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    for (const auto& b : m_found_blocks) {
        std::string method = (b.time_to_find > 0 && b.luck > 0) ? "simple_avg" : "first_block";
        arr.push_back({
            {"ts", b.ts},
            {"hash", b.hash},
            {"number", b.height},
            {"height", b.height},
            {"status", status_str[static_cast<int>(b.status)]},
            {"verified", b.status == BlockStatus::confirmed},
            {"checks", b.check_count},
            {"chain", b.chain},
            {"confirmations", b.confirmations},
            {"miner", b.miner},
            {"share", b.share_hash},
            {"network_difficulty", b.network_difficulty},
            {"share_difficulty", b.share_difficulty},
            {"pool_hashrate_at_find", b.pool_hashrate},
            {"subsidy", b.subsidy},
            {"expected_time", b.expected_time},
            {"time_to_find", b.time_to_find},
            {"luck", b.luck},
            {"luck_method", method}
        });
    }
    return arr;
}

nlohmann::json MiningInterface::rest_checkpoint()
{
    if (m_checkpoint_latest_fn)
        return m_checkpoint_latest_fn();
    return nlohmann::json::object({{"error", "checkpoint store not configured"}});
}

nlohmann::json MiningInterface::rest_checkpoints()
{
    if (m_checkpoints_all_fn)
        return m_checkpoints_all_fn();
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_uptime()
{
    // Return daemon uptime in seconds
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    return nlohmann::json(uptime_seconds);
}

nlohmann::json MiningInterface::rest_connected_miners()
{
    // p2pool returns a simple array of unique miner addresses
    auto workers = get_stratum_workers();
    std::set<std::string> unique_addrs;
    for (const auto& [sid, w] : workers) {
        // Strip worker suffix: "addr.worker" → "addr"
        std::string base = w.username;
        auto dot = base.find('.');
        if (dot != std::string::npos) base = base.substr(0, dot);
        unique_addrs.insert(base);
    }
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& addr : unique_addrs)
        arr.push_back(addr);
    return arr;
}

nlohmann::json MiningInterface::rest_stratum_stats()
{
    nlohmann::json result = nlohmann::json::object();
    auto workers = get_stratum_workers();

    double total_hashrate = 0.0;
    uint64_t total_accepted = 0, total_rejected = 0, total_stale = 0;
    std::set<std::string> unique_addrs;

    nlohmann::json workers_json = nlohmann::json::object();
    for (const auto& [sid, w] : workers) {
        total_hashrate += w.hashrate;
        total_accepted += w.accepted;
        total_rejected += w.rejected;
        total_stale += w.stale;
        unique_addrs.insert(w.username);

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - w.connected_at).count();

        // Key by worker name: "ADDRESS.worker" (like p2pool) or just "ADDRESS" if no worker suffix
        std::string worker_key = w.worker_name.empty()
            ? w.username
            : w.username + "." + w.worker_name;

        // Aggregate multiple connections for the same worker (p2pool behavior)
        if (workers_json.contains(worker_key)) {
            workers_json[worker_key]["connections"] = workers_json[worker_key]["connections"].get<int>() + 1;
            workers_json[worker_key]["connection_difficulties"].push_back(w.difficulty);
            workers_json[worker_key]["hash_rate"] = workers_json[worker_key]["hash_rate"].get<double>() + w.hashrate;
            workers_json[worker_key]["dead_hash_rate"] = workers_json[worker_key]["dead_hash_rate"].get<double>() + w.dead_hashrate;
            workers_json[worker_key]["accepted"] = workers_json[worker_key]["accepted"].get<uint64_t>() + w.accepted;
            workers_json[worker_key]["rejected"] = workers_json[worker_key]["rejected"].get<uint64_t>() + w.rejected;
            workers_json[worker_key]["stale"] = workers_json[worker_key]["stale"].get<uint64_t>() + w.stale;
        } else {
            workers_json[worker_key] = {
            {"hash_rate", w.hashrate},
            {"dead_hash_rate", w.dead_hashrate},
            {"connections", 1},
            {"connection_difficulties", nlohmann::json::array({w.difficulty})},
            {"last_seen", static_cast<uint64_t>(std::time(nullptr))},
            {"difficulty", w.difficulty},
            {"accepted", w.accepted},
            {"rejected", w.rejected},
            {"stale", w.stale},
            {"connected_seconds", elapsed},
            {"remote_endpoint", w.remote_endpoint}
        };
        }
    }

    result["difficulty"] = 1.0;
    if (!workers.empty())
        result["difficulty"] = workers.begin()->second.difficulty;
    result["accepted_shares"] = total_accepted;
    result["rejected_shares"] = total_rejected;
    result["stale_shares"] = total_stale;
    result["hashrate"] = total_hashrate;
    result["active_workers"] = static_cast<int>(workers.size());
    result["unique_addresses"] = static_cast<int>(unique_addrs.size());
    result["workers"] = workers_json;

    double total_shares = static_cast<double>(total_accepted + total_rejected + total_stale);
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - m_stratum_start_time).count();
    result["shares_per_minute"] = (uptime > 0) ? (total_shares * 60.0 / uptime) : 0.0;
    result["last_share_time"] = static_cast<uint64_t>(std::time(nullptr));
    result["uptime_seconds"] = static_cast<double>(uptime);

    {
        std::lock_guard<std::mutex> lock(m_control_mutex);
        result["mining_enabled"] = m_mining_enabled;
        result["banned_count"] = static_cast<uint64_t>(m_banned_targets.size());
    }

    return result;
}

nlohmann::json MiningInterface::rest_miner_thresholds()
{
    nlohmann::json result = nlohmann::json::object();

    // Get pool hashrate from global_stats computation
    auto gs = rest_global_stats();
    double pool_hr = gs.value("pool_hash_rate", 0.0);

    // Get block subsidy from cached GBT template
    uint64_t subsidy = 156250000; // default 1.5625 LTC
    if (m_cached_template.contains("coinbasevalue"))
        subsidy = m_cached_template.value("coinbasevalue", subsidy);

    // Network params (testnet defaults, overridden by config)
    uint32_t chain_length = 400;  // REAL_CHAIN_LENGTH
    uint32_t share_period = 4;    // SHARE_PERIOD
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("chain_length"))
            chain_length = hs.value("chain_length", chain_length);
        if (hs.contains("share_period"))
            share_period = hs.value("share_period", share_period);
    }

    double window_sec = static_cast<double>(chain_length) * share_period;

    // min_hashrate = pool_hashrate / chain_length (1 share per window)
    double min_hr_normal = pool_hr / chain_length;
    double min_hr_dust = min_hr_normal / 30.0; // 30x DUST range

    // min_payout = subsidy / chain_length
    double min_payout = static_cast<double>(subsidy) / 1e8 / chain_length;

    result["pool_hashrate"] = pool_hr;
    result["min_hashrate_normal"] = min_hr_normal;
    result["min_hashrate_dust"] = min_hr_dust;
    result["min_payout_ltc"] = min_payout;
    result["block_subsidy_ltc"] = static_cast<double>(subsidy) / 1e8;
    result["chain_length"] = chain_length;
    result["share_period"] = share_period;
    result["window_seconds"] = window_sec;
    result["dust_range"] = 30;

    // Human-readable formatting
    auto fmt_hr = [](double hr) -> std::string {
        char buf[32];
        if (hr >= 1e12) { snprintf(buf, sizeof(buf), "%.2f TH/s", hr / 1e12); return buf; }
        if (hr >= 1e9)  { snprintf(buf, sizeof(buf), "%.2f GH/s", hr / 1e9);  return buf; }
        if (hr >= 1e6)  { snprintf(buf, sizeof(buf), "%.2f MH/s", hr / 1e6);  return buf; }
        if (hr >= 1e3)  { snprintf(buf, sizeof(buf), "%.2f KH/s", hr / 1e3);  return buf; }
        snprintf(buf, sizeof(buf), "%.0f H/s", hr); return buf;
    };
    result["min_hashrate_display"] = fmt_hr(min_hr_dust);
    result["pool_hashrate_display"] = fmt_hr(pool_hr);

    return result;
}

nlohmann::json MiningInterface::rest_global_stats()
{
    // Return p2pool-compatible pool statistics
    nlohmann::json result = nlohmann::json::object();
    
    double pool_rate = 0.0;
    double share_diff = 1.0;
    int unique_miners = 0;
    int total_shares = 0;
    int orphan_shares = 0, dead_shares = 0;
    int chain_height = 0;

    // Populate from sharechain
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("total_shares"))
            total_shares = sc["total_shares"].get<int>();
        if (sc.contains("orphan_shares"))
            orphan_shares = sc["orphan_shares"].get<int>();
        if (sc.contains("dead_shares"))
            dead_shares = sc["dead_shares"].get<int>();
        if (sc.contains("chain_height"))
            chain_height = sc["chain_height"].get<int>();
        if (sc.contains("average_difficulty"))
            share_diff = sc["average_difficulty"].get<double>();
        if (sc.contains("shares_by_miner") && sc["shares_by_miner"].is_object())
            unique_miners = static_cast<int>(sc["shares_by_miner"].size());
    }

    // Pool hashrate from P2P node's get_pool_attempts_per_second (p2pool-correct)
    if (m_pool_hashrate_fn) {
        double hr = m_pool_hashrate_fn();
        if (hr > 0) pool_rate = hr;
    }
    
    // Network difficulty and hashrate
    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    double net_hashrate = 0.0;
    if (net_diff > 0) {
        // network_hashrate = net_difficulty * 2^32 / block_period
        double block_period = 150.0;  // LTC default 2.5 min
        net_hashrate = net_diff * 4294967296.0 / block_period;
    }

    // p2pool field names the dashboard expects
    // pool_stale_prop = stales / (lookbehind + stales), matching p2pool's get_average_stale_prop()
    int stales = orphan_shares + dead_shares;
    int good = total_shares - stales;
    double pool_stale_prop = (good + stales > 0) ? static_cast<double>(stales) / (good + stales) : 0.0;
    result["pool_hash_rate"] = pool_rate;
    result["pool_nonstale_hash_rate"] = pool_rate * (1.0 - pool_stale_prop);
    result["pool_stale_prop"] = pool_stale_prop;
    result["min_difficulty"] = share_diff;
    result["network_block_difficulty"] = net_diff;

    // Additional fields
    result["network_hashrate"] = net_hashrate;
    result["shares_in_chain"] = total_shares;
    result["unique_miners"] = unique_miners;
    result["current_height"] = chain_height;
    result["uptime_seconds"] = rest_uptime();
    result["status"] = "operational";
    result["last_block"] = 0;

    return result;
}

nlohmann::json MiningInterface::rest_sharechain_stats()
{
    // Delegate to the live tracker callback if wired
    if (m_sharechain_stats_fn)
        return m_sharechain_stats_fn();

    // Fallback: return empty stub when no tracker is connected
    nlohmann::json result = nlohmann::json::object();
    result["total_shares"] = 0;
    result["shares_by_version"] = nlohmann::json::object();
    result["shares_by_miner"] = nlohmann::json::object();
    result["chain_height"] = 0;
    result["chain_tip_hash"] = "";
    result["fork_count"] = 0;
    result["heaviest_fork_weight"] = 0.0;
    result["average_difficulty"] = 1.0;
    result["difficulty_trend"] = nlohmann::json::array();
    auto now = std::time(nullptr);
    nlohmann::json timeline = nlohmann::json::array();
    for (int i = 5; i >= 0; --i) {
        nlohmann::json slot;
        slot["timestamp"] = now - (i * 600);
        slot["share_count"] = 0;
        slot["miner_distribution"] = nlohmann::json::object();
        timeline.push_back(slot);
    }
    result["timeline"] = timeline;
    return result;
}

nlohmann::json MiningInterface::rest_sharechain_window()
{
    if (m_sharechain_window_fn)
        return m_sharechain_window_fn();

    // Fallback stub
    nlohmann::json result;
    result["shares"] = nlohmann::json::array();
    result["total"] = 0;
    result["best_hash"] = "";
    result["chain_length"] = 0;
    return result;
}

nlohmann::json MiningInterface::rest_sharechain_tip()
{
    if (m_sharechain_tip_fn)
        return m_sharechain_tip_fn();
    return nlohmann::json::object({{"hash", ""}, {"height", 0}});
}

nlohmann::json MiningInterface::rest_sharechain_delta(const std::string& since_hash)
{
    if (m_sharechain_delta_fn)
        return m_sharechain_delta_fn(since_hash);
    return nlohmann::json::object({{"shares", nlohmann::json::array()}, {"count", 0}});
}

nlohmann::json MiningInterface::rest_control_mining_start()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = true;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "start"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_stop()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = false;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "stop"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_restart()
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    m_mining_enabled = true;
    return nlohmann::json::object({
        {"ok", true},
        {"action", "restart"},
        {"mining_enabled", m_mining_enabled}
    });
}

nlohmann::json MiningInterface::rest_control_mining_ban(const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    if (!target.empty()) {
        m_banned_targets.insert(target);
    }
    return nlohmann::json::object({
        {"ok", !target.empty()},
        {"action", "ban"},
        {"target", target},
        {"banned_count", static_cast<uint64_t>(m_banned_targets.size())}
    });
}

nlohmann::json MiningInterface::rest_control_mining_unban(const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_control_mutex);
    if (!target.empty()) {
        m_banned_targets.erase(target);
    }
    return nlohmann::json::object({
        {"ok", !target.empty()},
        {"action", "unban"},
        {"target", target},
        {"banned_count", static_cast<uint64_t>(m_banned_targets.size())}
    });
}

void MiningInterface::record_found_block(uint64_t height, const uint256& hash, uint64_t ts,
                                          const std::string& chain,
                                          const std::string& miner,
                                          const std::string& share_hash,
                                          double network_difficulty,
                                          double share_difficulty,
                                          double pool_hashrate,
                                          uint64_t subsidy)
{
    if (ts == 0) ts = static_cast<uint64_t>(std::time(nullptr));
    std::string hash_hex = hash.GetHex();

    // Runtime dedup: skip if this hash+chain combo already exists
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        for (const auto& existing : m_found_blocks) {
            if (existing.hash == hash_hex && existing.chain == chain)
                return;  // already recorded
        }
    }

    FoundBlock blk{height, hash_hex, ts, BlockStatus::pending, 0, chain, 0,
                   miner, share_hash, network_difficulty, share_difficulty,
                   pool_hashrate, subsidy, 0, 0, 0};

    // Compute time_to_find from previous block, then derive expected_time and luck
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        // Find previous block in the same chain for time_to_find
        for (const auto& prev : m_found_blocks) {
            if (prev.chain == chain) {
                blk.time_to_find = static_cast<double>(ts) - static_cast<double>(prev.ts);
                break;
            }
        }
        // Fallback: if caller passed 0 pool hashrate, use live pool hashrate
        double hr = pool_hashrate;
        if (hr <= 0 && m_pool_hashrate_fn)
            hr = m_pool_hashrate_fn();
        blk.pool_hashrate = hr;
        // expected_time = network_difficulty * 2^32 / pool_hashrate
        if (hr > 0 && network_difficulty > 0) {
            blk.expected_time = network_difficulty * 4294967296.0 / hr;
        }
        // luck = expected / actual * 100 (>100 = lucky)
        if (blk.time_to_find > 0 && blk.expected_time > 0) {
            blk.luck = blk.expected_time / blk.time_to_find * 100.0;
        }
        m_found_blocks.insert(m_found_blocks.begin(), blk);
    }

    // Persist to LevelDB (Layer +2 — never pruned)
    if (m_persist_block_fn)
    {
        try { m_persist_block_fn(blk); }
        catch (const std::exception& e) {
            LOG_WARNING << "[Pool] Failed to persist found block: " << e.what();
        }
    }

    // Create THE checkpoint from current sharechain state
    // The state_root is already embedded in the block's coinbase — record it
    // so future nodes can verify sharechain integrity against the blockchain.
    if (m_checkpoint_create_fn)
    {
        try { m_checkpoint_create_fn(chain, height, hash.GetHex(), ts); }
        catch (const std::exception& e) {
            LOG_WARNING << "[THE] Failed to create checkpoint: " << e.what();
        }
    }
}

void MiningInterface::set_found_block_persistence(block_store_fn_t persist_fn, block_load_fn_t load_fn)
{
    m_persist_block_fn = std::move(persist_fn);
    m_load_blocks_fn = std::move(load_fn);
}

void MiningInterface::load_persisted_found_blocks()
{
    if (!m_load_blocks_fn) return;

    try {
        auto blocks = m_load_blocks_fn();
        if (blocks.empty()) return;

        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        // Merge loaded blocks with any already in memory (avoid duplicates)
        for (auto& blk : blocks)
        {
            bool exists = false;
            for (const auto& existing : m_found_blocks)
            {
                if (existing.hash == blk.hash && existing.chain == blk.chain)
                {
                    exists = true;
                    break;
                }
            }
            if (!exists)
                m_found_blocks.push_back(std::move(blk));
        }

        // Sort newest first
        std::sort(m_found_blocks.begin(), m_found_blocks.end(),
            [](const FoundBlock& a, const FoundBlock& b) {
                return a.ts > b.ts;
            });

        LOG_INFO << "[Pool] Loaded " << blocks.size() << " found blocks from persistent storage";
    }
    catch (const std::exception& e) {
        LOG_WARNING << "[Pool] Failed to load found blocks: " << e.what();
    }
}

void MiningInterface::backfill_block_fields(block_diff_lookup_fn diff_fn, block_ts_lookup_fn ts_fn)
{
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    int diff_filled = 0, ts_filled = 0;
    for (auto& blk : m_found_blocks) {
        if (!blk.hash.empty()) {
            if (diff_fn && blk.network_difficulty == 0.0) {
                double diff = diff_fn(blk.hash);
                if (diff > 0) { blk.network_difficulty = diff; ++diff_filled; }
            }
            if (ts_fn) {
                uint32_t ts = ts_fn(blk.hash);
                if (ts > 0 && blk.ts != ts) { blk.ts = ts; ++ts_filled; }
            }
        }
    }
    if (diff_filled > 0)
        LOG_INFO << "[Pool] Backfilled network_difficulty on " << diff_filled << " found block(s)";
    if (ts_filled > 0)
        LOG_INFO << "[Pool] Backfilled timestamp on " << ts_filled << " found block(s)";
}

void MiningInterface::set_merged_block_store(std::shared_ptr<void> store) { m_merged_block_store = std::move(store); }

void MiningInterface::set_block_verify_fn(block_verify_fn_t fn) { m_block_verify_fn = std::move(fn); }

void MiningInterface::add_chain_verify_fn(const std::string& chain, block_verify_fn_t fn) {
    m_chain_verify_fns[chain] = std::move(fn);
}

void MiningInterface::verify_found_block(size_t index)
{
    std::string hash;
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        if (index >= m_found_blocks.size()) return;
        auto& blk = m_found_blocks[index];
        if (blk.status != BlockStatus::pending) return;
        blk.check_count++;
        hash = blk.hash;
    }

    // Select chain-specific verifier, fall back to default
    std::string chain;
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        if (index < m_found_blocks.size())
            chain = m_found_blocks[index].chain;
    }
    block_verify_fn_t verify_fn;
    auto it = m_chain_verify_fns.find(chain);
    if (it != m_chain_verify_fns.end())
        verify_fn = it->second;
    else
        verify_fn = m_block_verify_fn;

    if (!verify_fn) return;

    // Callback returns: >0 confirmed, <0 orphaned, 0 unknown/pending
    int result = 0;
    try { result = verify_fn(hash); } catch (...) {}

    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    if (index >= m_found_blocks.size()) return;
    auto& blk = m_found_blocks[index];
    if (blk.status != BlockStatus::pending) return;

    const auto& cn = blk.chain.empty() ? std::string("unknown") : blk.chain;
    auto prev_status = blk.status;

    if (result > 0) {
        blk.confirmations = static_cast<uint32_t>(result);

        if (blk.status == BlockStatus::pending) {
            blk.status = BlockStatus::confirmed;
            auto age_sec = static_cast<uint64_t>(std::time(nullptr)) - blk.ts;
            LOG_INFO << "\n"
                     << "  +++  BLOCK CONFIRMED — " << cn << " height " << blk.height << "  +++\n"
                     << "  Chain:      " << cn << "\n"
                     << "  Height:     " << blk.height << "\n"
                     << "  Block hash: " << blk.hash << "\n"
                     << "  Verified:   check #" << (int)blk.check_count
                     << " (" << age_sec << "s after submission)"
                     << " confirmations=" << blk.confirmations;
        }
        // Already confirmed — just update confirmation count silently
    } else if (result < 0) {
        // Explicit orphan signal from verifier
        if (blk.status == BlockStatus::confirmed) {
            // Deep reorg: was confirmed, now orphaned
            LOG_WARNING << "[Pool] DEEP REORG — " << cn << " height " << blk.height
                        << " was CONFIRMED but now ORPHANED (had " << blk.confirmations << " confs)";
        }
        blk.status = BlockStatus::orphaned;
        blk.confirmations = 0;
        auto age_sec = static_cast<uint64_t>(std::time(nullptr)) - blk.ts;
        LOG_WARNING << "\n"
                    << "  ---  BLOCK ORPHANED — " << cn << " height " << blk.height << "  ---\n"
                    << "  Chain:      " << cn << "\n"
                    << "  Height:     " << blk.height << "\n"
                    << "  Block hash: " << blk.hash << "\n"
                    << "  Checked:    " << (int)blk.check_count
                    << " times over " << age_sec << "s — not in best chain";
    }
    // result == 0: still pending, keep checking

    // Persist any status/confirmation change to LevelDB
    if ((blk.status != prev_status || blk.confirmations > 0) && m_persist_block_fn)
    {
        try { m_persist_block_fn(blk); }
        catch (...) {}
    }
}

void MiningInterface::schedule_block_verification(const std::string& block_hash)
{
    if (!m_context) {
        LOG_WARNING << "schedule_block_verification: io_context not set (this=" << this
                    << "), skipping hash=" << block_hash.substr(0,16);
        return;
    }

    // Find the block index by hash
    size_t idx = SIZE_MAX;
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        for (size_t i = 0; i < m_found_blocks.size(); ++i) {
            if (m_found_blocks[i].hash == block_hash) {
                idx = i;
                break;
            }
        }
    }
    if (idx == SIZE_MAX) return;

    // Schedule verification checks for block acceptance.
    // Block acceptance (in best chain) typically confirmed within 6 blocks.
    // This is NOT coinbase maturity (100/240 confs for spending) — just
    // whether the block was accepted into the blockchain.
    //
    // Chain-specific block times:
    //   LTC: 2.5 min/block → check at +30s, +150s, +300s, +450s, +750s, +1500s
    //   DOGE: 1 min/block  → check at +10s, +60s, +120s, +180s, +360s, +600s
    //
    // After 6 confirmations the block is considered permanently accepted.
    // If still pending after all checks, mark as orphaned.
    std::string chain_name;
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        if (idx < m_found_blocks.size())
            chain_name = m_found_blocks[idx].chain;
    }

    int block_time_sec;
    if (chain_name == "LTC" || chain_name == "tLTC")
        block_time_sec = 150;   // 2.5 minutes
    else if (chain_name == "DOGE")
        block_time_sec = 60;    // 1 minute
    else
        block_time_sec = 60;

    // Check at: first_check, then every block_time for 6 blocks,
    // then one final check at 10 blocks
    auto& ioc = *m_context;
    std::vector<int> delays = {
        block_time_sec / 5,         // quick first check
        block_time_sec,             // ~1 conf
        block_time_sec * 2,         // ~2 confs
        block_time_sec * 3,         // ~3 confs
        block_time_sec * 5,         // ~5 confs
        block_time_sec * 10,        // ~10 confs (final)
    };

    for (int delay : delays) {
        auto timer = std::make_shared<boost::asio::steady_timer>(
            ioc, std::chrono::seconds(delay));
        timer->async_wait([this, idx, timer](boost::system::error_code ec) {
            if (!ec) verify_found_block(idx);
        });
    }
}

// ──────────── p2pool legacy compatibility REST endpoints ─────────────────
// These endpoints reproduce the exact JSON shape that the original p2pool
// dashboard (Forrest Voight) and jtoomim fork expect, enabling third-party
// dashboards built for the classic p2pool lineage to work unchanged.

nlohmann::json MiningInterface::rest_local_stats()
{
    nlohmann::json result = nlohmann::json::object();

    // peers — legacy format: {incoming, outgoing}
    result["peers"] = {{"incoming", 0}, {"outgoing", 0}};
    if (m_peer_info_fn) {
        auto pi = m_peer_info_fn();
        if (pi.is_array()) {
            int incoming = 0, outgoing = 0;
            for (const auto& p : pi) {
                if (p.value("incoming", false)) ++incoming;
                else ++outgoing;
            }
            result["peers"] = {{"incoming", incoming}, {"outgoing", outgoing}};
        }
    } else if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("peer_count"))
            result["peers"]["outgoing"] = hs["peer_count"];
    }

    // miner_hash_rates / miner_dead_hash_rates — from stratum worker registry
    nlohmann::json miner_rates = nlohmann::json::object();
    nlohmann::json miner_dead  = nlohmann::json::object();
    {
        auto workers = get_stratum_workers();
        for (const auto& [sid, w] : workers) {
            // Aggregate by username (address) — multiple workers may share same address
            std::string key = w.username;
            double existing = miner_rates.value(key, 0.0);
            miner_rates[key] = existing + w.hashrate;
            double existing_dead = miner_dead.value(key, 0.0);
            miner_dead[key] = existing_dead + w.dead_hashrate;
        }
    }
    result["miner_hash_rates"] = miner_rates;
    result["miner_dead_hash_rates"] = miner_dead;

    // shares — {total, orphan, dead}
    // Sharechain stats now use O(log n) StatsSkipList — no caching needed.
    nlohmann::json cached_sc;
    int total_shares = 0, orphan_shares = 0, dead_shares = 0;
    double share_diff = 1.0;
    if (m_sharechain_stats_fn) {
        cached_sc = m_sharechain_stats_fn();
        if (cached_sc.contains("total_shares"))
            total_shares = cached_sc["total_shares"].get<int>();
        if (cached_sc.contains("orphan_shares"))
            orphan_shares = cached_sc["orphan_shares"].get<int>();
        if (cached_sc.contains("dead_shares"))
            dead_shares = cached_sc["dead_shares"].get<int>();
        if (cached_sc.contains("average_difficulty"))
            share_diff = cached_sc["average_difficulty"].get<double>();
    }
    result["shares"] = {{"total", total_shares}, {"orphan", orphan_shares}, {"dead", dead_shares}};

    // efficiency = valid / total (null if no shares)
    if (total_shares > 0) {
        int valid = total_shares - orphan_shares - dead_shares;
        result["efficiency"] = static_cast<double>(valid) / total_shares;
    } else {
        result["efficiency"] = nullptr;
    }

    result["uptime"] = rest_uptime();

    // block_value in coins (not satoshis)
    double block_value = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null())
            block_value = m_cached_template.value("coinbasevalue", uint64_t(0)) / 1e8;
    }
    result["block_value"] = block_value;
    // Deduct total fee (node fee + dev donation) from miner portion
    // donation_proportion already represents the combined fee ratio
    double fee_ratio = m_pool_fee_percent / 100.0;
    result["block_value_miner"] = block_value * (1.0 - fee_ratio);
    result["block_value_payments"] = block_value;  // total including fees

    // Node fee amounts per block: fee% × (local_hashrate / pool_hashrate) × block_value
    // Matches p2pool: operator gets fee% of THIS node's contribution, not the whole block.
    {
        double local_hr = m_stratum_hashrate_fn ? m_stratum_hashrate_fn() : 0.0;
        double pool_hr = m_pool_hashrate_fn ? m_pool_hashrate_fn() : 0.0;
        double node_share = (pool_hr > 0 && local_hr > 0) ? local_hr / pool_hr : 0.0;
        result["node_fee_ltc"] = block_value * fee_ratio * node_share;
        if (m_mm_manager) {
            auto chain_infos = m_mm_manager->get_chain_infos();
            for (const auto& ci : chain_infos) {
                double merged_bv = ci.coinbase_value / 1e8;
                std::string sym = ci.symbol;
                for (auto& c : sym) c = std::tolower(c);
                result["node_fee_" + sym] = merged_bv * fee_ratio * node_share;
            }
        }
    }

    // Warnings: daemon health, version alerts, merged chain status
    {
        auto warnings = nlohmann::json::array();

        // 1. LTC daemon contact check (>60s since last work update)
        auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (m_last_work_update_time > 0 && now_s - m_last_work_update_time > 60)
            warnings.push_back("LOST CONTACT WITH LTC DAEMON for "
                + std::to_string(now_s - m_last_work_update_time) + "s! "
                "Check that it isn't frozen or dead!");

        // 2. No work template yet
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_work_valid)
                warnings.push_back("No block template received yet — waiting for daemon connection");
        }

        // 3. Merged chain daemon contact check
        // Threshold: 3x expected block time (LTC ~150s → 450s, DOGE ~60s → 180s).
        // Aux work updates on each new block — brief gaps between blocks are normal.
        if (m_mm_manager) {
            auto chain_infos = m_mm_manager->get_chain_infos();
            for (const auto& ci : chain_infos) {
                int64_t threshold = 180; // 3 minutes default (covers DOGE 1min blocks)
                if (ci.last_update_age_s > threshold)
                    warnings.push_back("LOST CONTACT WITH " + ci.symbol + " DAEMON for "
                        + std::to_string(ci.last_update_age_s) + "s!");
            }
        }

        // 4. No peers connected — use P2P peer info callback if available
        {
            int peers = 0;
            if (m_peer_info_fn) {
                auto pi = m_peer_info_fn();
                peers = pi.is_array() ? static_cast<int>(pi.size()) : 0;
            } else if (m_node) {
                peers = static_cast<int>(m_node->get_connected_peers_count());
            }
            if (peers == 0)
                warnings.push_back("No pool peers connected — share propagation disabled");
        }

        // 5. No miners connected
        if (get_stratum_workers().empty() && !m_solo_mode)
            warnings.push_back("No miners connected — pool is idle");

        // 6. Version signaling: majority voting for unsupported version
        if (m_node) {
            // Reuse cached sharechain stats to avoid a second expensive chain walk
            auto vs = rest_version_signaling(&cached_sc);
            if (vs.contains("versions") && vs["versions"].is_object()) {
                int64_t total_votes = 0;
                int64_t max_version = 0;
                int64_t max_count = 0;
                for (auto& [ver_str, entry] : vs["versions"].items()) {
                    int64_t v = std::stoll(ver_str);
                    int64_t c = entry.is_object() ? entry.value("weight", int64_t(0)) : entry.get<int64_t>();
                    total_votes += c;
                    if (c > max_count) { max_count = c; max_version = v; }
                }
                if (max_version > 36 && total_votes > 0 && max_count * 2 > total_votes)
                    warnings.push_back("MAJORITY VOTING FOR V" + std::to_string(max_version)
                        + " (" + std::to_string(max_count * 100 / total_votes)
                        + "% support) — an upgrade may be necessary!");
            }
        }

        result["warnings"] = warnings;
    }
    result["donation_proportion"] = m_pool_fee_percent / 100.0;
    result["fee"] = m_pool_fee_percent;  // percentage (e.g. 1.0)

    // attempts_to_{share,block} — estimate from difficulty
    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    result["attempts_to_share"] = static_cast<int64_t>(share_diff * 4294967296.0);
    result["attempts_to_block"] = static_cast<int64_t>(net_diff * 4294967296.0);

    // attempts_to_merged_block — from aux chain difficulty
    int64_t merged_attempts = 0;
    if (m_mm_manager && m_mm_manager->has_chains()) {
        auto chain_infos = m_mm_manager->get_chain_infos();
        if (!chain_infos.empty() && chain_infos.front().difficulty > 0) {
            merged_attempts = static_cast<int64_t>(chain_infos.front().difficulty * 4294967296.0);
        }
    }
    result["attempts_to_merged_block"] = merged_attempts;

    // p2pool-compat: my_hash_rates_in_last_hour — aggregate from all local workers
    double total_hr = 0, total_dead = 0;
    {
        auto workers = get_stratum_workers();
        for (const auto& [sid, w] : workers) {
            total_hr += w.hashrate;
            total_dead += w.dead_hashrate;
        }
    }
    result["my_hash_rates_in_last_hour"] = {
        {"nonstale", total_hr - total_dead},
        {"rewarded", total_hr - total_dead},
        {"actual", total_hr},
        {"note", "from stratum worker hashrates"}
    };

    // p2pool-compat: my_share_counts_in_last_hour
    result["my_share_counts_in_last_hour"] = {
        {"shares", total_shares},
        {"unstale_shares", total_shares - orphan_shares - dead_shares},
        {"stale_shares", orphan_shares + dead_shares},
        {"orphan_stale_shares", orphan_shares},
        {"doa_stale_shares", dead_shares}
    };

    // p2pool-compat: my_stale_proportions_in_last_hour
    double stale_prop = total_shares > 0 ? static_cast<double>(orphan_shares + dead_shares) / total_shares : 0.0;
    double orphan_prop = total_shares > 0 ? static_cast<double>(orphan_shares) / total_shares : 0.0;
    double dead_prop = total_shares > 0 ? static_cast<double>(dead_shares) / total_shares : 0.0;
    result["my_stale_proportions_in_last_hour"] = {
        {"stale", stale_prop}, {"orphan_stale", orphan_prop}, {"dead_stale", dead_prop}
    };

    // p2pool-compat: efficiency_if_miner_perfect
    if (total_shares > 0)
        result["efficiency_if_miner_perfect"] = 1.0 - stale_prop;
    else
        result["efficiency_if_miner_perfect"] = nullptr;

    // p2pool-compat: miner_last_difficulties — from stratum workers
    nlohmann::json miner_diffs = nlohmann::json::object();
    {
        auto workers = get_stratum_workers();
        for (const auto& [sid, w] : workers) {
            std::string key = w.username;
            miner_diffs[key] = w.difficulty;
        }
    }
    result["miner_last_difficulties"] = miner_diffs;

    // p2pool-compat: version and protocol_version
    result["version"] = m_pool_version;
    result["protocol_version"] = 3600;  // V36 share format

    return result;
}

nlohmann::json MiningInterface::rest_p2pool_global_stats()
{
    // Original p2pool /global_stats shape
    nlohmann::json result = nlohmann::json::object();
    double pool_rate = 0.0;
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            pool_rate = hs["global_hashrate"];
    }
    result["pool_hash_rate"] = pool_rate;
    result["pool_stale_prop"] = 0.0;
    result["min_difficulty"] = 1.0;
    return result;
}

nlohmann::json MiningInterface::rest_web_version()
{
    return m_pool_version;
}

nlohmann::json MiningInterface::rest_web_currency_info()
{
    nlohmann::json result = nlohmann::json::object();

    switch (m_blockchain) {
    case Blockchain::LITECOIN:
        result["symbol"] = "LTC";
        result["name"] = "Litecoin";
        result["block_period"] = 150;  // 2.5 min average
        if (!m_custom_address_explorer.empty()) {
            result["address_explorer_url_prefix"] = m_custom_address_explorer;
            result["block_explorer_url_prefix"]   = m_custom_block_explorer;
            result["tx_explorer_url_prefix"]      = m_custom_tx_explorer;
        } else if (m_testnet) {
            result["address_explorer_url_prefix"] = "https://blockchair.com/litecoin/testnet/address/";
            result["block_explorer_url_prefix"]   = "https://blockchair.com/litecoin/testnet/block/";
            result["tx_explorer_url_prefix"]      = "https://blockchair.com/litecoin/testnet/transaction/";
        } else {
            result["address_explorer_url_prefix"] = "https://blockchair.com/litecoin/address/";
            result["block_explorer_url_prefix"]   = "https://blockchair.com/litecoin/block/";
            result["tx_explorer_url_prefix"]      = "https://blockchair.com/litecoin/transaction/";
        }
        break;
    case Blockchain::BITCOIN:
        result["symbol"] = "BTC";
        result["name"] = "Bitcoin";
        result["block_period"] = 600;  // 10 min average
        if (!m_custom_address_explorer.empty()) {
            result["address_explorer_url_prefix"] = m_custom_address_explorer;
            result["block_explorer_url_prefix"]   = m_custom_block_explorer;
            result["tx_explorer_url_prefix"]      = m_custom_tx_explorer;
        } else {
            result["address_explorer_url_prefix"] = "https://blockchair.com/bitcoin/address/";
            result["block_explorer_url_prefix"]   = "https://blockchair.com/bitcoin/block/";
            result["tx_explorer_url_prefix"]      = "https://blockchair.com/bitcoin/transaction/";
        }
        break;
    case Blockchain::DOGECOIN:
        result["symbol"] = "DOGE";
        result["name"] = "Dogecoin";
        result["block_period"] = 60;   // 1 min average
        if (!m_custom_address_explorer.empty()) {
            result["address_explorer_url_prefix"] = m_custom_address_explorer;
            result["block_explorer_url_prefix"]   = m_custom_block_explorer;
            result["tx_explorer_url_prefix"]      = m_custom_tx_explorer;
        } else {
            result["address_explorer_url_prefix"] = "https://blockchair.com/dogecoin/address/";
            result["block_explorer_url_prefix"]   = "https://blockchair.com/dogecoin/block/";
            result["tx_explorer_url_prefix"]      = "https://blockchair.com/dogecoin/transaction/";
        }
        break;
    }

    // Expose explorer state so dashboard JS can link to internal explorer
    result["explorer_enabled"] = m_explorer_enabled;
    if (m_explorer_enabled && !m_explorer_url.empty())
        result["explorer_url"] = m_explorer_url;

    return result;
}

nlohmann::json MiningInterface::rest_payout_addr()
{
    return m_payout_address;
}

nlohmann::json MiningInterface::rest_payout_addrs()
{
    // p2pool: returns the node operator's address(es) so the dashboard
    // can look them up in /current_payouts and display operator earnings.
    // The probabilistic fee replacement puts shares under this address.
    nlohmann::json arr = nlohmann::json::array();
    if (!m_payout_address.empty())
        arr.push_back(m_payout_address);
    if (!m_node_fee_address.empty() && m_node_fee_address != m_payout_address)
        arr.push_back(m_node_fee_address);
    return arr;
}

nlohmann::json MiningInterface::rest_web_best_share_hash()
{
    if (m_best_share_hash_fn) {
        uint256 h = m_best_share_hash_fn();
        return h.GetHex();
    }
    return "0000000000000000000000000000000000000000000000000000000000000000";
}

// ── Log endpoints (read directly from debug.log) ───────────────────────

static std::string tail_file(const std::filesystem::path& path, size_t max_lines)
{
    std::ifstream f(path, std::ios::ate);
    if (!f.is_open()) return {};

    const auto size = f.tellg();
    if (size <= 0) return {};

    // Scan backwards for newlines
    std::string result;
    size_t lines = 0;
    std::streamoff pos = size;
    while (pos > 0 && lines <= max_lines) {
        --pos;
        f.seekg(pos);
        char c;
        f.get(c);
        if (c == '\n' && pos + 1 < size)
            ++lines;
    }
    if (pos > 0) {
        // skip the newline we're on
        f.seekg(pos + 1);
    } else {
        f.seekg(0);
    }
    result.resize(static_cast<size_t>(size - f.tellg()));
    f.read(result.data(), static_cast<std::streamsize>(result.size()));
    return result;
}

std::string MiningInterface::rest_web_log()
{
    auto path = core::filesystem::config_path() / "debug.log";
    return tail_file(path, 500);
}

std::string MiningInterface::rest_logs_export(const std::string& scope,
                                               int64_t /*from_ts*/, int64_t /*to_ts*/,
                                               const std::string& format)
{
    // Read all lines, optionally filter by scope keyword
    auto path = core::filesystem::config_path() / "debug.log";
    std::ifstream f(path);
    if (!f.is_open()) return "# log file not found\n";

    std::string out;
    std::string line;
    while (std::getline(f, line)) {
        // Scope filter: if scope is "node","stratum","security" etc, check if keyword appears
        if (!scope.empty() && scope != "all") {
            std::string upper_scope = scope;
            for (auto& c : upper_scope) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (line.find(upper_scope) == std::string::npos &&
                line.find(scope) == std::string::npos)
                continue;
        }
        if (format == "csv") {
            out += "0," + scope + "," + line + '\n';
        } else if (format == "jsonl") {
            nlohmann::json j;
            j["ts"] = 0;
            j["scope"] = scope;
            j["line"] = line;
            out += j.dump() + '\n';
        } else {
            out += line + '\n';
        }
    }
    return out;
}

// address_to_script is in address_utils.hpp (included via web_server.hpp)

// ──────────── Additional p2pool-compatible REST endpoints ────────────────

nlohmann::json MiningInterface::rest_rate()
{
    double rate = 0.0;
    if (m_node) {
        auto hs = m_node->get_hashrate_stats();
        if (hs.contains("global_hashrate"))
            rate = hs["global_hashrate"];
    }
    return rate;
}

nlohmann::json MiningInterface::rest_difficulty()
{
    double diff = m_network_difficulty.load(std::memory_order_relaxed);
    if (diff <= 0.0) {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null() && m_cached_template.contains("difficulty"))
            diff = m_cached_template["difficulty"].get<double>();
    }
    return diff;
}

nlohmann::json MiningInterface::rest_user_stales()
{
    // Map of address → stale proportion
    return nlohmann::json::object();
}

std::string MiningInterface::rest_peer_addresses()
{
    std::string result;
    if (m_peer_info_fn) {
        auto peers = m_peer_info_fn();
        for (const auto& p : peers) {
            if (!result.empty()) result += ' ';
            result += p.value("address", "");
        }
    }
    return result;
}

nlohmann::json MiningInterface::rest_peer_versions()
{
    nlohmann::json result = nlohmann::json::object();
    if (m_peer_info_fn) {
        auto peers = m_peer_info_fn();
        for (const auto& p : peers)
            result[p.value("address", "")] = p.value("version", "unknown");
    }
    return result;
}

nlohmann::json MiningInterface::rest_peer_txpool_sizes()
{
    nlohmann::json result = nlohmann::json::object();
    if (m_peer_info_fn) {
        auto peers = m_peer_info_fn();
        for (const auto& p : peers)
            result[p.value("address", "")] = p.value("txpool_size", 0);
    }
    return result;
}

nlohmann::json MiningInterface::rest_peer_list()
{
    if (m_peer_info_fn)
        return m_peer_info_fn();
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_pings()
{
    nlohmann::json result = nlohmann::json::object();
    if (m_peer_info_fn) {
        auto peers = m_peer_info_fn();
        for (const auto& p : peers)
            result[p.value("address", "")] = p.value("ping_ms", 0.0);
    }
    return result;
}

nlohmann::json MiningInterface::rest_stale_rates()
{
    nlohmann::json result = nlohmann::json::object();
    result["good"] = 0.0;
    result["orphan"] = 0.0;
    result["dead"] = 0.0;
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        uint64_t total = sc.value("total_shares", uint64_t(0));
        if (total > 0) {
            // If stale counts available, compute proportions
            uint64_t orphan = sc.value("orphan_shares", uint64_t(0));
            uint64_t dead = sc.value("dead_shares", uint64_t(0));
            uint64_t good = total - orphan - dead;
            result["good"] = static_cast<double>(good) / static_cast<double>(total);
            result["orphan"] = static_cast<double>(orphan) / static_cast<double>(total);
            result["dead"] = static_cast<double>(dead) / static_cast<double>(total);
        }
    }
    return result;
}

nlohmann::json MiningInterface::rest_node_info()
{
    nlohmann::json result = nlohmann::json::object();
    result["external_ip"] = m_external_ip.empty() ? "0.0.0.0" : m_external_ip;
    result["worker_port"] = m_worker_port;
    result["p2p_port"] = m_p2p_port;

    switch (m_blockchain) {
    case Blockchain::LITECOIN:
        result["network"] = m_testnet ? "litecoin_testnet" : "litecoin";
        result["symbol"] = "LTC";
        break;
    case Blockchain::BITCOIN:
        result["network"] = m_testnet ? "bitcoin_testnet" : "bitcoin";
        result["symbol"] = "BTC";
        break;
    case Blockchain::DOGECOIN:
        result["network"] = m_testnet ? "dogecoin_testnet" : "dogecoin";
        result["symbol"] = "DOGE";
        break;
    }
    return result;
}

nlohmann::json MiningInterface::rest_luck_stats()
{
    nlohmann::json result = nlohmann::json::object();
    std::lock_guard<std::mutex> lock(m_blocks_mutex);
    result["luck_available"] = !m_found_blocks.empty();

    nlohmann::json blocks = nlohmann::json::array();
    for (const auto& b : m_found_blocks) {
        blocks.push_back({{"ts", b.ts}, {"hash", b.hash}, {"luck", b.luck}});
    }
    result["blocks"] = blocks;

    // Current round luck: expected_time / time_since_last_block * 100
    // Matches p2pool: shows how the ongoing round compares to expectation
    nlohmann::json current_luck_val = nullptr;
    if (!m_found_blocks.empty()) {
        auto now_ts = static_cast<double>(std::time(nullptr));
        double time_since_last = now_ts - static_cast<double>(m_found_blocks.front().ts);

        // Get LIVE pool hashrate and network difficulty
        double pool_hr = m_pool_hashrate_fn ? m_pool_hashrate_fn() : 0;
        double net_diff = m_network_difficulty.load(std::memory_order_relaxed);

        double expected = 0;
        if (net_diff > 0 && pool_hr > 0)
            expected = net_diff * 4294967296.0 / pool_hr;

        if (expected > 0 && time_since_last > 1)
            current_luck_val = (expected / time_since_last) * 100.0;
    }
    result["current_luck_trend"] = current_luck_val;
    return result;
}

nlohmann::json MiningInterface::rest_ban_stats()
{
    nlohmann::json result = nlohmann::json::object();
    std::lock_guard<std::mutex> lock(m_control_mutex);
    result["total_banned"] = static_cast<uint64_t>(m_banned_targets.size());
    nlohmann::json banned = nlohmann::json::array();
    for (const auto& t : m_banned_targets)
        banned.push_back(t);
    result["banned_targets"] = banned;
    return result;
}

nlohmann::json MiningInterface::rest_stratum_security()
{
    // Stub — DDoS detection/security metrics placeholder
    nlohmann::json result = nlohmann::json::object();
    result["connections_per_second"] = 0.0;
    result["potential_ddos"] = false;
    result["blacklisted_ips"] = nlohmann::json::array();
    return result;
}

nlohmann::json MiningInterface::rest_miner_stats(const std::string& address)
{
    nlohmann::json result = nlohmann::json::object();
    result["address"] = address;

    // Aggregate from stratum workers matching this address
    double total_hr = 0, dead_hr = 0, diff = 0;
    uint64_t accepted = 0, rejected = 0, stale = 0;
    bool found = false;
    {
        auto workers = get_stratum_workers();
        for (const auto& [sid, w] : workers) {
            // Match base address (strip worker suffix)
            std::string base = w.username;
            auto dot = base.find('.');
            if (dot != std::string::npos) base = base.substr(0, dot);
            if (base == address) {
                total_hr += w.hashrate;
                dead_hr += w.dead_hashrate;
                diff = w.difficulty;  // last seen difficulty
                accepted += w.accepted;
                rejected += w.rejected;
                stale += w.stale;
                found = true;
            }
        }
    }

    result["active"] = found;
    result["hashrate"] = total_hr;
    result["estimated_hashrate"] = false;
    result["dead_hashrate"] = dead_hr;
    result["doa_rate"] = (accepted + stale > 0) ? static_cast<double>(stale) / (accepted + stale) : 0.0;
    result["share_difficulty"] = diff;
    result["time_to_share"] = (total_hr > 0 && diff > 0) ? (diff * 4294967296.0 / total_hr) : 0.0;
    result["current_payout"] = 0.0;
    result["merged_payouts"] = nlohmann::json::array();

    // Global stale proportion
    double global_stale_prop = 0.0;
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        uint64_t total_shares = sc.value("total_shares", uint64_t(0));
        uint64_t orphan_shares = sc.value("orphan_shares", uint64_t(0));
        uint64_t dead_shares = sc.value("dead_shares", uint64_t(0));
        if (total_shares > 0)
            global_stale_prop = static_cast<double>(orphan_shares + dead_shares) / total_shares;
    }
    result["global_stale_prop"] = global_stale_prop;

    // Best difficulty data
    {
        std::lock_guard<std::mutex> lock(m_best_diff_mutex);
        result["best_difficulty_all_time"] = m_best_difficulty.all_time;
        result["best_difficulty_session"] = m_best_difficulty.session;
        result["best_difficulty_round"] = m_best_difficulty.round;
    }

    result["hashrate_periods"] = {
        {"1m", {{"hashrate", total_hr}, {"dead_hashrate", dead_hr}}},
        {"10m", {{"hashrate", total_hr}, {"dead_hashrate", dead_hr}}},
        {"1h", {{"hashrate", total_hr}, {"dead_hashrate", dead_hr}}}
    };

    // Try to get current payout from PPLNS
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            auto script = address_to_script(address);
            if (!script.empty()) {
                for (const auto& [scr, amt] : outputs) {
                    if (scr == script) {
                        result["current_payout"] = static_cast<double>(amt) / 1e8;
                        result["active"] = true;
                        break;
                    }
                }
            }
        }
    }

    // Network difficulty
    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    result["network_difficulty"] = net_diff;
    result["chance_to_find_block"] = (net_diff > 0 && total_hr > 0)
        ? (total_hr / (net_diff * 4294967296.0) * 100.0) : 0.0;
    result["total_shares"] = accepted + stale;
    result["unstale_shares"] = accepted;
    result["dead_shares"] = stale;
    result["orphan_shares"] = 0;
    result["doa_shares"] = stale;

    return result;
}

nlohmann::json MiningInterface::rest_best_share()
{
    nlohmann::json result = nlohmann::json::object();

    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    result["network_difficulty"] = net_diff;

    {
        std::lock_guard<std::mutex> lock(m_best_diff_mutex);
        auto now_ts = static_cast<uint64_t>(std::time(nullptr));

        // If no local best share, use sharechain average difficulty as baseline
        double best_all = m_best_difficulty.all_time;
        double best_sess = m_best_difficulty.session;
        double best_round = m_best_difficulty.round;
        if (best_all == 0.0 && m_sharechain_stats_fn) {
            auto sc = m_sharechain_stats_fn();
            double avg = sc.value("average_difficulty", 0.0);
            best_all = avg;
            best_sess = avg;
            best_round = avg;
        }

        auto make_entry = [&](double diff, const std::string& miner, uint64_t ts) {
            nlohmann::json e;
            e["difficulty"] = diff;
            e["pct_of_block"] = (net_diff > 0) ? (diff / net_diff * 100.0) : 0.0;
            e["miner"] = miner;
            e["timestamp"] = ts;
            return e;
        };

        result["all_time"] = make_entry(best_all,
            m_best_difficulty.all_time_miner, m_best_difficulty.all_time_ts);
        auto session = make_entry(best_sess,
            m_best_difficulty.session_miner, m_best_difficulty.session_ts);
        session["started"] = m_start_time.time_since_epoch().count() / 1000000000ULL;
        result["session"] = session;
        auto round = make_entry(best_round,
            m_best_difficulty.miner, m_best_difficulty.timestamp);
        round["started"] = m_best_difficulty.round_start;
        result["round"] = round;
    }

    // ── Merged chain (DOGE) best share stats ──
    double merged_net_diff = 0.0;
    std::string merged_symbol = "DOGE";
    if (m_mm_manager && m_mm_manager->has_chains()) {
        auto chain_infos = m_mm_manager->get_chain_infos();
        if (!chain_infos.empty()) {
            merged_net_diff = chain_infos.front().difficulty;
            if (!chain_infos.front().symbol.empty())
                merged_symbol = chain_infos.front().symbol;
        }
    }

    if (merged_net_diff > 0 || m_best_difficulty.merged_all_time > 0) {
        std::lock_guard<std::mutex> lock(m_best_diff_mutex);
        auto pct = [](double d, double nd) { return nd > 0 ? d / nd * 100.0 : 0.0; };
        result["merged"] = {
            {"network_difficulty", merged_net_diff},
            {"symbol", merged_symbol},
            {"all_time", {
                {"difficulty", m_best_difficulty.merged_all_time},
                {"pct_of_block", pct(m_best_difficulty.merged_all_time, merged_net_diff)},
                {"miner", m_best_difficulty.merged_all_time_miner},
                {"timestamp", m_best_difficulty.merged_all_time_ts}
            }},
            {"round", {
                {"difficulty", m_best_difficulty.merged_round},
                {"pct_of_block", pct(m_best_difficulty.merged_round, merged_net_diff)},
                {"miner", m_best_difficulty.merged_round_miner},
                {"timestamp", m_best_difficulty.merged_round_ts},
                {"started", m_best_difficulty.merged_round_start}
            }}
        };
        // Merged median (same share difficulties, different network target)
        if (m_sharechain_stats_fn) {
            auto sc = m_sharechain_stats_fn();
            double avg = sc.value("average_difficulty", 0.0);
            if (avg > 0 && merged_net_diff > 0)
                result["median_merged_pct"] = avg / merged_net_diff * 100.0;
        }
    }

    // ── Median share % (approximate from average difficulty in skiplist) ──
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        double avg = sc.value("average_difficulty", 0.0);
        if (avg > 0 && net_diff > 0)
            result["median_pct"] = avg / net_diff * 100.0;
        else
            result["median_pct"] = 0.0;
    } else {
        result["median_pct"] = 0.0;
    }

    return result;
}

nlohmann::json MiningInterface::rest_miner_payouts(const std::string& address)
{
    nlohmann::json result = nlohmann::json::object();
    result["address"] = address;
    result["current_payout"] = 0.0;
    result["blocks_found"] = 0;
    result["total_estimated_rewards"] = 0.0;
    result["confirmed_rewards"] = 0.0;
    result["maturing_rewards"] = 0.0;
    result["blocks"] = nlohmann::json::array();

    // Get current payout from PPLNS
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            auto script = address_to_script(address);
            if (!script.empty()) {
                for (const auto& [scr, amt] : outputs) {
                    if (scr == script) {
                        result["current_payout"] = static_cast<double>(amt) / 1e8;
                        break;
                    }
                }
            }
        }
    }

    // Populate from found blocks history
    {
        std::lock_guard<std::mutex> lock(m_blocks_mutex);
        static const char* status_str[] = {"pending", "confirmed", "orphaned", "stale"};
        nlohmann::json blocks_arr = nlohmann::json::array();
        int blocks_found = 0;
        double confirmed_rewards = 0, maturing_rewards = 0;
        // Block explorer URL prefix — use custom if set, else Blockchair
        std::string explorer_prefix;
        if (!m_custom_block_explorer.empty()) {
            explorer_prefix = m_custom_block_explorer;
        } else {
            bool is_ltc = (m_blockchain == Blockchain::LITECOIN);
            explorer_prefix = is_ltc
                ? (m_testnet ? "https://blockchair.com/litecoin/testnet/block/" : "https://blockchair.com/litecoin/block/")
                : "https://blockchair.com/bitcoin/block/";
        }

        for (const auto& b : m_found_blocks) {
            if (b.miner == address || address.empty()) {
                ++blocks_found;
                double payout_estimate = b.subsidy > 0 ? static_cast<double>(b.subsidy) / 1e8 : 0;
                if (b.status == BlockStatus::confirmed)
                    confirmed_rewards += payout_estimate;
                else if (b.status == BlockStatus::pending)
                    maturing_rewards += payout_estimate;

                if (blocks_arr.size() < 20) {
                    blocks_arr.push_back({
                        {"timestamp", b.ts},
                        {"block_height", b.height},
                        {"block_hash", b.hash},
                        {"block_reward", payout_estimate},
                        {"explorer_url", explorer_prefix + b.hash},
                        {"status", status_str[static_cast<int>(b.status)]},
                        {"estimated_payout", payout_estimate},
                        {"confirmations", b.confirmations},
                        {"confirmations_required", 100}
                    });
                }
            }
        }
        result["blocks_found"] = blocks_found;
        result["total_estimated_rewards"] = confirmed_rewards + maturing_rewards;
        result["confirmed_rewards"] = confirmed_rewards;
        result["maturing_rewards"] = maturing_rewards;
        result["blocks"] = blocks_arr;
    }
    return result;
}

nlohmann::json MiningInterface::rest_version_signaling(const nlohmann::json* cached_sc)
{
    // Matches p2pool's get_version_signaling() — all fields the dashboard JS expects.
    constexpr int TARGET_VERSION = 36;
    const std::map<int, std::string> share_type_names = {
        {17, "Share"}, {32, "PreSegwitShare"}, {33, "NewShare"},
        {34, "SegwitMiningShare"}, {35, "PaddingBugfixShare"}, {36, "MergedMiningShare"}
    };

    nlohmann::json result = nlohmann::json::object();

    // Use pre-computed sharechain stats if provided
    nlohmann::json sc;
    if (cached_sc && !cached_sc->is_null())
        sc = *cached_sc;
    else if (m_sharechain_stats_fn)
        sc = m_sharechain_stats_fn();

    if (sc.is_null()) return result;

    int chain_height = sc.value("chain_height", 0);
    int chain_length = sc.value("chain_length", 8640);
    int overall_total = sc.value("total_shares", 0);

    if (overall_total < 10) return result;

    // ── Share type counts (format VERSION) ──
    int overall_v36_shares = 0;
    int current_share_type = 0;
    nlohmann::json share_types_json = nlohmann::json::object();
    if (sc.contains("shares_by_version") && sc["shares_by_version"].is_object()) {
        auto& sv = sc["shares_by_version"];
        for (auto& [ver, count] : sv.items()) {
            int v = std::stoi(ver);
            int c = count.get<int>();
            auto it = share_type_names.find(v);
            std::string name = (it != share_type_names.end()) ? it->second : "V" + ver;
            double pct = overall_total > 0 ? (c * 100.0 / overall_total) : 0;
            share_types_json[ver] = {{"name", name}, {"count", c}, {"percentage", pct}};
            if (v >= TARGET_VERSION) overall_v36_shares += c;
            if (v > current_share_type) current_share_type = v;
        }
    }

    // ── Desired version counts (voting — full chain) ──
    int overall_v36_votes = 0;
    nlohmann::json full_chain_versions = nlohmann::json::object();
    nlohmann::json versions_json = nlohmann::json::object();  // populated below from sampling window
    if (sc.contains("shares_by_desired_version") && sc["shares_by_desired_version"].is_object()) {
        auto& dv = sc["shares_by_desired_version"];
        for (auto& [ver, count] : dv.items()) {
            int v = std::stoi(ver);
            int c = count.get<int>();
            double pct = overall_total > 0 ? (c * 100.0 / overall_total) : 0;
            full_chain_versions[ver] = {{"count", c}, {"percentage", pct}};
            if (v >= TARGET_VERSION) overall_v36_votes += c;
        }
    }

    double overall_v36_vote_pct = overall_total > 0 ? (overall_v36_votes * 100.0 / overall_total) : 0;
    double overall_v36_share_pct = overall_total > 0 ? (overall_v36_shares * 100.0 / overall_total) : 0;

    // ── Chain maturity ──
    double chain_maturity = chain_length > 0 ? std::min(chain_height / static_cast<double>(chain_length), 1.0) * 100.0 : 0;
    bool chain_ready = chain_height >= chain_length;

    // ── Current share name ──
    auto cit = share_type_names.find(current_share_type);
    std::string current_share_name = (cit != share_type_names.end()) ? cit->second : "V" + std::to_string(current_share_type);

    // ── Target version: successor if V35 has one (V36), else dominant vote ──
    int target_version = TARGET_VERSION;  // V35's successor is V36
    auto tit = share_type_names.find(target_version);
    std::string target_version_name = (tit != share_type_names.end()) ? tit->second : "V" + std::to_string(target_version);

    // ── Transition detection ──
    bool successor_transition = (current_share_type < TARGET_VERSION);  // V35 → V36
    bool classic_transition = false;  // dominant vote differs from current
    bool is_transitioning = classic_transition || successor_transition;

    // ── show_transition: golden border ──
    bool all_target = (overall_total > 0 && overall_v36_shares == overall_total);
    bool confirmed = all_target && chain_height >= chain_length * 3;
    bool show_transition = (is_transitioning || !confirmed) && !confirmed && !all_target;

    // ── Sampling window signaling (CHAIN_LENGTH/10 shares from tip, work-weighted like p2pool) ──
    int sampling_window_size = chain_length / 10;
    double sampling_v36_weight = 0;
    double sampling_total_weight = 0;
    if (sc.contains("sampling_desired_version") && sc["sampling_desired_version"].is_object()) {
        versions_json = nlohmann::json::object();
        for (auto& [ver, weight] : sc["sampling_desired_version"].items()) {
            int v = std::stoi(ver);
            double w = weight.get<double>();
            sampling_total_weight += w;
            if (v >= TARGET_VERSION) sampling_v36_weight += w;
        }
        // Build versions_json with percentages from work weights
        for (auto& [ver, weight] : sc["sampling_desired_version"].items()) {
            double w = weight.get<double>();
            double pct = sampling_total_weight > 0 ? (w * 100.0 / sampling_total_weight) : 0;
            versions_json[ver] = {{"weight", w}, {"percentage", pct}};
        }
    }
    double sampling_signaling = sampling_total_weight > 0
        ? (sampling_v36_weight * 100.0 / sampling_total_weight) : 0;

    // ── Propagation depth (needed for status logic) ──
    int deepest_v36_pos = sc.value("deepest_v36_position", 0);

    // ── Status and message (matching p2pool phases) ──
    std::string status, message;
    double transition_progress = 0;

    if (!is_transitioning && all_target) {
        status = "no_transition";
        message = "No version transition in progress";
        transition_progress = 100;
    } else if (!chain_ready) {
        status = "building_chain";
        int remaining = chain_length - chain_height;
        message = "Building chain: " + std::to_string(chain_height) + "/" +
                  std::to_string(chain_length) + " shares (need " +
                  std::to_string(remaining) + " more before upgrade checks activate)";
        transition_progress = chain_maturity;
    } else if (sampling_signaling >= 95) {
        status = "activating";
        char buf[128];
        snprintf(buf, sizeof(buf), "V%d activation threshold reached! %.1f%% in sampling window — switchover imminent",
                 target_version, sampling_signaling);
        message = buf;
        transition_progress = 100;
    } else if (sampling_signaling >= 60) {
        status = "signaling_strong";
        char buf[128];
        snprintf(buf, sizeof(buf), "Strong V%d signaling — activation approaching (need 95%%)", target_version);
        message = buf;
        transition_progress = sampling_signaling;
    } else if (sampling_signaling > 0) {
        // Votes present in sampling window but below 60%
        status = "signaling";
        char buf[256];
        snprintf(buf, sizeof(buf), "Network is signaling for V%d upgrade", target_version);
        message = buf;
        transition_progress = sampling_signaling;
    } else if (overall_v36_votes > 0 && deepest_v36_pos < chain_length) {
        // V36 votes exist but haven't reached the sampling window yet
        status = "propagating";
        int shares_to = std::max(0, chain_length - deepest_v36_pos);
        int eta_sec = shares_to * 10;  // SHARE_PERIOD = 10s for LTC
        int eta_min = eta_sec / 60;
        int eta_h = eta_min / 60;
        int eta_m = eta_min % 60;
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "V%d votes propagating: %d votes (%.1f%% of chain), deepest at position %d/%d. Reach sampling window in ~%s",
                 target_version, overall_v36_votes, overall_v36_vote_pct,
                 deepest_v36_pos, chain_length,
                 eta_h > 0 ? (std::to_string(eta_h) + "h " + std::to_string(eta_m) + "m").c_str()
                           : (std::to_string(eta_m) + "m").c_str());
        message = buf;
        double prop_pct = chain_length > 0
            ? std::min(deepest_v36_pos * 100.0 / chain_length, 100.0) : 0;
        transition_progress = prop_pct;
    } else if (overall_v36_votes > 0) {
        // V36 votes reached window position but 0% weighted (edge case)
        status = "signaling";
        char buf[256];
        snprintf(buf, sizeof(buf), "V%d votes appearing in sampling window. %d votes (%.1f%%) in chain overall",
                 target_version, overall_v36_votes, overall_v36_vote_pct);
        message = buf;
        transition_progress = overall_v36_vote_pct;
    } else {
        status = "waiting";
        char buf[256];
        snprintf(buf, sizeof(buf), "Waiting for miners to upgrade. No V%d votes in chain yet (0/%d shares)",
                 target_version, overall_total);
        message = buf;
        transition_progress = 0;
    }

    // ── Populate result ──
    result["chain_height"] = chain_height;
    result["chain_length_required"] = chain_length;
    result["chain_ready"] = chain_ready;
    result["chain_maturity"] = std::round(chain_maturity * 100) / 100.0;
    result["lookbehind"] = std::min(chain_height, chain_length / 10);
    result["total_weight"] = overall_total;
    result["sampling_window_size"] = sampling_window_size;
    result["sampling_signaling"] = std::round(sampling_signaling * 100) / 100.0;
    result["share_types"] = share_types_json;
    result["current_share_type"] = current_share_type;
    result["current_share_name"] = current_share_name;
    result["target_version"] = target_version;
    result["target_version_name"] = target_version_name;
    result["versions"] = versions_json;
    result["full_chain_versions"] = full_chain_versions;
    result["overall_v36_votes"] = overall_v36_votes;
    result["overall_v36_vote_pct"] = std::round(overall_v36_vote_pct * 100) / 100.0;
    result["overall_v36_shares"] = overall_v36_shares;
    result["overall_v36_share_pct"] = std::round(overall_v36_share_pct * 100) / 100.0;
    result["overall_total"] = overall_total;
    result["show_transition"] = show_transition;
    result["is_transitioning"] = is_transitioning;
    result["transition_progress"] = std::round(transition_progress * 100) / 100.0;
    result["thresholds"] = {{"accept", 60}, {"activate", 95}};
    result["status"] = status;
    result["message"] = message;

    // ── Propagation tracking (V36 votes aging toward sampling window) ──
    int v36_contiguous = sc.value("v36_contiguous_from_tip", 0);
    int propagation_target = chain_length;  // 8640 for LTC
    double propagation_pct = propagation_target > 0
        ? std::min(deepest_v36_pos * 100.0 / propagation_target, 100.0) : 0;
    int shares_to_window = std::max(0, propagation_target - deepest_v36_pos);
    constexpr int SHARE_PERIOD = 10;  // LTC: 10 seconds per share
    double time_to_window_seconds = shares_to_window * SHARE_PERIOD;
    result["propagation_pct"] = std::round(propagation_pct * 100) / 100.0;
    result["propagation_target"] = propagation_target;
    result["deepest_v36_position"] = deepest_v36_pos;
    result["v36_contiguous_from_tip"] = v36_contiguous;
    result["shares_to_window"] = shares_to_window;
    result["time_to_window_seconds"] = std::round(time_to_window_seconds);
    result["chain_length"] = chain_length;

    // ── Transition message + authority announcements ──
    // First try live messages from best share, then fall back to cached blob files.
    result["transition_message"] = nullptr;
    result["authority_announcements"] = nlohmann::json::array();

    // Try live messages from best share's message_data
    if (m_protocol_messages_fn) {
        try {
            auto pm = m_protocol_messages_fn();
            if (pm.value("decrypted", false) && pm.contains("messages") && pm["messages"].is_array()) {
                auto now = static_cast<uint32_t>(std::time(nullptr));
                nlohmann::json announcements = nlohmann::json::array();
                for (auto& msg : pm["messages"]) {
                    int msg_type = msg.value("type", 0);
                    uint32_t ts = msg.value("timestamp", uint32_t(0));
                    std::string payload_hex = msg.value("payload_hex", "");
                    bool is_authority = msg.value("protocol_authority", false);
                    auto payload_bytes = ParseHex(payload_hex);
                    std::string payload_text(payload_bytes.begin(), payload_bytes.end());
                    nlohmann::json payload_json;
                    try { payload_json = nlohmann::json::parse(payload_text); } catch (...) {}

                    if (msg_type == 0x20 && is_authority && result["transition_message"].is_null()) {
                        nlohmann::json tmsg = {{"timestamp", ts}, {"verified", true}, {"authority", true}};
                        if (payload_json.is_object()) {
                            tmsg["msg"] = payload_json.value("msg", "");
                            tmsg["url"] = payload_json.value("url", "");
                            tmsg["urgency"] = payload_json.value("urg", "info");
                            tmsg["from_ver"] = payload_json.value("from", "");
                            tmsg["to_ver"] = payload_json.value("to", "");
                        } else { tmsg["msg"] = payload_text; tmsg["urgency"] = "info"; }
                        result["transition_message"] = tmsg;
                    } else if (msg_type == 0x03 || msg_type == 0x10) {
                        nlohmann::json ann = {
                            {"type", (msg_type == 0x10) ? "EMERGENCY" : "POOL_ANNOUNCE"},
                            {"type_id", msg_type}, {"timestamp", ts},
                            {"age", (now > ts) ? int(now - ts) : 0},
                            {"verified", true}, {"authority", is_authority}
                        };
                        if (payload_json.is_object()) {
                            ann["text"] = payload_json.value("msg", payload_json.value("text", ""));
                            ann["urgency"] = payload_json.value("urg", "info");
                            ann["url"] = payload_json.value("url", "");
                        } else { ann["text"] = payload_text; ann["urgency"] = (msg_type == 0x10) ? "alert" : "info"; }
                        announcements.push_back(ann);
                    }
                }
                if (!announcements.empty())
                    result["authority_announcements"] = announcements;
            }
        } catch (...) {}
    }

    // Fall back to cached blob files (loaded at startup via load_transition_blobs)
    if (result["transition_message"].is_null() && !m_cached_transition_message.is_null())
        result["transition_message"] = m_cached_transition_message;
    if (result["authority_announcements"].empty() && !m_cached_authority_announcements.empty())
        result["authority_announcements"] = m_cached_authority_announcements;

    // ── Address format warnings (node-generated, matches p2pool) ──
    {
        bool ratchet_confirmed = all_target && confirmed;
        nlohmann::json warnings = nlohmann::json::array();

        if (!ratchet_confirmed && TARGET_VERSION >= 36) {
            warnings.push_back({
                {"id", "v35_addr_limitation"},
                {"urgency", "recommended"},
                {"title", "V35 Address Limitation (Current Phase)"},
                {"text", "During V35 (current share format), shares cannot carry "
                         "explicit merged mining addresses. Even if you configure "
                         "LTC,DOGE in stratum, PPLNS will use ONLY auto-converted "
                         "DOGE addresses derived from your LTC public key hash. "
                         "Explicit address support activates after V36 transition."}
            });
        }

        warnings.push_back({
            {"id", "multiaddr_format"},
            {"urgency", "recommended"},
            {"title", "Multi-Address Mining Format"},
            {"text", "V36 introduces merged mining. To receive rewards on both "
                     "chains, configure your miner's stratum username as: "
                     "LTC_ADDRESS,DOGE_ADDRESS.worker_name  "
                     "Example: ltc1q...abc,D9ab...def.rig1"}
        });

        warnings.push_back({
            {"id", "auto_convert"},
            {"urgency", "info"},
            {"title", "Address Auto-Conversion"},
            {"text", "If you only provide a LTC address, a DOGE address will be "
                     "auto-derived from its public key hash. This derived address "
                     "may NOT match your actual DOGE wallet \u2014 you could lose "
                     "merged mining rewards. Always specify your own DOGE address "
                     "explicitly."}
        });

        warnings.push_back({
            {"id", "invalid_addr_redist"},
            {"urgency", "info"},
            {"title", "Invalid Address Redistribution"},
            {"text", "Miners with invalid or unparseable addresses are handled "
                     "per case: (1) Invalid LTC + no DOGE = both redistributed. "
                     "(2) Invalid LTC + valid DOGE = DOGE preserved, LTC "
                     "reverse-derived from DOGE key (Case 4). "
                     "Redistributed shares go probabilistically to PPLNS miners."}
        });

        result["address_warnings"] = warnings;
    }

    return result;
}

nlohmann::json MiningInterface::rest_v36_status()
{
    nlohmann::json result = nlohmann::json::object();
    result["auto_ratchet"] = {
        {"state", "voting"},
        {"persisted_state", ""},
        {"activated_at", nullptr},
        {"activated_height", nullptr},
        {"confirmed_at", nullptr}
    };
    result["share_chain"] = {
        {"height", 0},
        {"sample_size", 0},
        {"v35_shares", 0},
        {"v36_shares", 0},
        {"v36_percentage", 0.0}
    };
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("chain_height"))
            result["share_chain"]["height"] = sc["chain_height"];
        if (sc.contains("total_shares"))
            result["share_chain"]["sample_size"] = sc["total_shares"];
    }
    return result;
}

nlohmann::json MiningInterface::rest_patron_sendmany(const std::string& total)
{
    // Builds a sendmany JSON string that splits <total> among current miners
    nlohmann::json result = nlohmann::json::object();
    result["note"] = "patron_sendmany stub";
    result["total"] = total;
    result["destinations"] = nlohmann::json::object();
    return result;
}

nlohmann::json MiningInterface::rest_tracker_debug()
{
    nlohmann::json result = nlohmann::json::object();
    if (m_sharechain_stats_fn) {
        result = m_sharechain_stats_fn();
    }
    result["best_share_hash"] = rest_web_best_share_hash();
    return result;
}

// ──────────── Merged mining endpoints ────────────────────────────────────

nlohmann::json MiningInterface::rest_merged_stats()
{
    nlohmann::json result = nlohmann::json::object();
    if (!m_mm_manager || !m_mm_manager->has_chains()) {
        result["total_blocks"] = 0;
        result["networks"] = nlohmann::json::object();
        result["recent"] = nlohmann::json::array();
        return result;
    }

    result["total_blocks"] = m_mm_manager->get_total_blocks();

    // Primary chain block_value + symbol for dashboard card
    auto chain_infos = m_mm_manager->get_chain_infos();
    if (!chain_infos.empty()) {
        const auto& primary = chain_infos.front();
        // block_value in coins (coinbase_value is in satoshis; 1e8 sat/coin)
        result["block_value"] = primary.coinbase_value / 1e8;
        result["symbol"] = primary.symbol;
        result["difficulty"] = primary.difficulty;
    }

    // Per-network stats
    nlohmann::json networks = nlohmann::json::object();
    for (const auto& ci : chain_infos) {
        nlohmann::json net;
        net["chain_id"]       = ci.chain_id;
        net["blocks_found"]   = m_mm_manager->get_chain_block_count(ci.chain_id);
        net["current_height"] = ci.current_height;
        net["current_tip"]    = ci.current_tip;
        net["rpc_host"]       = ci.rpc_host;
        net["rpc_port"]       = ci.rpc_port;
        net["p2p_port"]       = ci.p2p_port;
        net["multiaddress"]   = ci.multiaddress;
        net["block_value"]    = ci.coinbase_value / 1e8;
        net["difficulty"]     = ci.difficulty;
        networks[ci.symbol]   = std::move(net);
    }
    result["networks"] = std::move(networks);

    // Recent blocks (last 20) – field names match dashboard renderMergedBlocks()
    nlohmann::json recent = nlohmann::json::array();
    for (const auto& blk : m_mm_manager->get_recent_blocks(20)) {
        nlohmann::json j;
        j["ts"]          = blk.timestamp;
        j["symbol"]      = blk.symbol;
        j["network"]     = blk.symbol;
        j["chainid"]     = blk.chain_id;
        j["pow_hash"]    = blk.block_hash;
        j["parent_hash"] = blk.parent_hash;
        j["height"]      = blk.height;
        j["miner"]       = nullptr;
        j["verified"]    = blk.accepted ? nlohmann::json(true) : nlohmann::json(nullptr);
        recent.push_back(std::move(j));
    }
    result["recent"] = std::move(recent);

    return result;
}

nlohmann::json MiningInterface::rest_current_merged_payouts()
{
    // Format: { "LTC_ADDRESS": { "amount": 0.123, "merged": [{"symbol":"DOGE","address":"D...","amount":0.456}] } }
    nlohmann::json result = nlohmann::json::object();

    // Get parent chain (LTC) payouts
    auto payouts_json = rest_current_payouts();
    if (!payouts_json.is_object()) return result;

    // Convert current_payouts {addr: amount_float} to merged format
    for (auto& [addr, amount] : payouts_json.items()) {
        result[addr] = {{"amount", amount}, {"merged", nlohmann::json::array()}};
    }

    // Add merged chain payouts via the payout_provider callback
    if (m_mm_manager) {
        auto chain_infos = m_mm_manager->get_chain_infos();
        for (const auto& ci : chain_infos) {
            if (ci.coinbase_value == 0) continue;

            // Use the same payout_provider that build_multiaddress_block uses
            auto merged_payouts = m_mm_manager->get_payouts(ci.chain_id, ci.coinbase_value);
            if (merged_payouts.empty()) continue;

            // DOGE address version bytes (mainnet P2PKH=0x1e, P2SH=0x16)
            uint8_t merged_p2pkh_ver = 0x1e;
            uint8_t merged_p2sh_ver = 0x16;
            // TODO: testnet detection for DOGE address versions

            for (auto& [script, amount] : merged_payouts) {
                // Determine source label (p2pool: auto-convert, donation, explicit)
                std::string source = "auto-convert"; // default for V35 (no explicit merged addrs)
                // Donation: P2PK (ends with OP_CHECKSIG), P2SH matching donation script,
                // or script matching the known donation_script from MiningInterface
                bool is_donation = (script.size() > 33 && script.back() == 0xac); // P2PK
                if (!is_donation && !m_donation_script.empty() && script == m_donation_script)
                    is_donation = true; // matches configured donation script
                if (!is_donation && script.size() == 23 && script[0] == 0xa9) {
                    // Check if P2SH matches combined donation hash (8c6272621d89e8fa...)
                    if (script[2] == 0x8c && script[3] == 0x62 && script[4] == 0x72)
                        is_donation = true;
                }
                if (is_donation) source = "donation";
                // TODO: detect "explicit" when V36 shares carry merged_addresses

                // Convert merged script to proper DOGE address
                std::string merged_addr = script_to_address(script, "", merged_p2pkh_ver, merged_p2sh_ver);
                if (merged_addr.empty()) {
                    if (source == "donation") {
                        merged_addr = "donation";
                    }
                }

                // Extract hash160 from merged script for matching to parent LTC address
                std::string hash160_hex;
                int h160_offset = -1;
                if (script.size() == 25 && script[0] == 0x76) h160_offset = 3; // P2PKH
                else if (script.size() == 23 && script[0] == 0xa9) h160_offset = 2; // P2SH
                else if (script.size() == 22 && script[0] == 0x00) h160_offset = 2; // P2WPKH
                if (h160_offset >= 0) {
                    static const char* HEX = "0123456789abcdef";
                    hash160_hex.reserve(40);
                    for (int i = h160_offset; i < h160_offset + 20; ++i) {
                        hash160_hex += HEX[script[i] >> 4];
                        hash160_hex += HEX[script[i] & 0x0f];
                    }
                }

                // Find parent LTC address with same hash160
                bool attached = false;
                if (!hash160_hex.empty()) {
                    for (auto& [parent_addr, entry] : result.items()) {
                        auto ps = address_to_script(parent_addr);
                        int po = (ps.size() == 25) ? 3 : (ps.size() == 22) ? 2 : (ps.size() == 23) ? 2 : -1;
                        if (po >= 0 && po + 20 <= static_cast<int>(ps.size())) {
                            static const char* HEX = "0123456789abcdef";
                            std::string ph;
                            ph.reserve(40);
                            for (int i = po; i < po + 20; ++i) { ph += HEX[ps[i] >> 4]; ph += HEX[ps[i] & 0x0f]; }
                            if (ph == hash160_hex) {
                                entry["merged"].push_back({
                                    {"symbol", ci.symbol},
                                    {"address", merged_addr.empty() ? hash160_hex : merged_addr},
                                    {"amount", amount / 1e8},
                                    {"source", source}
                                });
                                attached = true;
                                break;
                            }
                        }
                    }
                }
                // Donation not matched by hash160 — attach to LTC donation address
                // by name (p2pool web.py:1164). DONATION_SCRIPT (P2PK → LeD2f on mainnet)
                // and COMBINED_DONATION_SCRIPT (P2SH → MLhSm on mainnet) have different
                // hash160 values, so hash160 matching won't find the parent.
                if (!attached && is_donation) {
                    // Use known DOGE donation address (precomputed, same as p2pool)
                    std::string doge_donation_addr = merged_addr;
                    if (doge_donation_addr.empty() || doge_donation_addr == "donation")
                        doge_donation_addr = ltc::PoolConfig::is_testnet
                            ? "2N63WXLw22FXFdLBNqWZLsDX7WQJTPXus7f"   // COMBINED_DONATION_DOGE_TESTNET
                            : "A5EZCT4tUrtoKuvJaWbtVQADzdUKdtsqpr";  // COMBINED_DONATION_DOGE_MAINNET

                    // Find LTC donation address: try known prefixes
                    std::string ltc_donation_key;
                    for (auto& [parent_addr, entry] : result.items()) {
                        // Pre-V36: LeD2fnn... (hash160 of DONATION_SCRIPT pubkey)
                        // V36+:    MLhSmVQ... (COMBINED_DONATION_SCRIPT P2SH)
                        if (parent_addr.rfind("LeD2f", 0) == 0 ||
                            parent_addr.rfind("MLhSm", 0) == 0)
                        {
                            ltc_donation_key = parent_addr;
                            break;
                        }
                    }
                    if (!ltc_donation_key.empty()) {
                        result[ltc_donation_key]["merged"].push_back({
                            {"symbol", ci.symbol},
                            {"address", doge_donation_addr},
                            {"amount", amount / 1e8},
                            {"source", "donation"}
                        });
                        attached = true;
                    }
                }
                if (!attached && amount > 0) {
                    std::string key = merged_addr.empty() ? (hash160_hex.empty() ? "unknown" : hash160_hex) : merged_addr;
                    if (!result.contains(key))
                        result[key] = {{"amount", 0.0}, {"merged", nlohmann::json::array()}};
                    result[key]["merged"].push_back({
                        {"symbol", ci.symbol},
                        {"address", key},
                        {"amount", amount / 1e8},
                        {"source", source}
                    });
                }
            }
        }
    }

    // Filter out entries with 0 LTC and no merged payouts
    nlohmann::json filtered = nlohmann::json::object();
    for (auto& [key, entry] : result.items()) {
        double ltc_amount = entry.value("amount", 0.0);
        auto& merged = entry["merged"];
        bool has_merged = merged.is_array() && !merged.empty();
        if (ltc_amount < 0.000001 && !has_merged) continue;
        // Filter out overflow merged entries (< 0.01 DOGE or > 1B — clearly wrong)
        if (has_merged) {
            nlohmann::json good = nlohmann::json::array();
            for (auto& m : merged) {
                double amt = m.value("amount", 0.0);
                if (amt >= 0.01 && amt < 1e9)
                    good.push_back(m);
            }
            entry["merged"] = good;
            if (ltc_amount < 0.000001 && good.empty()) continue;
        }
        filtered[key] = entry;
    }
    return filtered;
}

nlohmann::json MiningInterface::rest_recent_merged_blocks()
{
    nlohmann::json arr = nlohmann::json::array();
    if (!m_mm_manager) return arr;

    for (const auto& blk : m_mm_manager->get_recent_blocks(50)) {
        nlohmann::json j;
        // Field names match dashboard.html renderMergedBlocks() expectations
        j["ts"]          = blk.timestamp;
        j["symbol"]      = blk.symbol;
        j["network"]     = blk.symbol;
        j["chainid"]     = blk.chain_id;
        j["pow_hash"]    = blk.block_hash;
        j["parent_hash"] = blk.parent_hash;
        j["height"]      = blk.height;
        j["miner"]       = blk.miner.empty() ? nlohmann::json(nullptr) : nlohmann::json(blk.miner);
        j["verified"]    = blk.accepted ? nlohmann::json(true) : nlohmann::json(nullptr);
        arr.push_back(std::move(j));
    }
    return arr;
}

nlohmann::json MiningInterface::rest_all_merged_blocks()
{
    nlohmann::json arr = nlohmann::json::array();
    if (!m_mm_manager) return arr;

    for (const auto& blk : m_mm_manager->get_discovered_blocks()) {
        nlohmann::json j;
        j["ts"]          = blk.timestamp;
        j["symbol"]      = blk.symbol;
        j["chainid"]     = blk.chain_id;
        j["pow_hash"]    = blk.block_hash;
        j["parent_hash"] = blk.parent_hash;
        j["height"]      = blk.height;
        j["miner"]       = nullptr;
        j["verified"]    = blk.accepted ? nlohmann::json(true) : nlohmann::json(nullptr);
        arr.push_back(std::move(j));
    }
    return arr;
}

nlohmann::json MiningInterface::rest_discovered_merged_blocks()
{
    // Field names match dashboard.html renderDiscoveredMerged() expectations
    nlohmann::json arr = nlohmann::json::array();
    if (!m_mm_manager) return arr;

    for (const auto& blk : m_mm_manager->get_discovered_blocks()) {
        nlohmann::json j;
        j["ts"]               = blk.timestamp;
        j["number"]           = blk.parent_height > 0 ? nlohmann::json(blk.parent_height) : nlohmann::json(nullptr);
        j["hash"]             = blk.parent_hash;
        j["aux_block_height"] = blk.height;
        j["aux_hash"]         = blk.block_hash;
        j["aux_symbol"]       = blk.symbol;
        j["aux_reward"]       = blk.coinbase_value > 0 ? nlohmann::json(blk.coinbase_value / 1e8) : nlohmann::json(nullptr);
        j["miner"]            = blk.miner.empty() ? nlohmann::json(nullptr) : nlohmann::json(blk.miner);
        j["peer_addr"]        = blk.is_local ? "local" : "peer";
        j["status"]           = blk.accepted ? "confirmed" : "orphaned";
        arr.push_back(std::move(j));
    }
    return arr;
}

nlohmann::json MiningInterface::rest_broadcaster_status()
{
    nlohmann::json result = nlohmann::json::object();
    if (!m_mm_manager || !m_mm_manager->has_chains()) {
        result["running"] = false;
        result["last_broadcast"] = nullptr;
        return result;
    }
    result["running"] = true;
    result["enabled"] = true;
    result["chains"] = m_mm_manager->chain_count();
    result["total_blocks_found"] = m_mm_manager->get_total_blocks();
    // LTC P2P peer info
    if (m_ltc_peer_info_fn)
        result["peers"] = m_ltc_peer_info_fn();
    return result;
}

nlohmann::json MiningInterface::rest_merged_broadcaster_status()
{
    nlohmann::json result = nlohmann::json::object();
    if (!m_mm_manager || !m_mm_manager->has_chains()) {
        result["running"] = false;
        result["last_broadcast"] = nullptr;
        result["chains"] = nlohmann::json::object();
        return result;
    }

    result["running"] = true;

    nlohmann::json chains = nlohmann::json::object();
    for (const auto& ci : m_mm_manager->get_chain_infos()) {
        nlohmann::json ch;
        ch["chain_id"]       = ci.chain_id;
        ch["current_height"] = ci.current_height;
        ch["current_tip"]    = ci.current_tip;
        ch["p2p_port"]       = ci.p2p_port;
        ch["blocks_found"]   = m_mm_manager->get_chain_block_count(ci.chain_id);
        chains[ci.symbol]    = std::move(ch);
    }
    result["chains"] = std::move(chains);

    // DOGE P2P peer info
    if (m_doge_peer_info_fn)
        result["peers"] = m_doge_peer_info_fn();

    return result;
}

void MiningInterface::add_netdiff_sample(double difficulty, const std::string& source)
{
    if (difficulty <= 0) return;
    // Skip if unchanged from last sample (dedup same-block updates)
    if (difficulty == m_last_netdiff_sampled && source == "periodic") return;
    m_last_netdiff_sampled = difficulty;

    std::lock_guard<std::mutex> lock(m_netdiff_mutex);
    double now = static_cast<double>(std::time(nullptr));
    m_netdiff_history.push_back({now, difficulty, source});
    // Cap at 2000 samples (oldest first)
    while (m_netdiff_history.size() > 2000)
        m_netdiff_history.erase(m_netdiff_history.begin());
}

nlohmann::json MiningInterface::rest_network_difficulty()
{
    nlohmann::json arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(m_netdiff_mutex);
        for (const auto& s : m_netdiff_history)
            arr.push_back({{"ts", s.ts}, {"network_diff", s.difficulty}, {"source", s.source}});
    }
    // If empty, at least return current
    if (arr.empty()) {
        double diff = m_network_difficulty.load(std::memory_order_relaxed);
        arr.push_back({
            {"ts", static_cast<double>(std::time(nullptr))},
            {"network_diff", diff},
            {"source", "current"}
        });
    }
    return arr;
}

// ──────────── Stratum worker session tracking ───────────────────────────

void MiningInterface::register_stratum_worker(const std::string& session_id, const WorkerInfo& info)
{
    std::lock_guard<std::mutex> lock(m_stratum_workers_mutex);
    m_stratum_workers[session_id] = info;
}

void MiningInterface::unregister_stratum_worker(const std::string& session_id)
{
    std::lock_guard<std::mutex> lock(m_stratum_workers_mutex);
    m_stratum_workers.erase(session_id);
}

void MiningInterface::update_stratum_worker(const std::string& session_id,
                                             double hashrate, double dead_hashrate, double difficulty,
                                             uint64_t accepted, uint64_t rejected, uint64_t stale)
{
    std::lock_guard<std::mutex> lock(m_stratum_workers_mutex);
    auto it = m_stratum_workers.find(session_id);
    if (it != m_stratum_workers.end()) {
        it->second.hashrate = hashrate;
        it->second.dead_hashrate = dead_hashrate;
        it->second.difficulty = difficulty;
        it->second.accepted = accepted;
        it->second.rejected = rejected;
        it->second.stale = stale;
    }
}

std::map<std::string, MiningInterface::WorkerInfo> MiningInterface::get_stratum_workers() const
{
    std::lock_guard<std::mutex> lock(m_stratum_workers_mutex);
    return m_stratum_workers;
}

// ──────────── /web/ sub-endpoints (share chain inspection) ───────────────

nlohmann::json MiningInterface::rest_web_heads()
{
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("heads"))
            return sc["heads"];
    }
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_web_verified_heads()
{
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("verified_heads"))
            return sc["verified_heads"];
    }
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_web_tails()
{
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("tails"))
            return sc["tails"];
    }
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_web_verified_tails()
{
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("verified_tails"))
            return sc["verified_tails"];
    }
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_web_my_share_hashes()
{
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        if (sc.contains("my_share_hashes"))
            return sc["my_share_hashes"];
    }
    return nlohmann::json::array();
}

nlohmann::json MiningInterface::rest_web_my_share_hashes50()
{
    auto all = rest_web_my_share_hashes();
    if (all.is_array() && all.size() > 50) {
        nlohmann::json trimmed = nlohmann::json::array();
        for (size_t i = 0; i < 50; ++i)
            trimmed.push_back(all[i]);
        return trimmed;
    }
    return all;
}

nlohmann::json MiningInterface::rest_web_share(const std::string& hash)
{
    // Use dedicated share lookup if wired
    if (m_share_lookup_fn) {
        auto result = m_share_lookup_fn(hash);
        if (!result.is_null() && !result.contains("error"))
            return result;
    }
    nlohmann::json result = nlohmann::json::object();
    result["error"] = "share not found";
    result["hash"] = hash;
    return result;
}

nlohmann::json MiningInterface::rest_web_payout_address(const std::string& hash)
{
    auto share = rest_web_share(hash);
    if (share.contains("share_data") && share["share_data"].contains("payout_address"))
        return share["share_data"]["payout_address"];
    return "";
}

nlohmann::json MiningInterface::rest_web_log_json()
{
    std::lock_guard<std::mutex> lock(m_stat_log_mutex);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& entry : m_stat_log) {
        arr.push_back({
            {"time", entry.time},
            {"pool_hash_rate", entry.pool_hash_rate},
            {"pool_stale_prop", entry.pool_stale_prop},
            {"local_hash_rates", entry.local_hash_rates},
            {"shares", entry.shares},
            {"stale_shares", entry.stale_shares},
            {"current_payout", entry.current_payout},
            {"peers", entry.peers},
            {"attempts_to_share", entry.attempts_to_share},
            {"attempts_to_block", entry.attempts_to_block},
            {"block_value", entry.block_value}
        });
    }
    return arr;
}

nlohmann::json MiningInterface::rest_web_graph_data(const std::string& source, const std::string& view)
{
    // Graph data endpoint — returns p2pool-compatible time-series
    // Format: array of [timestamp, value] tuples
    // For pool_rates: [timestamp, {good: X, orphan: Y, null: Z}]
    // For others:     [timestamp, scalar]
    nlohmann::json result = nlohmann::json::array();

    std::lock_guard<std::mutex> lock(m_stat_log_mutex);
    auto now = std::time(nullptr);
    double window = 3600.0; // default: last hour
    if (view == "last_day") window = 86400.0;
    else if (view == "last_week") window = 604800.0;
    else if (view == "last_month") window = 2592000.0;
    else if (view == "last_year") window = 31536000.0;

    for (const auto& entry : m_stat_log) {
        if (entry.time < (now - static_cast<time_t>(window)))
            continue;

        if (source == "pool_rates") {
            // p2pool format: [timestamp, {good, orphan, null}]
            nlohmann::json val = nlohmann::json::object();
            val["good"] = entry.pool_hash_rate;
            val["orphan"] = entry.pool_hash_rate * entry.pool_stale_prop;
            val["null"] = 0.0;
            result.push_back({entry.time, val});
        }
        else if (source == "pool_hash_rate") {
            result.push_back({entry.time, entry.pool_hash_rate});
        }
        else if (source == "pool_stale_prop") {
            result.push_back({entry.time, entry.pool_stale_prop});
        }
        else if (source == "local_hash_rate") {
            double total = 0.0;
            if (entry.local_hash_rates.is_object()) {
                for (auto& [k, v] : entry.local_hash_rates.items()) {
                    if (v.is_number())
                        total += v.get<double>();
                }
            }
            result.push_back({entry.time, total});
        }
        else if (source == "local_dead_hash_rate") {
            result.push_back({entry.time, 0.0});
        }
        else if (source == "worker_count") {
            // Unique address.worker combos — 1 miner with 3 named workers = 3
            result.push_back({entry.time, entry.worker_count});
        }
        else if (source == "unique_miner_count") {
            // Unique base addresses — 3 rigs with same address = 1 miner
            result.push_back({entry.time, entry.miner_count});
        }
        else if (source == "connected_miners") {
            // Raw stratum TCP connections — 1 ASIC with 2 connections = 2
            result.push_back({entry.time, entry.connected_count});
        }
        else if (source == "current_payout") {
            result.push_back({entry.time, entry.current_payout});
        }
        else if (source == "peers") {
            result.push_back({entry.time, entry.peers});
        }
        else if (source == "local_share_hash_rates") {
            // Return per-miner data as object
            result.push_back({entry.time, entry.local_hash_rates});
        }
        else if (source == "miner_hash_rates") {
            result.push_back({entry.time, entry.local_hash_rates});
        }
        else if (source == "miner_dead_hash_rates") {
            result.push_back({entry.time, nlohmann::json::object()});
        }
        else if (source == "current_payouts") {
            result.push_back({entry.time, nlohmann::json::object()});
        }
        else if (source == "desired_version_rates") {
            result.push_back({entry.time, nlohmann::json::object()});
        }
        else if (source == "traffic_rate") {
            result.push_back({entry.time, 0.0});
        }
        else if (source == "getwork_latency") {
            result.push_back({entry.time, 0.0});
        }
        else if (source == "memory_usage") {
            result.push_back({entry.time, 0.0});
        }
        else {
            result.push_back({entry.time, 0.0});
        }
    }
    return result;
}

// ──────────── Difficulty tracking and stat log helpers ────────────────────

void MiningInterface::record_share_difficulty(double difficulty, const std::string& miner)
{
    std::lock_guard<std::mutex> lock(m_best_diff_mutex);
    auto now_ts = static_cast<uint64_t>(std::time(nullptr));
    if (difficulty > m_best_difficulty.all_time) {
        m_best_difficulty.all_time = difficulty;
        m_best_difficulty.all_time_miner = miner;
        m_best_difficulty.all_time_ts = now_ts;
    }
    if (difficulty > m_best_difficulty.session) {
        m_best_difficulty.session = difficulty;
        m_best_difficulty.session_miner = miner;
        m_best_difficulty.session_ts = now_ts;
    }
    if (difficulty > m_best_difficulty.round) {
        m_best_difficulty.round = difficulty;
        m_best_difficulty.miner = miner;
        m_best_difficulty.timestamp = now_ts;
    }
}

void MiningInterface::record_merged_share_difficulty(double difficulty, const std::string& miner)
{
    std::lock_guard<std::mutex> lock(m_best_diff_mutex);
    auto now_ts = static_cast<uint64_t>(std::time(nullptr));
    if (difficulty > m_best_difficulty.merged_all_time) {
        m_best_difficulty.merged_all_time = difficulty;
        m_best_difficulty.merged_all_time_miner = miner;
        m_best_difficulty.merged_all_time_ts = now_ts;
    }
    if (difficulty > m_best_difficulty.merged_round) {
        m_best_difficulty.merged_round = difficulty;
        m_best_difficulty.merged_round_miner = miner;
        m_best_difficulty.merged_round_ts = now_ts;
    }
}

void MiningInterface::update_stat_log()
{
    StatLogEntry entry;
    entry.time = static_cast<double>(std::time(nullptr));

    // Pool hash rate — use p2pool-correct callback (safe, runs on ioc thread)
    entry.pool_hash_rate = m_pool_hashrate_fn ? m_pool_hashrate_fn() : 0.0;

    // Periodic network difficulty sample for graph
    double cur_diff = m_network_difficulty.load(std::memory_order_relaxed);
    if (cur_diff > 0)
        add_netdiff_sample(cur_diff, "periodic");

    // Pool stale proportion from sharechain orphan+dead counts
    if (m_sharechain_stats_fn) {
        auto sc = m_sharechain_stats_fn();
        int ts = sc.value("total_shares", 0);
        int os = sc.value("orphan_shares", 0);
        int ds = sc.value("dead_shares", 0);
        int st = os + ds;
        entry.pool_stale_prop = (ts > 0) ? static_cast<double>(st) / ts : 0.0;
    } else {
        entry.pool_stale_prop = 0.0;
    }

    // Local hash rates by address — from stratum worker registry
    // Matches p2pool: worker_count = unique address.worker combos,
    // unique_miner_count = unique base addresses,
    // connected_miners = raw stratum TCP connections.
    entry.local_hash_rates = nlohmann::json::object();
    {
        auto workers = get_stratum_workers();
        entry.connected_count = static_cast<int>(workers.size());  // raw TCP connections
        std::set<std::string> worker_combos;
        for (const auto& [sid, w] : workers) {
            double existing = entry.local_hash_rates.value(w.username, 0.0);
            entry.local_hash_rates[w.username] = existing + w.hashrate;
            // address.worker combo — e.g. "LTC1abc.rig1" is distinct from "LTC1abc.rig2"
            std::string combo = w.username;
            if (!w.worker_name.empty()) combo += "." + w.worker_name;
            worker_combos.insert(combo);
        }
        entry.miner_count = static_cast<int>(entry.local_hash_rates.size());  // unique addresses
        entry.worker_count = static_cast<int>(worker_combos.size());          // unique address.worker
    }

    entry.shares = 0;
    entry.stale_shares = 0;
    // Note: sharechain_stats_fn is unsafe (concurrent tracker modification).
    // Share count is non-critical for graphs — leave at 0 for now.

    // Current payout
    entry.current_payout = 0.0;
    auto* pm = m_payout_manager_ptr ? m_payout_manager_ptr : m_payout_manager.get();
    if (pm && pm->has_pplns_data() && !m_payout_address.empty()) {
        uint64_t subsidy = 0;
        {
            std::lock_guard<std::mutex> lock(m_work_mutex);
            if (!m_cached_template.is_null())
                subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
        }
        if (subsidy > 0) {
            auto outputs = pm->calculate_pplns_outputs(subsidy);
            auto script = address_to_script(m_payout_address);
            if (!script.empty()) {
                for (const auto& [scr, amt] : outputs) {
                    if (scr == script) {
                        entry.current_payout = static_cast<double>(amt) / 1e8;
                        break;
                    }
                }
            }
        }
    }

    // Peers — use P2P peer info callback for accurate counts
    int incoming = 0, outgoing = 0;
    if (m_peer_info_fn) {
        auto pi = m_peer_info_fn();
        if (pi.is_array()) {
            for (const auto& p : pi) {
                if (p.value("incoming", false)) ++incoming;
                else ++outgoing;
            }
        }
    } else if (m_node) {
        outgoing = static_cast<int>(m_node->get_connected_peers_count());
    }
    entry.peers = {{"incoming", incoming}, {"outgoing", outgoing}};

    double share_diff = m_network_difficulty.load(std::memory_order_relaxed) / 65536.0; // approx
    entry.attempts_to_share = share_diff * 4294967296.0;
    double net_diff = m_network_difficulty.load(std::memory_order_relaxed);
    entry.attempts_to_block = net_diff * 4294967296.0;

    // Block value
    entry.block_value = 0.0;
    {
        std::lock_guard<std::mutex> lock(m_work_mutex);
        if (!m_cached_template.is_null())
            entry.block_value = m_cached_template.value("coinbasevalue", uint64_t(0)) / 1e8;
    }

    {
        std::lock_guard<std::mutex> lock(m_stat_log_mutex);
        m_stat_log.push_back(entry);
        // Keep rolling 24h window (max ~288 entries at 5min intervals)
        double cutoff = entry.time - 86400.0;
        while (!m_stat_log.empty() && m_stat_log.front().time < cutoff)
            m_stat_log.erase(m_stat_log.begin());
    }
}

void MiningInterface::set_pool_fee_percent(double fee_percent)
{
    m_pool_fee_percent = fee_percent;
}

// Extract hash160 from any address type and return the address category.

// address_to_hash160, hash160_to_merged_script, is_address_for_chain,
// address_to_script moved to address_utils.cpp

void MiningInterface::set_node_fee_from_address(double percent, const std::string& address)
{
    auto script = address_to_script(address);
    if (script.empty()) {
        LOG_WARNING << "set_node_fee_from_address: invalid address " << address;
        return;
    }
    set_node_fee(percent, script);
    m_node_fee_address = address;
}

void MiningInterface::set_donation_script_from_address(const std::string& address)
{
    auto script = address_to_script(address);
    if (script.empty()) return;
    set_donation_script(script);
}

nlohmann::json MiningInterface::mining_subscribe(const std::string& user_agent, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.subscribe from: " << user_agent;
    
    // Return stratum subscription response
    return nlohmann::json::array({
        nlohmann::json::array({"mining.notify", "subscription_id_1"}),
        "extranonce1",
        0 // extranonce2_size = 0 (p2pool per-connection coinbase)
    });
}

nlohmann::json MiningInterface::mining_authorize(const std::string& username, const std::string& password, const std::string& request_id)
{
    LOG_INFO << "Stratum mining.authorize for user: " << username;
    
    // Validate the username as a payout address for the configured blockchain/network
    if (!is_valid_address(username)) {
        std::string blockchain_name = m_address_validator.get_blockchain_name(m_blockchain);
        LOG_WARNING << "Authorization failed: Invalid address for " 
                   << blockchain_name << " " 
                   << (m_testnet ? "testnet" : "mainnet") << ": " << username;
        
        nlohmann::json error_response;
        error_response["result"] = false;
        error_response["error"] = {
            {"code", -1},
            {"message", "Invalid payout address for " + blockchain_name + 
                       " " + (m_testnet ? "testnet" : "mainnet")}
        };
        return error_response;
    }
    
    LOG_INFO << "Authorization successful for address: " << username;
    return true;
}

nlohmann::json MiningInterface::mining_submit(const std::string& username, const std::string& job_id, const std::string& extranonce1, const std::string& extranonce2, const std::string& ntime, const std::string& nonce, const std::string& request_id,
    const std::map<uint32_t, std::vector<unsigned char>>& merged_addresses,
    const JobSnapshot* job)
{
    LOG_TRACE << "[Stratum] mining.submit " << username << " job=" << job_id
              << " nonce=" << nonce << " en2=" << extranonce2;
    
    // Basic share validation
    bool share_valid = true;
    
    // Validate hex parameters
    if (extranonce2.empty() || ntime.empty() || nonce.empty()) {
        LOG_WARNING << "Invalid share parameters from " << username;
        return false;
    }
    
    // Validate nonce format (should be 8 hex chars)
    if (nonce.length() != 8) {
        LOG_WARNING << "Invalid nonce length from " << username << ": " << nonce;
        return false;
    }
    
    // Validate extranonce2 format
    if (extranonce2.length() != 8) {
        LOG_WARNING << "Invalid extranonce2 length from " << username << ": " << extranonce2;
        return false;
    }
    
    // Validate timestamp format (should be 8 hex chars)
    if (ntime.length() != 8) {
        LOG_WARNING << "Invalid ntime length from " << username << ": " << ntime;
        return false;
    }
    
    // Calculate share difficulty
    double share_difficulty = calculate_share_difficulty(job_id, extranonce1, extranonce2, ntime, nonce);
    
    if (m_solo_mode) {
        // Solo mining mode - work directly with blockchain
        LOG_INFO << "Solo mining share from " << username << " (difficulty: " << share_difficulty << ")";
        
        // In solo mode, check if share meets network difficulty for block submission
        std::string payout_address = m_solo_address.empty() ? username : m_solo_address;
        
        // Calculate payout allocation if we have a payout manager
        if (m_payout_manager_ptr) {
            // Simulate block reward for calculation (25 LTC = 2500000000 satoshis)
            uint64_t block_reward = 2500000000; // 25 LTC in satoshis
            auto allocation = m_payout_manager_ptr->calculate_payout(block_reward);
            
            if (allocation.is_valid()) {
                LOG_INFO << "Solo mining payout allocation:";
                LOG_INFO << "  Miner (" << payout_address << "): " << allocation.miner_percent << "% = " << allocation.miner_amount << " satoshis";
                LOG_INFO << "  Developer: " << allocation.developer_percent << "% = " << allocation.developer_amount << " satoshis (" << allocation.developer_address << ")";
                if (allocation.node_owner_amount > 0) {
                    LOG_INFO << "  Node owner: " << allocation.node_owner_percent << "% = " << allocation.node_owner_amount << " satoshis (" << allocation.node_owner_address << ")";
                }
                
                // Allocation is already baked into coinbase parts by refresh_work() →
                // build_coinbase_parts(). When a valid block is found below, it carries
                // the correct developer and node-owner fee outputs.
            }
        }
        
        LOG_INFO << "Solo mining share accepted - primary payout address: " << payout_address;
        
        // Check if share meets network difficulty and attempt block submission
        if ((m_coin_rpc || m_embedded_node) && !extranonce1.empty()) {
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce, job);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                bool solo_merged_found = check_merged_mining(block_hex, extranonce1, extranonce2, job);

                // Check PoW hash against the blockchain target before submitting
                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                if (block_bytes.size() == 80) {
                    char pow_hash_bytes[32];
                    scrypt_1024_1_1_256(reinterpret_cast<const char*>(block_bytes.data()), pow_hash_bytes);
                    uint256 pow_hash;
                    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

                    // Read nBits directly from the block header (offset 72, LE uint32).
                    // Using the header's own bits guarantees the same target litecoind
                    // will verify, avoiding races when GBT difficulty changes between
                    // job creation and share submission.
                    uint32_t header_bits = block_bytes[72] | (block_bytes[73] << 8) |
                                           (block_bytes[74] << 16) | (block_bytes[75] << 24);
                    uint256 block_target = chain::bits_to_target(header_bits);

                    if (!block_target.IsNull() && pow_hash <= block_target) {
                        // Validate merkle root before submitting
                        uint256 header_merkle;
                        std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                        std::string coinbase_hex;
                        uint256 expected_merkle;
                        {
                            const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                            const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                            const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                            coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                            expected_merkle = reconstruct_merkle_root(coinbase_hex, branches);
                        }

                        if (header_merkle != expected_merkle) {
                            LOG_ERROR << "Block merkle_root mismatch!"
                                      << " header=" << header_merkle.GetHex()
                                      << " expected=" << expected_merkle.GetHex();
                        } else {
                            // Skip duplicate blocks at the same prev_block
                            // (multiple shares can meet the target at the same height)
                            uint256 prev_block;
                            std::memcpy(prev_block.data(), block_bytes.data() + 4, 32);
                            static uint256 s_last_submitted_prev;
                            if (prev_block != s_last_submitted_prev) {
                                s_last_submitted_prev = prev_block;
                                uint256 block_hash = Hash(std::span<const unsigned char>(block_bytes.data(), block_bytes.size()));
                                LOG_INFO << "[BLOCK] Parent block found by " << username
                                         << " hash=" << block_hash.GetHex().substr(0,16);
                                submitblock(block_hex);
                            }
                        }
                    }
                }
            }
        }

        return nlohmann::json{{"result", true}};
    } else {
        // Standard pool mode - track shares for sharechain and payouts

        // Extract primary address from multiaddress username format.
        // Format: PRIMARY_ADDR[,MERGED_ADDR...][.WORKER_NAME]
        std::string primary_addr = username;
        {
            auto dot_pos = primary_addr.rfind('.');
            if (dot_pos != std::string::npos && dot_pos > 20)
                primary_addr = primary_addr.substr(0, dot_pos);
            auto comma_pos = primary_addr.find(',');
            if (comma_pos != std::string::npos)
                primary_addr = primary_addr.substr(0, comma_pos);
        }
        // Decode any address format: base58 (P2PKH/P2SH) or bech32 (P2WPKH)
        std::string addr_type_str;
        std::string share_address = address_to_hash160(primary_addr, addr_type_str);
        uint8_t share_addr_type = 0; // 0=P2PKH, 1=P2WPKH, 2=P2SH
        if (share_address.size() == 40) {
            if (addr_type_str == "p2wpkh") share_addr_type = 1;
            else if (addr_type_str == "p2sh") share_addr_type = 2;
        }
        if (share_address.size() != 40) {
            // Case 4 (Python work.py): invalid/empty LTC address but miner provided an
            // explicit DOGE merged address → derive LTC hash160 from DOGE P2PKH script.
            // LTC and DOGE use identical secp256k1 keys: same pubkey_hash, different version byte.
            static constexpr uint32_t DOGE_CHAIN_ID = 98;
            auto doge_it = merged_addresses.find(DOGE_CHAIN_ID);
            if (doge_it != merged_addresses.end()) {
                const auto& doge_script = doge_it->second;
                // P2PKH script: 76 a9 14 <20-byte hash160> 88 ac
                if (doge_script.size() == 25 &&
                    doge_script[0] == 0x76 && doge_script[1] == 0xa9 && doge_script[2] == 0x14) {
                    static const char* HEX = "0123456789abcdef";
                    std::string h160;
                    h160.reserve(40);
                    for (int i = 3; i < 23; ++i) {
                        h160 += HEX[doge_script[i] >> 4];
                        h160 += HEX[doge_script[i] & 0x0f];
                    }
                    share_address = h160;
                    LOG_INFO << "mining_submit: Case 4 — LTC share hash160 derived from DOGE merged address";
                }
            }
        }
        if (share_address.size() != 40) {
            // Case 3 (Python work.py): no valid LTC or DOGE address → redistribute
            // according to the node's configured --redistribute mode.
            if (m_address_fallback_fn) {
                share_address = m_address_fallback_fn(primary_addr);
                if (share_address.size() == 40)
                    LOG_INFO << "mining_submit: Case 3 — redistributed share for invalid address '"
                             << primary_addr << "'";
            }
            if (share_address.size() != 40)
                LOG_WARNING << "mining_submit: cannot resolve share address for '"
                            << primary_addr << "' — share will carry zero-hash payout";
        }

        // p2pool -f: probabilistic node fee (matches work.py:1592-1594).
        // With probability fee%, replace the miner's pubkey_hash with the
        // node operator's. ~fee% of shares carry the operator's address
        // in PPLNS, so the operator earns ~fee% of block rewards.
        // Supports P2PKH, P2SH, and P2WPKH node fee addresses.
        if (m_node_fee_percent > 0.0 && !m_node_fee_script.empty()) {
            float roll = core::random::random_float(0.0f, 100.0f);
            if (roll < static_cast<float>(m_node_fee_percent)) {
                // Extract hash160 from node fee scriptPubKey (any supported type)
                static const char* HEX = "0123456789abcdef";
                int h160_off = -1;
                auto sz = m_node_fee_script.size();
                if (sz == 25 && m_node_fee_script[0] == 0x76 &&
                    m_node_fee_script[1] == 0xa9 && m_node_fee_script[2] == 0x14) {
                    h160_off = 3;  // P2PKH: 76 a9 14 <20> 88 ac
                } else if (sz == 23 && m_node_fee_script[0] == 0xa9 &&
                           m_node_fee_script[1] == 0x14) {
                    h160_off = 2;  // P2SH: a9 14 <20> 87
                } else if (sz == 22 && m_node_fee_script[0] == 0x00 &&
                           m_node_fee_script[1] == 0x14) {
                    h160_off = 2;  // P2WPKH: 00 14 <20>
                }
                if (h160_off >= 0) {
                    std::string h160;
                    h160.reserve(40);
                    for (int i = h160_off; i < h160_off + 20; ++i) {
                        h160 += HEX[m_node_fee_script[i] >> 4];
                        h160 += HEX[m_node_fee_script[i] & 0x0f];
                    }
                    share_address = h160;
                    LOG_DEBUG_POOL << "Node fee: share " << job_id
                                   << " address replaced → operator (roll="
                                   << roll << " < " << m_node_fee_percent << ")";
                }
            }
        }
        
        // Track mining_share submission for statistics
        if (m_node) {
            m_node->track_mining_share_submission(username, share_difficulty);
        }

        // Record share contribution for payout calculation (pool mode only)
        if (m_payout_manager) {
            m_payout_manager->record_share_contribution(share_address, share_difficulty);
            LOG_DEBUG_POOL << "Share contribution recorded: " << share_address << " (difficulty: " << share_difficulty << ")";
        }

        // Create a proper V36 share in the tracker with all block template data.
        // The payout_script is built from share_address (which may have been
        // probabilistically replaced with the node operator's address for the
        // primary chain node fee).  Merged addresses are passed through
        // unmodified — Python p2pool does NOT apply node fee to merged chains.
        if (m_create_share_fn) {
            ShareCreationParams params;
            // Miner display name: PRIMARY_ADDR.WORKER (strip merged addrs, keep worker)
            {
                std::string display = username;
                // Remove merged addresses (after first comma) but keep worker name (after last dot)
                auto comma_pos = display.find(',');
                std::string worker;
                if (comma_pos != std::string::npos) {
                    // Check for worker name after the merged addresses
                    auto dot_pos = display.rfind('.');
                    if (dot_pos != std::string::npos && dot_pos > comma_pos)
                        worker = display.substr(dot_pos);
                    display = display.substr(0, comma_pos) + worker;
                }
                params.miner_address = display;
            }

            // Build scriptPubKey from share_address (40-char hex hash160) + type
            if (share_address.size() == 40) {
                std::vector<unsigned char> hash160_bytes;
                hash160_bytes.reserve(20);
                for (size_t i = 0; i < share_address.size(); i += 2)
                    hash160_bytes.push_back(static_cast<unsigned char>(
                        std::stoul(share_address.substr(i, 2), nullptr, 16)));

                if (share_addr_type == 1) {
                    // P2WPKH: 00 14 <20-byte witness program>
                    params.payout_script = {0x00, 0x14};
                    params.payout_script.insert(params.payout_script.end(),
                        hash160_bytes.begin(), hash160_bytes.end());
                } else if (share_addr_type == 2) {
                    // P2SH: a9 14 <20-byte hash> 87
                    params.payout_script = {0xa9, 0x14};
                    params.payout_script.insert(params.payout_script.end(),
                        hash160_bytes.begin(), hash160_bytes.end());
                    params.payout_script.push_back(0x87);
                } else {
                    // P2PKH: 76 a9 14 <20-byte hash> 88 ac
                    params.payout_script = {0x76, 0xa9, 0x14};
                    params.payout_script.insert(params.payout_script.end(),
                        hash160_bytes.begin(), hash160_bytes.end());
                    params.payout_script.push_back(0x88);
                    params.payout_script.push_back(0xac);
                }
            }

            params.merged_addresses = merged_addresses;
            params.nonce = static_cast<uint32_t>(std::stoul(nonce, nullptr, 16));
            params.timestamp = static_cast<uint32_t>(std::stoul(ntime, nullptr, 16));

            // Extract block template fields — prefer job snapshot over live template.
            // CRITICAL: share.m_bits (share chain target) and min_header.m_bits
            // (block difficulty in the 80-byte header) are DIFFERENT values.
            // - params.bits = share chain target from compute_share_target()
            // - params.block_bits = GBT block difficulty (what the miner puts in the header)
            // Confusing these causes p2pool to reject shares as "PoW invalid".
            {
                std::lock_guard<std::mutex> lock(m_work_mutex);
                if (job) {
                    params.block_version = job->version;
                    params.prev_block_hash.SetHex(job->gbt_prevhash);
                    // Share chain difficulty
                    params.bits = job->share_bits ? job->share_bits
                        : static_cast<uint32_t>(std::stoul(job->nbits, nullptr, 16));
                    // Block difficulty (GBT bits) — goes into the 80-byte header
                    params.block_bits = static_cast<uint32_t>(
                        std::stoul(job->block_nbits.empty() ? job->nbits : job->block_nbits, nullptr, 16));
                    params.subsidy = job->subsidy;
                } else if (m_work_valid) {
                    params.block_version = m_cached_template.value("version", 536870912U);
                    if (m_cached_template.contains("previousblockhash")) {
                        params.prev_block_hash.SetHex(
                            m_cached_template["previousblockhash"].get<std::string>());
                    }
                    // Share chain difficulty
                    uint32_t sb = m_share_bits.load();
                    if (sb != 0) {
                        params.bits = sb;
                    } else if (m_cached_template.contains("bits")) {
                        params.bits = static_cast<uint32_t>(std::stoul(
                            m_cached_template["bits"].get<std::string>(), nullptr, 16));
                    }
                    // Block difficulty from GBT
                    if (m_cached_template.contains("bits")) {
                        params.block_bits = static_cast<uint32_t>(std::stoul(
                            m_cached_template["bits"].get<std::string>(), nullptr, 16));
                    }
                    params.subsidy = m_cached_template.value("coinbasevalue", uint64_t(0));
                }

                // Build the actual mined coinbase: coinb1 + en1 + en2 + coinb2
                // In the new split, en1+en2 fill the last_txout_nonce (in OP_RETURN),
                // not the scriptSig.  So the scriptSig is the same in all coinbases.
                std::string full_coinbase_hex;
                {
                    const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                    const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                    full_coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                }

                // Extract scriptSig from the coinbase (scriptSig is fixed, no en1/en2).
                // Layout: version(4) + vin_count(1) + prev_hash(32) + prev_idx(4) + script_len(1+)
                auto cb_bytes = ParseHex(full_coinbase_hex);
                if (cb_bytes.size() > 41) {
                    size_t pos = 41;
                    uint64_t scriptsig_len = cb_bytes[pos++];
                    if (scriptsig_len < 0xfd && pos + scriptsig_len <= cb_bytes.size()) {
                        params.coinbase_scriptSig.assign(
                            cb_bytes.begin() + pos,
                            cb_bytes.begin() + pos + scriptsig_len);
                    }
                    LOG_INFO << "[scriptSig-extract] cb_total=" << cb_bytes.size()
                             << " scriptsig_varint=0x" << std::hex << scriptsig_len << std::dec
                             << " scriptsig_len=" << scriptsig_len
                             << " extracted=" << params.coinbase_scriptSig.size()
                             << " cb1_src=" << (job ? "job" : "cached");
                }

                // Convert string merkle branches to uint256 (internal byte order)
                const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                params.merkle_branches.reserve(branches.size());
                for (const auto& branch_hex : branches) {
                    uint256 h;
                    auto branch_bytes = ParseHex(branch_hex);
                    if (branch_bytes.size() == 32)
                        memcpy(h.begin(), branch_bytes.data(), 32);
                    params.merkle_branches.push_back(h);
                }

                // Segwit fields for SegwitData on the share
                params.segwit_active = job ? job->segwit_active : m_segwit_active;
                if (params.segwit_active) {
                    if (job && !job->witness_commitment_hex.empty()) {
                        params.witness_commitment_hex = job->witness_commitment_hex;
                        params.witness_root = job->witness_root;
                    } else {
                        // Fallback: use cached values from refresh_work
                        params.witness_commitment_hex = m_cached_witness_commitment;
                        params.witness_root = m_cached_witness_root;
                    }
                    // Safety net: if witness_root is still null, recompute from
                    // the job's frozen tx_data (matches p2pool data.py:1024).
                    // This handles race conditions where the root was lost in transit.
                    const auto& txd = job ? job->tx_data : std::vector<std::string>{};
                    if (params.witness_root.IsNull() && !txd.empty()) {
                        std::vector<uint256> wtxids;
                        wtxids.push_back(uint256());  // coinbase wtxid = 0
                        for (const auto& tx_hex : txd) {
                            auto tx_bytes = ParseHex(tx_hex);
                            if (!tx_bytes.empty())
                                wtxids.push_back(Hash(tx_bytes));
                        }
                        params.witness_root = compute_witness_merkle_root(std::move(wtxids));
                        LOG_WARNING << "[WC-FIX] witness_root was null, recomputed from "
                                    << txd.size() << " txs: "
                                    << params.witness_root.GetHex();
                    }
                }

                // Pass the actual mined coinbase TX bytes for hash_link computation.
                if (!full_coinbase_hex.empty())
                    params.full_coinbase_bytes = ParseHex(full_coinbase_hex);

                // Optional operator-provided authority message blob (V36 message_data).
                params.message_data = get_operator_message_blob();

                // Use the share chain tip and frozen fields from work-generation time.
                // These match what was used to compute the ref_hash in the coinbase.
                if (job) {
                    params.prev_share_hash = job->prev_share_hash;
                    params.frozen_absheight = job->frozen_ref.absheight;
                    params.frozen_abswork = job->frozen_ref.abswork;
                    params.frozen_far_share_hash = job->frozen_ref.far_share_hash;
                    params.frozen_max_bits = job->frozen_ref.max_bits;
                    params.frozen_bits = job->frozen_ref.bits;
                    params.frozen_timestamp = job->frozen_ref.timestamp;
                    params.frozen_merged_payout_hash = job->frozen_ref.merged_payout_hash;
                    params.frozen_merkle_branches = job->frozen_ref.frozen_merkle_branches;
                    params.frozen_witness_root = job->frozen_ref.frozen_witness_root;
                    // Safety: if frozen_witness_root is null, use the recomputed witness_root.
                    // The ref_hash_fn stored the same witness_root when it ran, so using
                    // the recomputed value keeps consistency (both come from the same tx set).
                    if (params.frozen_witness_root.IsNull() && !params.witness_root.IsNull())
                        params.frozen_witness_root = params.witness_root;
                    params.frozen_merged_coinbase_info = job->frozen_ref.frozen_merged_coinbase_info;
                    // has_frozen = true when ref_hash_fn produced valid frozen data.
                    // Cannot use absheight > 0: absheight IS 0 for the genesis share,
                    // but frozen data is still valid. Use bits != 0 as the indicator:
                    // bits is always non-zero when ref_hash_fn ran (share target > 0).
                    params.has_frozen_fields = (job->frozen_ref.bits != 0);
                    params.share_version = job->frozen_ref.share_version;
                    params.desired_version = job->frozen_ref.desired_version;
                    params.stale_info = job->stale_info;
                }
            }

            // Bootstrap: when chain depth < TARGET_LOOKBEHIND, share_bits is 0
            // to signal "not ready for share creation yet". Skip share creation
            // and only mine pseudoshares until difficulty stabilizes.
            // Exception: genesis mode (no peers) uses max_target fallback.
            if (params.bits == 0) {
                params.bits = m_share_max_bits.load();
                // Only use genesis fallback if no peers have connected yet
                // (m_share_max_bits is 0 when compute_share_target returns {0,0})
            }
            if (!params.payout_script.empty() && params.bits != 0) {
                m_create_share_fn(params);
            }
        }
        
        // Attempt block construction + submission only when PoW meets blockchain target.
        if ((m_coin_rpc || m_embedded_node) && !extranonce1.empty()) {
            std::string block_hex = build_block_from_stratum(extranonce1, extranonce2, ntime, nonce, job);
            if (!block_hex.empty()) {
                // Check merged mining targets for every share (aux targets are lower)
                bool merged_found = check_merged_mining(block_hex, extranonce1, extranonce2, job);

                auto block_bytes = ParseHex(block_hex.substr(0, 160));
                if (block_bytes.size() == 80) {
                    char pow_hash_bytes[32];
                    scrypt_1024_1_1_256(reinterpret_cast<const char*>(block_bytes.data()), pow_hash_bytes);
                    uint256 pow_hash;
                    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

                    // Read nBits from the block header itself (offset 72, LE uint32)
                    // to match exactly what litecoind will verify.
                    uint32_t header_bits = block_bytes[72] | (block_bytes[73] << 8) |
                                           (block_bytes[74] << 16) | (block_bytes[75] << 24);
                    uint256 block_target = chain::bits_to_target(header_bits);

                    if (!block_target.IsNull() && pow_hash <= block_target) {
                        uint256 header_merkle;
                        std::memcpy(header_merkle.data(), block_bytes.data() + 36, 32);

                        std::string coinbase_hex;
                        uint256 expected_merkle;
                        {
                            const std::string& cb1 = job ? job->coinb1 : m_cached_coinb1;
                            const std::string& cb2 = job ? job->coinb2 : m_cached_coinb2;
                            const auto& branches = job ? job->merkle_branches : m_cached_merkle_branches;
                            coinbase_hex = cb1 + extranonce1 + extranonce2 + cb2;
                            expected_merkle = reconstruct_merkle_root(coinbase_hex, branches);
                        }

                        if (header_merkle != expected_merkle) {
                            LOG_ERROR << "Pool block merkle_root mismatch!"
                                      << " header=" << header_merkle.GetHex()
                                      << " expected=" << expected_merkle.GetHex();
                        } else {
                            // Skip duplicate blocks at the same prev_block
                            uint256 prev_block;
                            std::memcpy(prev_block.data(), block_bytes.data() + 4, 32);
                            static uint256 s_last_pool_submitted_prev;
                            if (prev_block != s_last_pool_submitted_prev) {
                                s_last_pool_submitted_prev = prev_block;
                                uint256 block_hash = Hash(std::span<const unsigned char>(block_bytes.data(), block_bytes.size()));
                                LOG_INFO << "[BLOCK] " << (merged_found ? "Twin" : "Parent")
                                         << " block found by " << username
                                         << " hash=" << block_hash.GetHex().substr(0,16);
                                submitblock(block_hex);
                            }
                        }
                    }
                }
            }
        }
        
        return nlohmann::json{{"result", true}};
    }
}

nlohmann::json MiningInterface::validate_address(const std::string& address)
{
    LOG_INFO << "Address validation request for: " << address;
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (m_payout_manager) {
            // Use the existing address validator from payout manager
            auto validation_result = m_payout_manager->get_address_validator()->validate_address(address);
            
            result["valid"] = validation_result.is_valid;
            result["address"] = address;
            result["type"] = static_cast<int>(validation_result.type);
            result["blockchain"] = static_cast<int>(validation_result.blockchain);
            result["network"] = static_cast<int>(validation_result.network);
            
            if (!validation_result.is_valid) {
                result["error"] = validation_result.error_message;
            }
            
            LOG_INFO << "Address validation result: " << (validation_result.is_valid ? "VALID" : "INVALID");
            
        } else {
            result["valid"] = false;
            result["error"] = "Payout manager not available";
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Address validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::build_coinbase(const nlohmann::json& params)
{
    LOG_INFO << "Coinbase construction request received";
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        // Extract parameters
        uint64_t block_reward = params.value("block_reward", 2500000000ULL); // Default 25 LTC
        std::string miner_address = params.value("miner_address", "");
        double dev_fee_percent = params.value("dev_fee_percent", 0.0);
        double node_fee_percent = params.value("node_fee_percent", 0.0);
        
        if (miner_address.empty()) {
            throw std::runtime_error("Miner address is required");
        }
        
        // Validate the miner address first
        auto addr_validation = m_payout_manager->get_address_validator()->validate_address(miner_address);
        if (!addr_validation.is_valid) {
            throw std::runtime_error("Invalid miner address: " + addr_validation.error_message);
        }
        
        // Build detailed coinbase
        auto result = m_payout_manager->build_coinbase_detailed(block_reward, miner_address, 
                                                               dev_fee_percent, node_fee_percent);
        
        LOG_INFO << "Coinbase construction successful for " << miner_address;
        return result;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase construction error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Coinbase construction failed: ") + e.what()}
        };
    }
}

nlohmann::json MiningInterface::validate_coinbase(const std::string& coinbase_hex)
{
    LOG_INFO << "Coinbase validation request - hex length: " << coinbase_hex.length();
    
    nlohmann::json result = nlohmann::json::object();
    
    try {
        if (!m_payout_manager) {
            throw std::runtime_error("Payout manager not available");
        }
        
        bool is_valid = m_payout_manager->validate_coinbase_transaction(coinbase_hex);
        
        result["valid"] = is_valid;
        result["coinbase_hex"] = coinbase_hex;
        result["hex_length"] = coinbase_hex.length();
        result["byte_length"] = coinbase_hex.length() / 2;
        
        if (!is_valid) {
            result["error"] = "Coinbase transaction validation failed";
        }
        
        LOG_INFO << "Coinbase validation result: " << (is_valid ? "VALID" : "INVALID");
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Coinbase validation error: " << e.what();
        result["valid"] = false;
        result["error"] = std::string("Validation failed: ") + e.what();
    }
    
    return result;
}

nlohmann::json MiningInterface::getblockcandidate(const nlohmann::json& params)
{
    LOG_INFO << "Block candidate request received";
    
    try {
        // Get base block template (this would normally come from the coin node)
        auto base_template = getblocktemplate(nlohmann::json::array());
        
        // Enhance with coinbase construction if payout manager available
        if (m_payout_manager && params.contains("miner_address")) {
            std::string miner_address = params["miner_address"];
            uint64_t coinbase_value = base_template.value("coinbasevalue", 2500000000ULL);
            
            // Build coinbase with payout distribution
            auto coinbase_result = m_payout_manager->build_coinbase_detailed(coinbase_value, miner_address);
            
            // Add coinbase info to block template
            base_template["coinbase_outputs"] = coinbase_result["outputs"];
            base_template["coinbase_hex"] = coinbase_result["coinbase_hex"];
            base_template["payout_distribution"] = true;
            
            LOG_INFO << "Block candidate with payout distribution generated";
        } else {
            base_template["payout_distribution"] = false;
            LOG_INFO << "Basic block candidate generated (no payout distribution)";
        }
        
        // Add validation info
        base_template["candidate_valid"] = true;
        base_template["generation_time"] = static_cast<uint64_t>(std::time(nullptr));
        
        return base_template;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Block candidate generation error: " << e.what();
        return nlohmann::json{
            {"error", std::string("Block candidate generation failed: ") + e.what()},
            {"candidate_valid", false}
        };
    }
}

/// WebServer Implementation
WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet)
    : ioc_(ioc)
    , acceptor_(http_ioc_)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)  // Default stratum port is +10 from main port
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node)
    : ioc_(ioc)
    , acceptor_(http_ioc_)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(Blockchain::LITECOIN)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node);
}

WebServer::WebServer(net::io_context& ioc, const std::string& address, uint16_t port, bool testnet, std::shared_ptr<IMiningNode> node, Blockchain blockchain)
    : ioc_(ioc)
    , acceptor_(http_ioc_)
    , bind_address_(address)
    , port_(port)
    , stratum_port_(port + 10)
    , running_(false)
    , testnet_(testnet)
    , blockchain_(blockchain)
    , solo_mode_(false)
{
    mining_interface_ = std::make_shared<MiningInterface>(testnet, node, blockchain);
}

WebServer::~WebServer()
{
    stop();
}

bool WebServer::start()
{
    try {
        // Bind and listen on the HTTP port (runs on dedicated http_ioc_)
        auto const address = net::ip::make_address(bind_address_);
        tcp::endpoint endpoint{address, port_};

        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);

        LOG_INFO << "WebServer started on " << bind_address_ << ":" << port_ << " (dedicated HTTP thread)";

        // Start accepting HTTP connections (on http_ioc_)
        accept_connections();

        // Launch dedicated thread for HTTP event loop — decouples dashboard
        // latency from think()/verification work on the main ioc_.
        http_thread_ = std::thread([this]() {
            LOG_INFO << "[HTTP-thread] started";
            auto work_guard = net::make_work_guard(http_ioc_);
            while (running_ || !http_ioc_.stopped()) {
                try {
                    http_ioc_.run();
                    break;  // run() returned normally (ioc stopped)
                } catch (const std::exception& e) {
                    LOG_ERROR << "[HTTP-thread] exception: " << e.what();
                }
            }
            LOG_INFO << "[HTTP-thread] exiting";
        });

        // Start stratum server if configured (stays on main ioc_)
        if (stratum_port_ > 0) {
            start_stratum_server();
        }

        // One-shot initial template fetch: populate the cache before any events fire.
        // After this, all template updates are event-driven (bestblock, best_share_changed).
        // p2pool has no recurring refresh timer — Twisted reactor events handle everything.
        if (m_coin_rpc_) {
            auto timer = std::make_shared<net::steady_timer>(ioc_);
            timer->expires_after(std::chrono::milliseconds(500));
            timer->async_wait([this, timer](beast::error_code ec) {
                if (ec || !running_) return;
                try { mining_interface_->refresh_work(); }
                catch (const std::exception& e) { LOG_WARNING << "initial refresh_work failed: " << e.what(); }
                catch (...) { LOG_WARNING << "initial refresh_work failed: unknown error"; }
                LOG_INFO << "Initial block template fetched";
            });
        }

        // Schedule stat_log timer (every 60 seconds for graph data)
        {
            auto stat_timer = std::make_shared<net::steady_timer>(ioc_);
            auto stat_fn = std::make_shared<std::function<void(beast::error_code)>>();
            *stat_fn = [this, stat_timer, stat_fn](beast::error_code ec) {
                if (ec || !running_) return;
                try { mining_interface_->update_stat_log(); }
                catch (const std::exception& e) {
                    LOG_WARNING << "Stat log update failed: " << e.what();
                }
                stat_timer->expires_after(std::chrono::seconds(60));
                stat_timer->async_wait(*stat_fn);
            };
            stat_timer->expires_after(std::chrono::seconds(10)); // first sample after 10s
            stat_timer->async_wait(*stat_fn);
            LOG_INFO << "Stat-log timer scheduled (every 60 s)";
        }

        running_ = true;
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer: " << e.what();
        return false;
    }
}

void WebServer::set_on_block_submitted(std::function<void(const std::string&, int)> fn)
{
    mining_interface_->set_on_block_submitted(std::move(fn));
}

void WebServer::set_on_block_relay(std::function<void(const std::string&)> fn)
{
    mining_interface_->set_on_block_relay(std::move(fn));
}

std::map<std::array<uint8_t, 20>, double> WebServer::get_local_addr_rates() const
{
    // Forward to StratumServer. Converts unordered_map → sorted map.
    // p2pool ref: work.py:1975-1990
    std::map<std::array<uint8_t, 20>, double> result;
    if (stratum_server_) {
        auto rates = stratum_server_->get_local_addr_rates();
        for (auto& [k, v] : rates)
            result[k] = v;
    }
    return result;
}

void WebServer::trigger_work_refresh()
{
    // Update local hashrate from stratum sessions (p2pool: get_local_addr_rates)
    if (stratum_server_)
        mining_interface_->set_local_hashrate(stratum_server_->get_total_hashrate());
    mining_interface_->refresh_work();
    // Push new work to all miners immediately (p2pool: new_work_event).
    // Old jobs stay valid — miner submits by job_id, which maps to frozen data.
    // Stale shares only occur when MAX_ACTIVE_JOBS (32) is exceeded.
    if (stratum_server_)
        stratum_server_->notify_all();
}

void WebServer::trigger_work_refresh_debounced()
{
    // No debounce — call refresh immediately.
    // C++ refresh_work() is 0ms latency. Shares arrive every ~3.5s on average,
    // so there's nothing to coalesce. The 100ms debounce was adding a 100ms race
    // window that caused ~14% orphan rate (miner works on stale prev_share while
    // waiting for debounce timer). With 0ms, orphan rate drops to ~1%.
    trigger_work_refresh();
}

void WebServer::set_coin_rpc(ltc::coin::NodeRPC* rpc, ltc::interfaces::Node* coin)
{
    m_coin_rpc_  = rpc;
    m_coin_node_ = coin;
    mining_interface_->set_coin_rpc(rpc, coin);
    LOG_INFO << "WebServer: coin RPC " << (rpc ? "attached" : "detached");
}

void WebServer::set_embedded_node(ltc::coin::CoinNodeInterface* node)
{
    mining_interface_->set_embedded_node(node);
    LOG_INFO << "WebServer: embedded coin node " << (node ? "attached" : "detached");
}

void WebServer::set_best_share_hash_fn(std::function<uint256()> fn)
{
    mining_interface_->set_best_share_hash_fn(std::move(fn));
}

void WebServer::set_pplns_fn(MiningInterface::pplns_fn_t fn)
{
    mining_interface_->set_pplns_fn(std::move(fn));
}

void WebServer::set_merged_mining_manager(c2pool::merged::MergedMiningManager* mgr)
{
    mining_interface_->set_merged_mining_manager(mgr);
}

void WebServer::set_dashboard_dir(const std::string& dir)
{
    mining_interface_->set_dashboard_dir(dir);
    if (!dir.empty())
        LOG_INFO << "Dashboard serving from: " << dir;
}

void WebServer::set_analytics_id(const std::string& id)
{
    mining_interface_->set_analytics_id(id);
    if (!id.empty())
        LOG_INFO << "Analytics tag enabled: " << id;
}

void WebServer::set_explorer_enabled(bool enabled)
{
    mining_interface_->set_explorer_enabled(enabled);
    if (enabled)
        LOG_INFO << "[Explorer] API enabled (loopback-only)";
}

void WebServer::set_explorer_url(const std::string& url)
{
    mining_interface_->set_explorer_url(url);
    if (!url.empty())
        LOG_INFO << "[Explorer] Nav link URL: " << url;
}

bool WebServer::start_solo()
{
    solo_mode_ = true;
    
    try {
        // In solo mode, only start stratum server
        if (stratum_port_ > 0) {
            start_stratum_server();
            LOG_INFO << "WebServer started in solo mode on Stratum port " << stratum_port_;
            running_ = true;
            return true;
        } else {
            LOG_ERROR << "Solo mode requires Stratum port configuration";
            return false;
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start WebServer in solo mode: " << e.what();
        return false;
    }
}

void WebServer::stop()
{
    if (running_) {
        try {
            running_ = false;
            acceptor_.close();
            // Stop the dedicated HTTP event loop and join its thread
            http_ioc_.stop();
            if (http_thread_.joinable())
                http_thread_.join();
            stop_stratum_server();
            LOG_INFO << "WebServer stopped";
        } catch (const std::exception& e) {
            LOG_ERROR << "Error stopping WebServer: " << e.what();
        }
    }
}

bool WebServer::start_stratum_server()
{
    try {
        if (!stratum_server_) {
            stratum_server_ = std::make_unique<StratumServer>(ioc_, bind_address_, stratum_port_, mining_interface_);
        }
        
        bool started = stratum_server_->start();
        if (started) {
            LOG_INFO << "Stratum server started on port " << stratum_port_;
            // Wire stratum hashrate callback to MiningInterface
            auto* ss = stratum_server_.get();
            mining_interface_->set_stratum_hashrate_fn([ss]() -> double {
                return ss->get_total_hashrate();
            });
            mining_interface_->set_stratum_rate_stats_fn([ss]() -> MiningInterface::RateStats {
                auto s = ss->get_rate_stats();
                return {s.hashrate, s.effective_dt, s.total_datums, s.dead_datums};
            });
        }
        return started;
        
    } catch (const std::exception& e) {
        LOG_ERROR << "Failed to start Stratum server: " << e.what();
        return false;
    }
}

void WebServer::stop_stratum_server()
{
    if (stratum_server_) {
        stratum_server_->stop();
        stratum_server_.reset();
        LOG_INFO << "Stratum server stopped";
    }
}

void WebServer::set_stratum_port(uint16_t port)
{
    stratum_port_ = port;
}

void WebServer::accept_connections()
{
    acceptor_.async_accept(
        [this](beast::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void WebServer::handle_accept(beast::error_code ec, tcp::socket socket)
{

    if (!ec) {
        // Create and run HTTP session
        std::make_shared<HttpSession>(std::move(socket), mining_interface_)->run();
    } else {
        LOG_ERROR << "HTTP accept error: " << ec.message();
    }
    
    // Continue accepting new connections
    if (running_) {
        accept_connections();
    }
}

bool WebServer::is_stratum_running() const
{
    return stratum_server_ && stratum_server_->is_running();
}

uint16_t WebServer::get_stratum_port() const
{
    return stratum_port_;
}

/// LitecoinRpcClient Implementation
LitecoinRpcClient::LitecoinRpcClient(bool testnet)
    : testnet_(testnet)
{
}

LitecoinRpcClient::SyncStatus LitecoinRpcClient::get_sync_status()
{
    SyncStatus status;
    status.is_synced = true;  // Assume synced for now
    status.progress = 1.0;
    status.current_blocks = 3945867;  // Mock value for testing
    status.total_headers = 3945867;
    status.initial_block_download = false;
    status.error_message = "";
    
    return status;
}

bool LitecoinRpcClient::is_connected()
{
    return true;  // Assume connected for now
}

std::string LitecoinRpcClient::execute_cli_command(const std::string& command)
{
    return "OK";  // Mock response for testing
}


// StratumServer and StratumSession implementations moved to stratum_server.cpp

bool MiningInterface::is_valid_address(const std::string& address) const
{
    if (m_payout_manager) {
        auto validator = m_payout_manager->get_address_validator();
        if (validator) {
            auto result = validator->validate_address(address);
            return result.is_valid;
        }
    }
    
    // Basic validation - check length and format
    if (address.length() < 26 || address.length() > 62) {
        return false;
    }
    
    // Check for valid characters (alphanumeric + some special chars)
    for (char c : address) {
        if (!std::isalnum(c) && c != '1' && c != '2' && c != '3') {
            return false;
        }
    }
    
    return true;
}

double MiningInterface::calculate_share_difficulty(const std::string& job_id, const std::string& extranonce1,
                                                   const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    // Build the 80-byte block header, compute scrypt hash, and derive difficulty.
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null() || m_cached_coinb1.empty())
        return 0.0;

    // Reconstruct coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
    std::string coinbase_hex = m_cached_coinb1 + extranonce1 + extranonce2 + m_cached_coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    // Build 80-byte header (little-endian fields)
    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    // version (4 bytes LE)
    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    // prev_hash (32 bytes, internal byte order)
    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);

    // merkle_root (32 bytes)
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime (4 bytes LE — miner sends BE hex, reverse for header)
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits (4 bytes LE — GBT gives BE hex, reverse for header)
    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce (4 bytes LE — miner sends BE hex, reverse for header)
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    // Compute scrypt hash
    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    // difficulty = truediffone / pow_hash_as_double
    // truediffone = 0x00000000FFFF0000... (Litecoin difficulty-1 target)
    // For a 256-bit hash, difficulty = 2^224 / pow_hash (approximate)
    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0; // 0xFFFF * 2^208
    if (pow_hash.IsNull())
        return 0.0;

    // Convert pow_hash to a double (most significant bytes)
    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

double MiningInterface::calculate_share_difficulty(const std::string& coinb1, const std::string& coinb2,
                                                   const std::string& extranonce1, const std::string& extranonce2,
                                                   const std::string& ntime, const std::string& nonce) const
{
    std::lock_guard<std::mutex> lock(m_work_mutex);

    if (!m_work_valid || m_cached_template.is_null())
        return 0.0;

    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, m_cached_merkle_branches);

    uint32_t version = m_cached_template.value("version", 536870912U);
    uint256 prev_hash;
    prev_hash.SetHex(m_cached_template.value("previousblockhash", std::string(64, '0')));

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime, nbits, nonce: miner/GBT sends as BE hex, header needs LE bytes
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    std::string bits_hex = m_cached_template.value("bits", std::string("1d00ffff"));
    auto bits_bytes = ParseHex(bits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}

/*static*/
double MiningInterface::calculate_share_difficulty(
    const std::string& coinb1, const std::string& coinb2,
    const std::string& extranonce1, const std::string& extranonce2,
    const std::string& ntime, const std::string& nonce,
    uint32_t version, const std::string& prevhash_hex,
    const std::string& nbits_hex,
    const std::vector<std::string>& merkle_branches)
{
    // Reconstruct coinbase from per-connection parts
    std::string coinbase_hex = coinb1 + extranonce1 + extranonce2 + coinb2;
    uint256 merkle_root = reconstruct_merkle_root(coinbase_hex, merkle_branches);

    // Prevhash: must match build_block_from_stratum exactly.
    // GBT prevhash is BE display hex. SetHex converts to internal LE.
    // .data() returns LE bytes — same as block header format.
    uint256 prev_hash;
    prev_hash.SetHex(prevhash_hex);

    std::vector<unsigned char> header;
    header.reserve(80);

    header.push_back(static_cast<unsigned char>((version      ) & 0xff));
    header.push_back(static_cast<unsigned char>((version >>  8) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 16) & 0xff));
    header.push_back(static_cast<unsigned char>((version >> 24) & 0xff));

    header.insert(header.end(), prev_hash.data(), prev_hash.data() + 32);

    // Merkle root: internal byte order from reconstruct_merkle_root
    header.insert(header.end(), merkle_root.data(), merkle_root.data() + 32);

    // ntime: Stratum sends as BE hex (swap4'd from LE). Miner parses as
    // BE uint32 and writes as LE in header. We must reverse to get LE.
    auto ntime_bytes = ParseHex(ntime);
    std::reverse(ntime_bytes.begin(), ntime_bytes.end());
    header.insert(header.end(), ntime_bytes.begin(), ntime_bytes.end());

    // nbits: same — Stratum sends BE hex, header needs LE
    auto bits_bytes = ParseHex(nbits_hex);
    std::reverse(bits_bytes.begin(), bits_bytes.end());
    header.insert(header.end(), bits_bytes.begin(), bits_bytes.end());

    // nonce: same — miner sends BE hex, header needs LE
    auto nonce_bytes = ParseHex(nonce);
    std::reverse(nonce_bytes.begin(), nonce_bytes.end());
    header.insert(header.end(), nonce_bytes.begin(), nonce_bytes.end());

    if (header.size() != 80)
        return 0.0;

    // Diagnostic: dump header hex for byte-order debugging
    {
        static int dump_count = 0;
        if (dump_count < 5) {
            std::string hdr_hex;
            static const char* HX = "0123456789abcdef";
            for (auto b : header) { hdr_hex += HX[b>>4]; hdr_hex += HX[b&0xf]; }
            LOG_INFO << "[PoW-diag] header(80)=" << hdr_hex;
            LOG_INFO << "[PoW-diag] prevhash=" << prevhash_hex.substr(0,16) << "..."
                     << " ntime=" << ntime << " nbits=" << nbits_hex << " nonce=" << nonce;
            ++dump_count;
        }
    }

    char pow_hash_bytes[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), pow_hash_bytes);

    uint256 pow_hash;
    memcpy(pow_hash.begin(), pow_hash_bytes, 32);

    static const double truediffone = 26959535291011309493156476344723991336010898738574164086137773096960.0;
    if (pow_hash.IsNull())
        return 0.0;

    double hash_val = 0.0;
    for (int i = 31; i >= 0; --i)
        hash_val = hash_val * 256.0 + static_cast<double>(pow_hash.data()[i]);

    if (hash_val == 0.0)
        return 0.0;

    return truediffone / hash_val;
}
} // namespace core
