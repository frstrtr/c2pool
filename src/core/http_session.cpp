// SPDX-License-Identifier: AGPL-3.0-or-later
//
// http_session.cpp — dashboard / REST / SSE presentation surface.
//
// Extracted verbatim from web_server.cpp as the first mechanical slice of
// issue #735 (source-dissolution of the web surface out of the mining
// engine). This translation unit holds ONLY the HTTP request router
// (core::HttpSession) and its URL/validation helpers. It is a pure consumer
// of core::MiningInterface's public rest_*() accessors — it produces no
// mining state of its own. Splitting it into its own TU narrows the seam
// between the miner-facing engine (MiningInterface + StratumServer, which
// stratum_server.cpp depends on) and the operator-facing dashboard, without
// any behaviour change: the code below is byte-identical to its former home.
//
// See docs/ (frstrtr/the) for the full dissolution plan.

#include "web_server.hpp"
#include "filesystem.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>

namespace core {


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
    response.set(http::field::server, mining_interface_->get_pool_version());
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

    // Admin endpoints accept both GET and POST so CLI tools can POST
    // mutations without falling through to the JSON-RPC handler.
    // Covers /api/admin/pool/* AND /api/admin/coin/*.
    bool is_admin_path = std::string(request_.target()).substr(0, 11) == "/api/admin/";

    try {
        std::string response_body;

        if (request_.method() == http::verb::options) {
            // Handle CORS preflight
            response_body = "";
        }
        else if (request_.method() == http::verb::get
                 || (is_admin_path && request_.method() == http::verb::post)) {
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
            else if (target == "/sharechain/window") {
                // Layer 1+2: cached response + ETag/304
                auto client_ip = socket_.remote_endpoint().address().to_string();
                if (!mining_interface_->rate_check(client_ip, 4)) {  // max 4/min
                    response.result(http::status::too_many_requests);
                    response_body = R"({"error":"Rate limited"})";
                } else {
                    auto [body, etag] = mining_interface_->get_cached_window_response();
                    std::string client_etag;
                    auto it = request_.find(http::field::if_none_match);
                    if (it != request_.end()) client_etag = std::string(it->value());
                    if (!etag.empty() && client_etag == "\"" + etag + "\"") {
                        response.result(http::status::not_modified);
                        response_body = "";
                    } else {
                        response.set(http::field::etag, "\"" + etag + "\"");
                        response.set(http::field::cache_control, "no-cache");
                        response_body = body;
                    }
                }
            }
            else if (target == "/sharechain/tip")
                rest_result = mining_interface_->rest_sharechain_tip();
            else if (target == "/sharechain/delta") {
                auto client_ip = socket_.remote_endpoint().address().to_string();
                if (!mining_interface_->rate_check(client_ip, 30)) {  // max 30/min
                    response.result(http::status::too_many_requests);
                    response_body = R"({"error":"Rate limited"})";
                } else {
                    rest_result = mining_interface_->rest_sharechain_delta(getQueryParam("since"));
                }
            }
            else if (target == "/sharechain/stream") {
                // Layer 4: SSE — send headers and keep connection open
                auto client_ip = socket_.remote_endpoint().address().to_string();
                if (!mining_interface_->rate_check(client_ip, 2)) {  // max 2 SSE connections/min per IP
                    response.result(http::status::too_many_requests);
                    response_body = R"({"error":"Rate limited"})";
                } else {
                    // Send SSE headers manually, then register for push
                    std::string sse_headers =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/event-stream\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Connection: keep-alive\r\n"
                        "X-Accel-Buffering: no\r\n"
                        "\r\n"
                        "data: {\"connected\":true}\n\n";
                    auto buf = std::make_shared<std::string>(sse_headers);
                    auto self = shared_from_this();
                    auto sock_ptr = std::make_shared<tcp::socket>(std::move(socket_));
                    boost::asio::async_write(*sock_ptr, boost::asio::buffer(*buf),
                        [buf, sock_ptr, mi = mining_interface_](beast::error_code ec, std::size_t) {
                            if (!ec) mi->sse_register(sock_ptr);
                        });
                    return;  // Don't close connection
                }
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
            else if (target == "/web/sync_status")
                rest_result = mining_interface_->rest_sync_status();
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
            else if (target == "/api/node_topology")
                rest_result = mining_interface_->rest_node_topology();
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
            else if (target == "/pplns/current")
                rest_result = mining_interface_->rest_pplns_current();
            else if (target.rfind("/pplns/miner/", 0) == 0) {
                // /pplns/miner/<address> — extract address from path.
                std::string addr = target.substr(std::string("/pplns/miner/").size());
                // URL-decode (spec §5.2 "MUST be URL-encoded by the client").
                std::string decoded;
                decoded.reserve(addr.size());
                for (size_t i = 0; i < addr.size(); ++i) {
                    if (addr[i] == '%' && i + 2 < addr.size()) {
                        auto hex = addr.substr(i + 1, 2);
                        try {
                            decoded.push_back(static_cast<char>(
                                std::stoi(hex, nullptr, 16)));
                            i += 2;
                        } catch (...) {
                            decoded.push_back(addr[i]);
                        }
                    } else if (addr[i] == '+') {
                        decoded.push_back(' ');
                    } else {
                        decoded.push_back(addr[i]);
                    }
                }
                rest_result = mining_interface_->rest_pplns_miner(decoded);
            }
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

            // ── Coin peer sharing (public, rate-limited) ──────────────
            else if (target == "/api/coin_peers") {
                auto remote_ip = socket_.remote_endpoint().address().to_string();
                auto result = mining_interface_->rest_coin_peers(remote_ip);
                if (result.contains("error")) {
                    response.result(http::status::too_many_requests);
                    response.set(http::field::retry_after, "10");
                }
                response.body() = result.dump();
                response.prepare_payload();
                send_response(std::move(response));
                return;
            }

            else {
                // ── Admin API endpoints (loopback-only) ───────────────────
                if (target.substr(0, 16) == "/api/admin/pool/") {
                    auto remote_addr = socket_.remote_endpoint().address();
                    if (!remote_addr.is_loopback()) {
                        response.result(http::status::forbidden);
                        response.body() = R"({"error":"Admin API is local-only"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }
                    if (!mining_interface_->has_admin_fns()) {
                        response.result(http::status::not_found);
                        response.body() = R"({"error":"Admin API not enabled"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }

                    std::string ep = target.substr(16); // after "/api/admin/pool/"
                    // strip query string
                    auto qpos = ep.find('?');
                    if (qpos != std::string::npos) ep = ep.substr(0, qpos);

                    auto parse_host_port = [&](uint16_t& port_out) -> std::string {
                        std::string host = getQueryParam("host");
                        std::string ip_q = getQueryParam("ip");
                        port_out = 0;
                        if (!host.empty()) {
                            auto colon = host.rfind(':');
                            if (colon != std::string::npos) {
                                try { port_out = static_cast<uint16_t>(std::stoul(host.substr(colon + 1))); } catch (...) {}
                                host = host.substr(0, colon);
                            }
                        } else {
                            host = ip_q;
                        }
                        std::string port_q = getQueryParam("port");
                        if (!port_q.empty()) {
                            try { port_out = static_cast<uint16_t>(std::stoul(port_q)); } catch (...) {}
                        }
                        return host;
                    };

                    if (ep == "bans/list") {
                        rest_result = mining_interface_->call_admin_list_bans();
                    } else if (ep == "bans/add") {
                        std::string ip = getQueryParam("ip");
                        int dur = 0;
                        try { auto d = getQueryParam("duration"); if (!d.empty()) dur = std::stoi(d); } catch (...) {}
                        rest_result = mining_interface_->call_admin_ban_ip(ip, dur);
                    } else if (ep == "bans/remove") {
                        std::string ip = getQueryParam("ip");
                        rest_result = mining_interface_->call_admin_unban_ip(ip);
                    } else if (ep == "whitelist/list") {
                        rest_result = mining_interface_->call_admin_list_whitelist();
                    } else if (ep == "whitelist/add") {
                        uint16_t p = 0;
                        std::string h = parse_host_port(p);
                        rest_result = mining_interface_->call_admin_whitelist_add(h, p);
                    } else if (ep == "whitelist/remove") {
                        uint16_t p = 0;
                        std::string h = parse_host_port(p);
                        rest_result = mining_interface_->call_admin_whitelist_remove(h, p);
                    } else if (ep == "peers/list") {
                        rest_result = mining_interface_->call_admin_list_peers();
                    } else if (ep == "peers/drop") {
                        std::string ip = getQueryParam("ip");
                        rest_result = mining_interface_->call_admin_drop_peer(ip);
                    } else if (ep == "peers/dial") {
                        uint16_t p = 0;
                        std::string h = parse_host_port(p);
                        rest_result = mining_interface_->call_admin_dial_peer(h, p);
                    } else {
                        rest_result = nlohmann::json{{"ok", false}, {"error", "Unknown admin endpoint"}};
                    }
                }
                // ── Admin API: embedded-coin peer management ──────────────
                else if (target.substr(0, 16) == "/api/admin/coin/") {
                    auto remote_addr = socket_.remote_endpoint().address();
                    if (!remote_addr.is_loopback()) {
                        response.result(http::status::forbidden);
                        response.body() = R"({"error":"Admin API is local-only"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }
                    if (!mining_interface_->has_admin_coin_fns()) {
                        response.result(http::status::not_found);
                        response.body() = R"({"error":"Coin admin API not enabled"})";
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }

                    std::string ep = target.substr(16); // after "/api/admin/coin/"
                    auto qpos = ep.find('?');
                    if (qpos != std::string::npos) ep = ep.substr(0, qpos);

                    std::string chain = getQueryParam("chain");
                    if (chain.empty()) chain = mining_interface_->primary_chain_key();

                    if (ep == "peers/list") {
                        rest_result = mining_interface_->call_admin_coin_list_peers(chain);
                    } else if (ep == "peer/add") {
                        std::string host = getQueryParam("host");
                        uint16_t port = 0;
                        // Host may be "A.B.C.D:PORT" (combined) OR "A.B.C.D" with separate ?port=
                        if (!host.empty()) {
                            auto colon = host.rfind(':');
                            if (colon != std::string::npos) {
                                try { port = static_cast<uint16_t>(std::stoul(host.substr(colon + 1))); } catch (...) {}
                                host = host.substr(0, colon);
                            }
                        }
                        std::string port_q = getQueryParam("port");
                        if (!port_q.empty()) {
                            try { port = static_cast<uint16_t>(std::stoul(port_q)); } catch (...) {}
                        }
                        rest_result = mining_interface_->call_admin_coin_add_peer(chain, host, port);
                    } else {
                        rest_result = nlohmann::json{{"ok", false}, {"error", "Unknown coin admin endpoint"}};
                    }
                }
                else
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
                    if (chain.empty()) chain = mining_interface_->primary_chain_key();

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
                    if (file_path == "/" || file_path.empty())
                        file_path = mining_interface_->is_node_ready()
                            ? "/dashboard.html" : "/loading.html";

                    // During startup, redirect all HTML pages to loading.html
                    // (except loading.html itself). Only loading.html + sync_status
                    // + currency_info work during early startup.
                    if (file_path != "/loading.html" && file_path.find(".html") != std::string::npos) {
                        bool node_ready = mining_interface_->is_node_ready();
                        if (!node_ready) {
                            response.result(http::status::temporary_redirect);
                            response.set(http::field::location, "/loading.html");
                            response.body() = "";
                            response.prepare_payload();
                            send_response(std::move(response));
                            return;
                        }
                    }

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
                        else if (ext == ".js" || ext == ".mjs") mime = "application/javascript; charset=utf-8";
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

                        // Explorer nav link injection removed — each HTML page has
                        // client-side JS that checks currency_info.explorer_enabled
                        // and injects the link dynamically. Server-side injection was
                        // fragile (depended on exact ">Classic</a>" text) and caused
                        // duplicate buttons on pages that had both mechanisms.

                        response.set(http::field::content_type, mime);
                        response.set(http::field::cache_control, "public, max-age=3600");
                        response.body() = std::move(contents);
                        response.prepare_payload();
                        send_response(std::move(response));
                        return;
                    }

                    // Dashboard IS configured, the request matched no REST
                    // endpoint above, and no such on-disk asset exists -> a real
                    // 404. Previously this fell through to getinfo() below, so
                    // unknown paths (explorer.html, blocks.html, typos, scanner
                    // probes) leaked the node-info JSON instead of Not Found.
                    response.result(http::status::not_found);
                    response.set(http::field::content_type, "text/plain; charset=utf-8");
                    response.body() = "404 Not Found";
                    response.prepare_payload();
                    send_response(std::move(response));
                    return;
                }
                // Fallback to getinfo JSON (API-only mode: no --dashboard-dir set)
                rest_result = mining_interface_->getinfo();
                }  // end static file serving else
            }  // end explorer/static dispatch

            if (!rest_result.is_null())
                response_body = rest_result.dump();
        }
        else if (request_.method() == http::verb::post) {
            // Handle JSON-RPC POST request.
            // Accept both 1.0 and 2.0 — upgrade 1.0 to 2.0 for the library.
            std::string request_body = request_.body();
            {
                auto pos = request_body.find("\"1.0\"");
                if (pos != std::string::npos) {
                    auto ctx = request_body.rfind("jsonrpc", pos);
                    if (ctx != std::string::npos && pos - ctx < 15)
                        request_body.replace(pos, 5, "\"2.0\"");
                }
            }

            response_body = mining_interface_->HandleRequest(request_body);
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

} // namespace core
