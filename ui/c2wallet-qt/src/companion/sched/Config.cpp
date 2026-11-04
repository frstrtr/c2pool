// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Config.hpp"

namespace c2w::companion::sched {

bool validate_node_url(const std::string& url, std::string& why)
{
    static const std::string scheme = "http://";
    const std::string loopback_rule =
        "node.url host must be 127.0.0.1, ::1 or localhost (reach a remote node through ssh -L "
        "18080:127.0.0.1:8080 host and use http://127.0.0.1:18080)";
    if (url.rfind(scheme, 0) != 0) {
        why = "node.url '" + url + "' must start with http:// (loopback only; TLS is not used on loopback)";
        return false;
    }
    std::string rest = url.substr(scheme.size());
    const size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        if (rest.substr(slash) != "/") {
            why = "node.url '" + url + "' must not carry a path";
            return false;
        }
        rest = rest.substr(0, slash);
    }
    if (rest.find('@') != std::string::npos || rest.find('?') != std::string::npos ||
        rest.find('#') != std::string::npos) {
        why = "node.url '" + url + "' must not carry user info, a query or a fragment";
        return false;
    }
    std::string host, port;
    if (!rest.empty() && rest[0] == '[') {
        const size_t close = rest.find(']');
        if (close == std::string::npos) {
            why = "node.url '" + url + "' has an unterminated IPv6 literal";
            return false;
        }
        host = rest.substr(0, close + 1);
        const std::string after = rest.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':') {
                why = "node.url '" + url + "' is malformed after the IPv6 literal";
                return false;
            }
            port = after.substr(1);
        }
    } else {
        const size_t colon = rest.find(':');
        host = rest.substr(0, colon);
        if (colon != std::string::npos) port = rest.substr(colon + 1);
    }
    if (host != "127.0.0.1" && host != "[::1]" && host != "localhost") {
        why = loopback_rule + "; got '" + host + "'";
        return false;
    }
    if (!port.empty() || rest.find(':') != std::string::npos) {
        if (port.empty() || port.size() > 5) {
            why = "node.url '" + url + "' has an invalid port";
            return false;
        }
        long v = 0;
        for (char c : port) {
            if (c < '0' || c > '9') {
                why = "node.url '" + url + "' has an invalid port";
                return false;
            }
            v = v * 10 + (c - '0');
        }
        if (v < 1 || v > 65535) {
            why = "node.url '" + url + "' port out of range";
            return false;
        }
    }
    return true;
}

bool parse_cli_overrides(const std::vector<std::string>& args, CliOverrides& out, std::string& why)
{
    out = CliOverrides{};
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];
        if (a == "--token" || a.rfind("--token=", 0) == 0) {
            why = "usage: there is no --token VALUE (argv is world-readable); put the token in a 0600 file "
                  "and pass --token-file PATH";
            return false;
        }
        std::string name, value;
        bool known = false;
        for (const char* opt : {"--node-url", "--token-file", "--queue", "--poll-sec"}) {
            const std::string o = opt;
            if (a == o) {
                if (i + 1 >= args.size()) {
                    why = "usage: " + o + " needs a value";
                    return false;
                }
                name = o;
                value = args[++i];
                known = true;
                break;
            }
            if (a.rfind(o + "=", 0) == 0) {
                name = o;
                value = a.substr(o.size() + 1);
                known = true;
                break;
            }
        }
        if (!known) {
            out.rest.push_back(a);
            continue;
        }
        if (name == "--node-url") {
            if (!validate_node_url(value, why)) return false;
            out.node_url = value;
        } else if (name == "--token-file") {
            if (value.empty()) {
                why = "usage: --token-file needs a path";
                return false;
            }
            out.token_file = value;
        } else if (name == "--queue") {
            if (value.empty()) {
                why = "usage: --queue needs a path";
                return false;
            }
            out.queue = value;
        } else {
            int64_t v = 0;
            if (value.empty() || value.size() > 6) {
                why = "usage: --poll-sec must be 1..3600";
                return false;
            }
            for (char c : value) {
                if (c < '0' || c > '9') {
                    why = "usage: --poll-sec must be 1..3600";
                    return false;
                }
                v = v * 10 + (c - '0');
            }
            if (v < 1 || v > 3600) {
                why = "usage: --poll-sec must be 1..3600";
                return false;
            }
            out.poll_sec = v;
        }
    }
    return true;
}

} // namespace c2w::companion::sched
