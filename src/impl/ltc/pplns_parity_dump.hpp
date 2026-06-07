#pragma once
// PPLNS parity dump emitter (debug-only, env-gated).
// Owner: ltc-doge-production-steward. Branch: ltc-doge/pplns-parity.
//
// When env C2POOL_PPLNS_DUMP names a writable path, emits line-delimited
// JSON (JSONL) capturing the exact inputs/outputs of
// get_v36_decayed_cumulative_weights() and the Step-5 compute_share_target()
// per GENTX, for byte-exact comparison against the p2pool-merged-v36
// reference dump. No effect when the env var is unset (zero prod impact).
//
// Schema (one JSON object per line):
//   {"t":"weights","start":<hex>,"max_shares":<int>,"desired_weight":<hex>,
//    "total_weight":<hex>,"total_donation_weight":<hex>,"n":<int>,
//    "weights":{<script_hex>:<weight_hex>,...}}
//   {"t":"payout","start":<hex>,"subsidy":<u64>,"donation":<u64>,
//    "outs":{<script_hex>:<u64>,...}}
//   {"t":"target","prev":<hex>,"ts":<u32>,"desired_target":<hex>,
//    "min_bits":<u32>,"max_bits":<u32>,"bits":<u32>}
// Numeric hashes/weights are GetHex() (big-endian, lowercase, fixed width:
// uint256=64, uint288=72 hex chars). Scripts are lowercase byte-hex.
// Functions are templated on the numeric types so this header has no
// include-order dependency and cannot affect any TU that does not include it.

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace ltc { namespace pplns_parity {

inline std::mutex& _mtx() { static std::mutex m; return m; }

inline std::ofstream* _stream() {
    static std::ofstream* s = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        const char* path = std::getenv("C2POOL_PPLNS_DUMP");
        if (path && *path) {
            s = new std::ofstream(path, std::ios::out | std::ios::app);
            if (s && !s->is_open()) { delete s; s = nullptr; }
        }
    }
    return s;
}

inline std::string _hex(const std::vector<unsigned char>& v) {
    static const char* d = "0123456789abcdef";
    std::string out; out.reserve(v.size() * 2);
    for (unsigned char c : v) { out.push_back(d[c >> 4]); out.push_back(d[c & 0xf]); }
    return out;
}

template <typename U256, typename U288, typename WMap>
inline void dump_weights(const U256& start, int32_t max_shares,
                         const U288& desired_weight, const WMap& weights,
                         const U288& total_weight, const U288& total_donation_weight) {
    std::ofstream* s = _stream(); if (!s) return;
    std::ostringstream o;
    o << "{\"t\":\"weights\",\"start\":\"" << start.GetHex()
      << "\",\"max_shares\":" << max_shares
      << ",\"desired_weight\":\"" << desired_weight.GetHex()
      << "\",\"total_weight\":\"" << total_weight.GetHex()
      << "\",\"total_donation_weight\":\"" << total_donation_weight.GetHex()
      << "\",\"n\":" << weights.size() << ",\"weights\":{";
    bool first = true;
    for (const auto& kv : weights) {
        if (!first) o << ","; first = false;
        o << "\"" << _hex(kv.first) << "\":\"" << kv.second.GetHex() << "\"";
    }
    o << "}}\n";
    std::lock_guard<std::mutex> lk(_mtx());
    (*s) << o.str(); s->flush();
}

template <typename U256, typename OMap>
inline void dump_payout(const U256& start, uint64_t subsidy, uint64_t donation,
                        const OMap& outs) {
    std::ofstream* s = _stream(); if (!s) return;
    std::ostringstream o;
    o << "{\"t\":\"payout\",\"start\":\"" << start.GetHex()
      << "\",\"subsidy\":" << subsidy << ",\"donation\":" << donation
      << ",\"outs\":{";
    bool first = true;
    for (const auto& kv : outs) {
        if (!first) o << ","; first = false;
        o << "\"" << _hex(kv.first) << "\":" << static_cast<uint64_t>(kv.second);
    }
    o << "}}\n";
    std::lock_guard<std::mutex> lk(_mtx());
    (*s) << o.str(); s->flush();
}

template <typename U256>
inline void dump_target(const U256& prev, uint32_t ts, const U256& desired_target,
                        uint32_t min_bits, uint32_t max_bits, uint32_t bits) {
    std::ofstream* s = _stream(); if (!s) return;
    std::ostringstream o;
    o << "{\"t\":\"target\",\"prev\":\"" << prev.GetHex()
      << "\",\"ts\":" << ts
      << ",\"desired_target\":\"" << desired_target.GetHex()
      << "\",\"min_bits\":" << min_bits
      << ",\"max_bits\":" << max_bits
      << ",\"bits\":" << bits << "}}\n";
    std::lock_guard<std::mutex> lk(_mtx());
    (*s) << o.str(); s->flush();
}

}} // namespace ltc::pplns_parity
