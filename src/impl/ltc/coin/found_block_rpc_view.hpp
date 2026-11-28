// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Found-block verdict for a parent (LTC) block in RPC mode
/// (--no-embedded-ltc). The node has no embedded header chain then, so the
/// verdict (ltc::coin::found_block::parent_verdict, the same rule as the
/// embedded node's) reads litecoind's best chain instead: getblockcount for
/// the tip, getblockhash for the block at a height, getblockheader for a
/// known block's height (on any branch). A call that fails (daemon down, -5
/// "Block not found", -8 "Block height out of range") reads as "not known".
/// When the daemon cannot tell, the verdict stays pending (0). It is never
/// confirmed just because the daemon answered.
///
/// TELEMETRY ONLY, like every found-block verdict: it never gates a submit,
/// a relay or a payout.
///
/// The calls go in as functions so the KAT
/// (src/impl/ltc/test/found_block_rpc_view_test.cpp) can stand in for
/// litecoind; main_ltc.cpp binds them to NodeRPC.

#include <core/uint256.hpp>
#include <impl/ltc/coin/found_block_verify.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ltc {
namespace coin {
namespace found_block {

/// The daemon calls a verdict needs, each returning the JSON-RPC result (or
/// throwing on an RPC/transport error).
struct RpcLookups {
    std::function<nlohmann::json()> getblockcount;
    std::function<nlohmann::json(uint32_t)> getblockhash;
    std::function<nlohmann::json(const uint256&)> getblockheader;
};

/// A ChainView over the daemon's best chain. The tip is read once per view,
/// so one verdict sees one tip.
inline ChainView rpc_chain_view(RpcLookups rpc)
{
    auto calls = std::make_shared<RpcLookups>(std::move(rpc));
    auto tip = std::make_shared<std::optional<std::optional<uint32_t>>>();
    auto read_tip = [calls, tip]() -> std::optional<uint32_t> {
        if (!tip->has_value()) {
            std::optional<uint32_t> t;
            try {
                const auto r = calls->getblockcount();
                if (r.is_number_integer() && r.get<int64_t>() >= 0)
                    t = static_cast<uint32_t>(r.get<int64_t>());
            } catch (...) {}
            *tip = t;
        }
        return **tip;
    };
    ChainView v;
    v.height_of = [calls](const uint256& h) -> std::optional<uint32_t> {
        try {
            const auto r = calls->getblockheader(h);
            if (r.is_object() && r.contains("height") && r["height"].is_number_integer()
                && r["height"].get<int64_t>() >= 0)
                return static_cast<uint32_t>(r["height"].get<int64_t>());
        } catch (...) {}
        return std::nullopt;
    };
    v.hash_at = [calls](uint32_t height) -> std::optional<uint256> {
        try {
            const auto r = calls->getblockhash(height);
            if (r.is_string()) {
                uint256 h;
                h.SetHex(r.get<std::string>());
                return h;
            }
        } catch (...) {}
        return std::nullopt;
    };
    v.tip_height = [read_tip]() { return read_tip().value_or(0); };
    v.has_tip = [read_tip]() { return read_tip().has_value(); };
    return v;
}

/// The found-block row a verdict is asked for, as the parent verifier sees
/// it. `parent` is false when no row has the hash or the row is not of this
/// node's own chain: a merged (DOGE) row whose chain has no verifier of its
/// own falls back to the parent one (MiningInterface::verify_found_block), and
/// litecoind cannot judge it. Asked anyway, a DOGE block 6 deep under an LTC
/// height reads as an LTC orphan.
struct ParentRow {
    bool parent = false;
    std::optional<uint32_t> height;   // its recorded height, if known
};

template <class Rows, class IsPrimary>
ParentRow find_parent_row(const Rows& rows, const std::string& hash_hex, IsPrimary is_primary)
{
    ParentRow r;
    for (const auto& b : rows) {
        if (b.hash != hash_hex)
            continue;
        if (!is_primary(b))
            return ParentRow{};
        r.parent = true;
        if (b.height > 0)
            r.height = static_cast<uint32_t>(b.height);
        return r;
    }
    return r;
}

/// >0 confirmed (confirmations), <0 orphaned, 0 pending.
inline int rpc_parent_verdict(RpcLookups rpc, const uint256& hash,
                              std::optional<uint32_t> found_height)
{
    return parent_verdict(rpc_chain_view(std::move(rpc)), hash, found_height);
}

} // namespace found_block
} // namespace coin
} // namespace ltc
