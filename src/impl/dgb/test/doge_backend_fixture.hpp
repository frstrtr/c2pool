// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// A fake embedded DOGE aux backend for the DGB merged-mining KATs: the
// embedded backend's shape (the work's block hash is its tip), as
// src/core/test/web_server_merged_drop_test.cpp fakes it.

#include <c2pool/merged/merged_mining.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <vector>

namespace dgb_test {

using c2pool::merged::MergedMiningManager;

inline constexpr uint32_t kDogeChainId = 98;

struct DogeBackend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
    DogeBackend()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = kDogeChainId;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = kDogeChainId;
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target.SetHex(std::string(8, '0') + std::string(56, 'f'));
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", 5'000'001}, {"bits", "1a01d2c3"},
            {"curtime", 1793210000}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string&) override { return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

// Registers the DOGE backend. The config is read through a raw pointer kept
// before the move: `add_chain(backend->cfg, std::move(backend))` may move the
// unique_ptr first (unspecified argument order) and dereference null.
inline void add_doge(MergedMiningManager& mm)
{
    auto backend = std::make_unique<DogeBackend>();
    auto* raw = backend.get();
    mm.add_chain(raw->cfg, std::move(backend));
}

} // namespace dgb_test
