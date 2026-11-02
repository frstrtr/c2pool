// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Shared fixture for the DASH full-UTXO-set KATs (S2): a synthetic chain of
// linked DASH blocks, and a full set built the way the node builds it — a
// dumptxoutset-layout file written by core::coin::SnapshotWriter, a
// digest-gated pin, import_dash_utxo_snapshot into a temp LevelDB, and
// open_dash_full_utxo_set (the S2-2 rule).

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/utxo_lane.hpp>
#include <impl/dash/coin/utxo_snapshot_import.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/coin/utxo_snapshot.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <unistd.h>

namespace dash_utxo_full {

using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using ::core::coin::Coin;
using ::core::coin::Outpoint;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

class TempDir {
public:
    explicit TempDir(const std::string& tag)
    {
        static std::atomic<int> counter{0};
        m_path = (std::filesystem::temp_directory_path() /
                  ("c2pool-s2-" + tag + "-" + std::to_string(static_cast<long>(::getpid())) + "-" +
                   std::to_string(counter++)))
                     .string();
        std::filesystem::remove_all(m_path);
        std::filesystem::create_directories(m_path);
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(m_path, ec);
    }
    std::string sub(const std::string& n) const { return (std::filesystem::path(m_path) / n).string(); }

private:
    std::string m_path;
};

inline OPScript script(const std::vector<uint8_t>& v) { return OPScript(v.data(), v.data() + v.size()); }

inline std::vector<uint8_t> p2pkh(uint8_t tag)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, tag);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

inline uint256 fake_hash(uint32_t n)
{
    uint256 h;
    for (int i = 0; i < 8; ++i) std::memcpy(h.data() + 4 * i, &n, 4);
    h.data()[31] = 0x5a;
    return h;
}

inline TxOut out(int64_t value, const std::vector<uint8_t>& spk)
{
    TxOut o;
    o.value = value;
    o.scriptPubKey = script(spk);
    return o;
}

inline TxIn in(const Outpoint& op)
{
    TxIn i;
    i.prevout.hash = op.txid;
    i.prevout.index = op.index;
    i.sequence = 0xffffffffu;
    return i;
}

inline MutableTransaction coinbase(int64_t value, uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = 0xc0b00000u ^ salt;
    tx.vout.push_back(out(value, p2pkh(static_cast<uint8_t>(salt))));
    return tx;
}

inline MutableTransaction spend(const std::vector<Outpoint>& ins, const std::vector<TxOut>& outs, uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    for (const auto& op : ins) tx.vin.push_back(in(op));
    tx.vout = outs;
    return tx;
}

inline BlockType block(const uint256& prev, std::vector<MutableTransaction> txs, uint32_t salt)
{
    BlockType b;
    b.m_previous_block = prev;
    b.m_nonce = salt;
    b.m_txs = std::move(txs);
    return b;
}

inline uint256 hash_of(const BlockType& b)
{
    auto p = ::pack(static_cast<const dash::coin::BlockHeaderType&>(b));
    return dash::crypto::hash_x11(p.get_span());
}

/// The header chain the lane is judged against.
struct Chain {
    std::map<uint32_t, uint256> hashes;
    dash::coin::UtxoLane::HashAtFn fn()
    {
        return [this](uint32_t h) -> std::optional<uint256> {
            auto it = hashes.find(h);
            if (it == hashes.end()) return std::nullopt;
            return it->second;
        };
    }
};

struct SnapCoin {
    Outpoint op;
    Coin coin;
};

/// Write `coins` (any order) as a snapshot file, pin it for `network`, and
/// return the pin as the node loads it (re-parsed, digest-gated).
inline dash::coin::DashUtxoPin make_pinned_snapshot(const std::string& file, std::vector<SnapCoin> coins,
                                                    uint32_t base_height, const uint256& base_hash,
                                                    const std::string& network = "regtest",
                                                    const std::string& coin = "dash")
{
    std::sort(coins.begin(), coins.end(), [](const SnapCoin& a, const SnapCoin& b) {
        const int c = std::memcmp(a.op.txid.data(), b.op.txid.data(), 32);
        return c != 0 ? c < 0 : a.op.index < b.op.index;
    });
    ::core::coin::SnapshotWriter w(file);
    EXPECT_TRUE(w.begin(::core::coin::SnapshotMetadata{base_hash, coins.size()}));
    for (const auto& c : coins) EXPECT_TRUE(w.append(c.op, c.coin)) << w.refusal() << " " << w.detail();
    EXPECT_TRUE(w.finish()) << w.refusal() << " " << w.detail();
    const auto scan = ::core::coin::scan_utxo_snapshot({file});
    EXPECT_TRUE(scan.ok) << scan.refusal << " " << scan.detail;
    ::core::coin::SnapshotPin pin;
    pin.coin = coin;
    pin.network = network;
    pin.height = base_height;
    pin.blockhash = base_hash;
    pin.coins = coins.size();
    pin.muhash = scan.hashes.muhash;
    pin.hash_serialized_2 = scan.hashes.hash_serialized_2;
    for (const auto& p : scan.parts) pin.parts.push_back({p.bytes, p.sha256});
    pin.sources = "kat";
    return dash::coin::check_dash_utxo_pin(::core::coin::render_snapshot_pin(pin), network, "kat");
}

/// A full set at `base_height` / `base_hash` holding `coins`, imported and
/// opened into `lane` exactly as the node does it.
inline bool open_full_set(dash::coin::UtxoLane& lane, const TempDir& tmp, std::vector<SnapCoin> coins,
                          uint32_t base_height, const uint256& base_hash)
{
    const auto pin = make_pinned_snapshot(tmp.sub("snap.dat"), std::move(coins), base_height, base_hash);
    EXPECT_TRUE(pin.pin) << pin.refusal << " " << pin.detail;
    dash::coin::DashUtxoImportConfig cfg;
    cfg.network = "regtest";
    const auto r = dash::coin::import_dash_utxo_snapshot({tmp.sub("snap.dat")}, tmp.sub("full"), pin, cfg);
    EXPECT_TRUE(r.ok) << r.refusal << " " << r.detail;
    if (!r.ok) return false;
    auto full = dash::coin::open_dash_full_utxo_set(tmp.sub("full"), "regtest", 0);
    EXPECT_TRUE(full.ok()) << full.refusal << " " << full.detail;
    if (!full.ok()) return false;
    return lane.open_full(std::move(full.db), full.assumed, 0);
}

inline SnapCoin snap_coin(const uint256& txid, uint32_t n, int64_t value, uint8_t tag, uint32_t height = 500,
                          bool cb = false)
{
    SnapCoin c;
    c.op = Outpoint(txid, n);
    c.coin = Coin(value, script(p2pkh(tag)), height, cb);
    return c;
}

} // namespace dash_utxo_full
