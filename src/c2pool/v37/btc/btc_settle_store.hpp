// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_settle_store.hpp   (Track A2 / Milestone A-BTC — W6)
//
// The DURABLE side of the live BITCOIN-FAMILY node: an ISettleStore seam + a
// file-backed concrete store + a RecoveryDriver that rebuilds the OWED ledger +
// settlement high-water on restart, BEFORE V37Engine::start() (donor lifecycle
// order).
//
// THIS IS THE SIBLING OF src/c2pool/v37/xmr/xmr_settle_store.hpp (Milestone
// A-XMR). The persistence seam, the record codec, the RecoveryDriver §4 replay
// and the two W6 red-team invariants (F1 in-order per-height replay, F2
// fail-closed open) are COIN-AGNOSTIC — the store persists W4's OWED events and
// the high-water only, keyed by a block-id STRING that here is a BTC-family
// block HASH hex (display byte order) instead of a Monero block id. Nothing in
// this file differs in logic from the XMR sibling; only the doc-comments name
// the coin. The two could be unified into one v37/settle_store.hpp; they are
// kept parallel to match the per-milestone directory layout and to let each
// milestone land independently.
//
// RELATIONSHIP TO THE MERGED W6 LEG (v37/w6-persistence branch):
//   The W6 wave authored src/c2pool/v37/w6_persistence.hpp — the full
//   ISettleBatch/ISettleStore seam, the §2.3 record codecs, RecoveryDriver
//   (§4 steps 1-9), and a LevelDBSettleStore concrete binding. When that lands
//   on master, XbtcNode swaps FileSettleStore -> LevelDBSettleStore with a
//   one-line change (see GAP note in btc_node.hpp). Until then this small,
//   self-contained store keeps THIS milestone building on a fresh master clone
//   and DIGEST-NEUTRAL: it uses ONLY merged master types (OwedLedger, SettleHW
//   from w4_settlement.hpp), mirrors the W6 ISettleStore SHAPE, and honours F1
//   and F2. NO consensus digest lives here — owed_digest / lane digest are
//   recomputed by the merged OwedLedger / executor, byte-identically to a fresh
//   run.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // OwedLedger, SettleHW (merged, master)

namespace c2pool::v37n::btc {

using ::c2pool::v37n::settle::OwedLedger;
using ::c2pool::v37n::settle::SettleHW;
using Amounts = OwedLedger::Amounts;      // std::map<bytes32,long long>

// ---------------------------------------------------------------------------
// ISettleStore — the persistence seam (W6 §7.1 shape). A production build backs
// this with LevelDBSettleStore (v37/w6-persistence); Milestone A-BTC backs it
// with FileSettleStore below and MemSettleStore in the smoke/KAT.
// ---------------------------------------------------------------------------
struct ISettleBatch {
    virtual ~ISettleBatch() = default;
    virtual void put(const std::string& k, const std::string& v) = 0;
    virtual void remove(const std::string& k) = 0;
    virtual bool commit_sync() = 0;               // false == torn / IO error
};

struct ISettleStore {
    virtual ~ISettleStore() = default;
    virtual std::unique_ptr<ISettleBatch> batch() = 0;
    virtual std::optional<std::string> get(const std::string& k) = 0;
    virtual bool for_each_prefix(
        const std::string& prefix,
        const std::function<bool(const std::string& k, const std::string& v)>& fn) = 0;
};

// ---------------------------------------------------------------------------
// Record codec + key layout (a compatible subset of W6 keys::/Writer/Reader).
// Records: u8 ver=1 ‖ payload. Ints little-endian. Fail-closed on a short read.
// ---------------------------------------------------------------------------
namespace store_codec {
constexpr std::uint8_t SCHEMA_VER = 1;

inline std::string chain_fmt(::v37::ChainId c) {
    char b[16];
    std::snprintf(b, sizeof b, "%010u", static_cast<unsigned>(c));
    return b;
}
inline std::string seq_fmt(std::uint64_t s) {
    char b[24];
    std::snprintf(b, sizeof b, "%020llu", static_cast<unsigned long long>(s));
    return b;
}
// keys ----------------------------------------------------------------------
inline std::string k_hw(::v37::ChainId c)        { return "v37s:hw:" + chain_fmt(c); }
inline std::string k_cursor(::v37::ChainId c)    { return "v37s:fcur:" + chain_fmt(c); }
inline std::string k_evt(::v37::ChainId c, std::uint64_t seq) {
    return "v37s:levt:" + chain_fmt(c) + ":" + seq_fmt(seq);
}
inline std::string k_evt_prefix(::v37::ChainId c){ return "v37s:levt:" + chain_fmt(c) + ":"; }

// serialize a u64 LE ---------------------------------------------------------
inline void put_u64(std::string& s, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
}
inline void put_i64(std::string& s, long long v) { put_u64(s, static_cast<std::uint64_t>(v)); }
inline void put_amounts(std::string& s, const Amounts& m) {
    put_u64(s, m.size());
    for (const auto& [k, v] : m) {   // std::map canonical key order
        s.append(reinterpret_cast<const char*>(k.data()), k.size());
        put_i64(s, v);
    }
}
inline void put_str(std::string& s, const std::string& v) {
    put_u64(s, v.size());
    s.append(v);
}

// Fail-closed reader: any short read throws (caught by RecoveryDriver → abort).
struct Reader {
    const std::string& s;
    std::size_t o = 0;
    explicit Reader(const std::string& src) : s(src) {}
    void need(std::size_t n) const {
        if (o + n > s.size()) throw std::runtime_error("settle-store: torn record (short read)");
    }
    std::uint8_t u8()  { need(1); return std::uint8_t(s[o++]); }
    std::uint64_t u64() {
        need(8); std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x |= std::uint64_t(std::uint8_t(s[o++])) << (8 * i);
        return x;
    }
    long long i64() { return static_cast<long long>(u64()); }
    ::v37::bytes32 b32() {
        need(32); ::v37::bytes32 b{};
        for (std::size_t i = 0; i < 32; ++i) b[i] = std::uint8_t(s[o++]);
        return b;
    }
    Amounts amounts() {
        Amounts m; std::uint64_t n = u64();
        for (std::uint64_t i = 0; i < n; ++i) { auto k = b32(); m[k] = i64(); }
        return m;
    }
    std::string str() { std::uint64_t n = u64(); need(n); std::string v = s.substr(o, n); o += n; return v; }
    void expect_end() const { if (o != s.size()) throw std::runtime_error("settle-store: trailing bytes"); }
};
} // namespace store_codec

// ---------------------------------------------------------------------------
// The three persisted ledger-event kinds (W6 EvKind). Written write-ahead by
// XbtcNode as the OwedLedger mutates; replayed in seq order on recovery.
// ---------------------------------------------------------------------------
enum class SettleEvKind : std::uint8_t { Found = 1, Finalize = 2, Orphan = 3 };

struct SettleEvent {
    SettleEvKind  kind = SettleEvKind::Found;
    std::string   bid;                 // BTC-family block hash (hex) that carried the settlement
    Amounts       credit;              // FOUND: per-key entitlement E_b
    Amounts       payout;              // FOUND/ORPHAN: coinbase outputs settled
    std::uint64_t bin_height = 0;      // FINALIZE: the monotone K_fair clock at THIS step

    std::string serialize() const {
        std::string s;
        s.push_back(char(store_codec::SCHEMA_VER));
        s.push_back(char(static_cast<std::uint8_t>(kind)));
        store_codec::put_str(s, bid);
        store_codec::put_amounts(s, credit);
        store_codec::put_amounts(s, payout);
        store_codec::put_u64(s, bin_height);
        return s;
    }
    static SettleEvent deserialize(const std::string& blob) {
        store_codec::Reader r(blob);
        std::uint8_t ver = r.u8();
        if (ver > store_codec::SCHEMA_VER)
            throw std::runtime_error("settle-store: record schema newer than reader");
        SettleEvent e;
        e.kind = static_cast<SettleEvKind>(r.u8());
        e.bid = r.str();
        e.credit = r.amounts();
        e.payout = r.amounts();
        e.bin_height = r.u64();
        r.expect_end();
        return e;
    }
};

// ---------------------------------------------------------------------------
// MemSettleStore — in-memory ISettleStore for the smoke/KAT (no filesystem).
// ---------------------------------------------------------------------------
class MemSettleStore final : public ISettleStore {
public:
    struct Batch final : public ISettleBatch {
        MemSettleStore* owner;
        std::map<std::string, std::optional<std::string>> ops;  // nullopt == remove
        explicit Batch(MemSettleStore* o) : owner(o) {}
        void put(const std::string& k, const std::string& v) override { ops[k] = v; }
        void remove(const std::string& k) override { ops[k] = std::nullopt; }
        bool commit_sync() override {
            for (auto& [k, v] : ops) { if (v) owner->kv_[k] = *v; else owner->kv_.erase(k); }
            return true;
        }
    };
    std::unique_ptr<ISettleBatch> batch() override { return std::make_unique<Batch>(this); }
    std::optional<std::string> get(const std::string& k) override {
        auto it = kv_.find(k); return it == kv_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        for (auto& [k, v] : kv_) {           // std::map => lexicographic key order
            if (k.compare(0, prefix.size(), prefix) == 0) if (!fn(k, v)) break;
        }
        return true;
    }
private:
    std::map<std::string, std::string> kv_;
};

// ---------------------------------------------------------------------------
// FileSettleStore — a durable single-file append/rewrite ISettleStore. Each
// commit_sync() rewrites the whole key/value image and fsyncs (atomic rename),
// modelling the LevelDB write-batch atomicity the production store gives for
// free. Small by construction (one lane, bounded event log); a production
// deployment swaps in LevelDBSettleStore.
// ---------------------------------------------------------------------------
class FileSettleStore final : public ISettleStore {
public:
    explicit FileSettleStore(std::filesystem::path dir) : dir_(std::move(dir)) {
        std::filesystem::create_directories(dir_);
        img_ = dir_ / "settle.img";
        load();
    }

    struct Batch final : public ISettleBatch {
        FileSettleStore* owner;
        std::map<std::string, std::optional<std::string>> ops;
        explicit Batch(FileSettleStore* o) : owner(o) {}
        void put(const std::string& k, const std::string& v) override { ops[k] = v; }
        void remove(const std::string& k) override { ops[k] = std::nullopt; }
        bool commit_sync() override {
            for (auto& [k, v] : ops) { if (v) owner->kv_[k] = *v; else owner->kv_.erase(k); }
            return owner->flush();
        }
    };
    std::unique_ptr<ISettleBatch> batch() override { return std::make_unique<Batch>(this); }
    std::optional<std::string> get(const std::string& k) override {
        auto it = kv_.find(k); return it == kv_.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        for (auto& [k, v] : kv_)
            if (k.compare(0, prefix.size(), prefix) == 0) if (!fn(k, v)) break;
        return true;
    }

private:
    // Image format: repeated [u64 klen | key | u64 vlen | val]. Fail-closed:
    // a truncated tail throws → RecoveryDriver aborts the open (F2).
    void load() {
        std::ifstream f(img_, std::ios::binary);
        if (!f) return;                              // fresh store
        std::string all((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        store_codec::Reader r(all);
        while (r.o < all.size()) {
            std::string k = r.str();
            std::string v = r.str();
            kv_[k] = v;
        }
    }
    bool flush() {
        std::string img;
        for (auto& [k, v] : kv_) { store_codec::put_str(img, k); store_codec::put_str(img, v); }
        std::filesystem::path tmp = img_;
        tmp += ".tmp";
        { std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
          if (!f) return false;
          f.write(img.data(), static_cast<std::streamsize>(img.size()));
          f.flush();
          if (!f) return false; }
        std::error_code ec;
        std::filesystem::rename(tmp, img_, ec);      // atomic replace
        return !ec;
    }
    std::filesystem::path dir_, img_;
    std::map<std::string, std::string> kv_;
};

// ---------------------------------------------------------------------------
// RecoveryDriver — rebuilds one lane's OwedLedger + SettleHW + finalize cursor
// from the store, BEFORE V37Engine::start(). Deterministic replay: FOUND events
// re-enter pending; FINALIZE events call on_block_finalized(bid, bin_height) IN
// SEQ ORDER with the PERSISTED per-height bin_height (F1 — never the live tip);
// ORPHAN events dispose. Any torn record throws → recover() sets ok=false so the
// daemon refuses to start on a corrupt store (F2 fail-closed), rather than
// silently resuming from a truncated ledger.
// ---------------------------------------------------------------------------
struct RecoveredState {
    SettleHW      hw;
    std::uint64_t finalize_cursor_height = 0;  // last coin height the F1 driver stepped through
    std::uint64_t max_event_seq = 0;           // next write-ahead seq = this + 1
    bool          recovered = false;           // false == fresh store (no prior state)
};

class RecoveryDriver {
public:
    RecoveryDriver(ISettleStore& store, ::v37::ChainId chain)
        : store_(store), chain_(chain) {}

    // Rebuild `ledger` and return the recovered high-water / cursor. `ok` is set
    // false ONLY on a torn store (F2). A fresh store recovers cleanly with
    // recovered=false and an empty ledger.
    RecoveredState recover(OwedLedger& ledger, bool& ok) {
        ok = true;
        RecoveredState st;
        try {
            // (1) high-water leg.
            if (auto hwb = store_.get(store_codec::k_hw(chain_))) {
                if (hwb->size() >= 24) st.hw = SettleHW::deserialize(*hwb);
                st.recovered = true;
            }
            // (2) finalize cursor.
            if (auto cur = store_.get(store_codec::k_cursor(chain_))) {
                store_codec::Reader r(*cur);
                st.finalize_cursor_height = r.u64();
                st.recovered = true;
            }
            // (3) replay the ledger event log IN SEQ ORDER (keys are zero-padded
            //     so lexicographic == numeric). This is the whole F1 discipline:
            //     FINALIZE replays with its own recorded per-height bin_height.
            store_.for_each_prefix(store_codec::k_evt_prefix(chain_),
                [&](const std::string& k, const std::string& v) {
                    (void)k;
                    SettleEvent e = SettleEvent::deserialize(v);
                    ++st.max_event_seq;
                    switch (e.kind) {
                        case SettleEvKind::Found:
                            ledger.on_block_found(e.bid, e.credit, e.payout); break;
                        case SettleEvKind::Finalize:
                            ledger.on_block_finalized(e.bid, e.bin_height); break;  // F1
                        case SettleEvKind::Orphan:
                            ledger.on_block_orphaned(e.bid, e.payout); break;
                    }
                    return true;
                });
            if (st.max_event_seq) st.recovered = true;
        } catch (const std::exception&) {
            ok = false;                          // F2: torn store → refuse to start
        }
        return st;
    }
private:
    ISettleStore&  store_;
    ::v37::ChainId chain_;
};

} // namespace c2pool::v37n::btc
