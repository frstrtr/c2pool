// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_template.hpp   (Track A2 / X9 O-2 — the template)
//
// THE MONEROD TEMPLATE for the O-2 serve side: the block bytes the stratum
// listener serves to miners and the live submitter hands back to monerod.
//
//   MonerodTemplateProvider — pulls monerod's get_block_template (blocking, over
//       the shared LiveMonerodTransport — a fresh socket per call, so the MAIN
//       thread's refresh() never collides with the listener thread's reads) and
//       keeps ONE mutex-guarded snapshot: the hashing blob (what the miner
//       grinds), the FULL blocktemplate_blob (what is submitted), the height,
//       the 128-bit network difficulty, prev_hash, expected_reward and the
//       RandomX seed pair. Keyed by a template_id that changes ONLY when the
//       template really changed (height / prev / bytes), so in-flight jobs stay
//       resolvable across identical refreshes.
//   MonerodStratumTemplateSource — the X5 ITemplateSource over that snapshot:
//       one blob for every worker (max_extra_nonces == 1; the extra_nonce is not
//       baked), the job (lane) target from cfg.stratum_share_diff or, when 0,
//       the network target (solo: every accepted share is a network block).
//
// HONEST SCOPE (option A, see main_v37_xmr.cpp): the bytes are monerod's own
// single-coinbase template paid to cfg.payout_address, nonce patched at submit.
// The v37 K_fair settlement coinbase (XmrBlockTemplate + X6, option B) slots in
// behind the same two seams once impl/xmr/template/xmr_coin_primitives has
// bodies. Nothing here defines a consensus digest (consumer tree only).
//
// THREADING: refresh() = main thread; current()/by_id()/template_id()/get_job()/
// rebuild_blob() = any thread (mutex snapshot copy / atomic).
// ===========================================================================
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/node/minijson.hpp"
#include "impl/xmr/node/monerod_transport.hpp"
#include "impl/xmr/node/xmr_node_types.hpp"
#include "impl/xmr/stratum/xmr_stratum.hpp"

namespace c2pool::v37n::xmr::o2 {

namespace strat = ::v37::xmr::stratum;
namespace mj    = ::c2pool::xmr::node::minijson;

// One get_block_template snapshot (everything the serve + submit side needs).
struct MonerodTemplate {
    std::uint32_t template_id = 0;
    std::vector<std::uint8_t> hashing_blob;    // blockhashing_blob (miner grinds this)
    std::vector<std::uint8_t> full_blob;       // blocktemplate_blob (submitted, nonce patched)
    std::uint64_t height = 0;
    std::uint64_t difficulty = 0;              // network difficulty, low 64 bits
    std::uint64_t difficulty_top64 = 0;        // high 64 bits (0 on regtest/stagenet/mainnet today)
    std::size_t   nonce_offset = strat::EXPECTED_NONCE_OFFSET_V16;   // header nonce, v16 == 39
    std::uint64_t reserved_offset = 0;         // tx_extra nonce reservation (0 = none)
    std::uint64_t expected_reward = 0;         // piconero
    ::c2pool::xmr::node::Hash prev_id{};       // result.prev_hash
    std::array<std::uint8_t, strat::HASH_SIZE> seed_hash{};
    std::optional<std::array<std::uint8_t, strat::HASH_SIZE>> next_seed_hash;
    std::uint8_t  major_version = 0;
    bool          valid = false;
};

class MonerodTemplateProvider {
public:
    MonerodTemplateProvider(::c2pool::xmr::node::IMonerodTransport& transport,
                            std::string payout_address, std::uint32_t reserve_size = 0)
        : m_transport(transport), m_addr(std::move(payout_address)), m_reserve(reserve_size) {}

    // Refresh the cached template from monerod (main thread). Returns true when
    // a valid template is now cached (new or unchanged); the error is kept in
    // last_error() otherwise.
    bool refresh() {
        const std::string body =
            R"({"jsonrpc":"2.0","id":"0","method":"get_block_template","params":{)"
            R"("wallet_address":")" + m_addr + R"(","reserve_size":)" +
            std::to_string(m_reserve) + "}}";
        bool got = false;
        m_transport.rpc_post(body, [&](const ::c2pool::xmr::node::RpcResponse& r) {
            if (!r.ok()) { set_error(r.error); return; }
            got = parse_into(r.body);
        });
        if (got) m_refreshes.fetch_add(1, std::memory_order_relaxed);
        else     m_failures.fetch_add(1, std::memory_order_relaxed);
        return got;
    }

    // Snapshot of the current template (copy; any thread).
    MonerodTemplate current() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_cur;
    }
    // Look a template up by id. Only the CURRENT template is retained; an older
    // id is gone (=> "Stale share" in the submit path).
    bool by_id(std::uint32_t id, MonerodTemplate& out) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_cur.valid && m_cur.template_id == id) { out = m_cur; return true; }
        return false;
    }
    // The current template id (0 = none yet). Any thread. The main loop compares
    // it across refreshes and signals the listener ONLY on a change.
    std::uint32_t template_id() const { return m_tid.load(std::memory_order_acquire); }

    std::string last_error() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last_error;
    }
    std::string offset_note() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_offset_note;
    }
    std::uint64_t refreshes() const { return m_refreshes.load(std::memory_order_relaxed); }
    std::uint64_t failures()  const { return m_failures.load(std::memory_order_relaxed); }
    std::uint64_t changes()   const { return m_changes.load(std::memory_order_relaxed); }

    static bool from_hex(const std::string& hex, std::vector<std::uint8_t>& out) {
        if (hex.size() % 2 != 0) return false;
        out.clear();
        out.reserve(hex.size() / 2);
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (std::size_t i = 0; i < hex.size(); i += 2) {
            const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
            if (hi < 0 || lo < 0) return false;
            out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
        }
        return true;
    }

private:
    void set_error(std::string e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last_error = std::move(e);
    }

    // monerod emits difficulty as a JSON number here, but the X9 bring-up found
    // get_miner_data emitting a "0x…" hex STRING (v0.18); accept both, and read
    // wide_difficulty (hex string, 128-bit) when present so the top64 is exact.
    static void read_difficulty(const mj::Value& res, std::uint64_t& lo, std::uint64_t& hi) {
        lo = 0; hi = 0;
        const mj::Value& wide = res["wide_difficulty"];
        if (wide.is_string() && !wide.as_string().empty()) {
            std::uint64_t h = 0, l = 0;
            if (mj::hex_to_u128(wide.as_string(), h, l)) { lo = l; hi = h; return; }
        }
        const mj::Value& d = res["difficulty"];
        if (d.is_number()) {
            lo = d.as_u64();
            hi = res["difficulty_top64"].as_u64();
            return;
        }
        if (d.is_string()) {
            std::uint64_t h = 0, l = 0;
            if (mj::hex_to_u128(d.as_string(), h, l)) { lo = l; hi = h; }
        }
    }

    bool parse_into(const std::vector<char>& body) {
        mj::Value root;
        if (!mj::parse(body.data(), body.size(), root)) { set_error("template: JSON parse failed"); return false; }
        const mj::Value& res = root["result"];
        if (!res.is_object()) {
            set_error("template: no result (" + root["error"]["message"].as_string() + ")");
            return false;
        }
        if (res["status"].as_string() != "OK") {
            set_error("template: status " + res["status"].as_string());
            return false;
        }
        MonerodTemplate t;
        if (!from_hex(res["blocktemplate_blob"].as_string(), t.full_blob) || t.full_blob.empty()) {
            set_error("template: bad blocktemplate_blob"); return false;
        }
        if (!from_hex(res["blockhashing_blob"].as_string(), t.hashing_blob) || t.hashing_blob.empty()) {
            set_error("template: bad blockhashing_blob"); return false;
        }
        t.height          = res["height"].as_u64();
        t.reserved_offset = res["reserved_offset"].as_u64();
        t.expected_reward = res["expected_reward"].as_u64();
        t.major_version   = t.full_blob[0];
        read_difficulty(res, t.difficulty, t.difficulty_top64);
        if (t.height == 0 || (t.difficulty == 0 && t.difficulty_top64 == 0)) {
            set_error("template: height/difficulty missing"); return false;
        }
        std::array<std::uint8_t, 32> h{};
        if (mj::hex_to_hash(res["prev_hash"].as_string(), h)) t.prev_id = h;
        if (mj::hex_to_hash(res["seed_hash"].as_string(), h)) t.seed_hash = h;
        if (mj::hex_to_hash(res["next_seed_hash"].as_string(), h)) t.next_seed_hash = h;

        // Header nonce offset: v16 headers put the 4-byte nonce at 39. Cross-check
        // against where the hashing blob and the full blob first diverge (they
        // share the whole header incl. the nonce, then diverge — hashing blob has
        // the tree root, the full blob has the miner_tx): divergence == offset+4.
        // The derived offset is load-bearing (a wrong one yields a wrong block id
        // and a share hashed at the wrong bytes), so trust it over the constant.
        t.nonce_offset = strat::EXPECTED_NONCE_OFFSET_V16;
        std::string note;
        {
            std::size_t div = 0;
            const std::size_t n = std::min(t.hashing_blob.size(), t.full_blob.size());
            while (div < n && t.hashing_blob[div] == t.full_blob[div]) ++div;
            if (div >= strat::NONCE_SIZE && div - strat::NONCE_SIZE != t.nonce_offset) {
                note = "nonce_offset derived=" + std::to_string(div - strat::NONCE_SIZE) +
                       " (v16 default 39)";
                t.nonce_offset = div - strat::NONCE_SIZE;
            }
        }
        if (t.nonce_offset + strat::NONCE_SIZE > t.hashing_blob.size() ||
            t.nonce_offset + strat::NONCE_SIZE > t.full_blob.size()) {
            set_error("template: nonce offset past blob end"); return false;
        }
        t.valid = true;

        std::lock_guard<std::mutex> lk(m_mtx);
        m_offset_note = note;
        m_last_error.clear();
        // Bump the id only when the template actually changed (new height, new
        // parent or new bytes), so in-flight jobs stay resolvable otherwise.
        if (!m_cur.valid || m_cur.height != t.height || m_cur.prev_id != t.prev_id ||
            m_cur.full_blob != t.full_blob) {
            t.template_id = ++m_id_counter;
            m_changes.fetch_add(1, std::memory_order_relaxed);
        } else {
            t.template_id = m_cur.template_id;
        }
        m_cur = std::move(t);
        m_tid.store(m_cur.template_id, std::memory_order_release);
        return true;
    }

    ::c2pool::xmr::node::IMonerodTransport& m_transport;
    std::string   m_addr;
    std::uint32_t m_reserve;
    mutable std::mutex m_mtx;
    MonerodTemplate m_cur;
    std::uint32_t m_id_counter = 0;
    std::string   m_last_error;
    std::string   m_offset_note;
    std::atomic<std::uint32_t> m_tid{0};
    std::atomic<std::uint64_t> m_refreshes{0}, m_failures{0}, m_changes{0};
};

// ---------------------------------------------------------------------------
// ITemplateSource — serve the cached monerod hashing blob to miners.
// ---------------------------------------------------------------------------
class MonerodStratumTemplateSource final : public strat::ITemplateSource {
public:
    // share_diff 0 => the job target is the network target (solo).
    MonerodStratumTemplateSource(const MonerodTemplateProvider& provider, std::uint64_t share_diff)
        : m_provider(provider), m_share_diff(share_diff) {}

    bool get_job(std::uint32_t /*extra_nonce*/, strat::TemplateJob& out) override {
        MonerodTemplate t = m_provider.current();
        if (!t.valid) return false;
        fill_from(t, out);
        return true;
    }
    bool rebuild_blob(std::uint32_t template_id, std::uint32_t /*extra_nonce*/,
                      strat::TemplateJob& out) override {
        MonerodTemplate t;
        if (!m_provider.by_id(template_id, t)) return false;   // -> Stale
        fill_from(t, out);
        return true;
    }
    std::uint32_t max_extra_nonces() const override { return 1; }

    // 64-bit target from a difficulty (xmr_stratum.cpp target_from_diff rule).
    static std::uint64_t target_from_diff(std::uint64_t diff) {
        return diff ? (0xFFFFFFFFFFFFFFFFULL / diff) : 0xFFFFFFFFFFFFFFFFULL;
    }
    // The u64 network target of a 128-bit difficulty: a top64 > 0 means the
    // difficulty exceeds 2^64 and no u64 target can express it — serve the
    // hardest target (1) so nothing is mistaken for a block; the sink applies
    // the exact 128-bit rule anyway.
    static std::uint64_t network_target(std::uint64_t lo, std::uint64_t hi) {
        if (hi) return 1;
        return target_from_diff(lo);
    }

private:
    void fill_from(const MonerodTemplate& t, strat::TemplateJob& out) const {
        out.blob                 = t.hashing_blob;
        out.nonce_offset         = t.nonce_offset;
        out.template_id          = t.template_id;
        out.height               = t.height;
        out.mainchain_target     = network_target(t.difficulty, t.difficulty_top64);
        // lane target = the EASIER of {share diff, network}; 0 => network (solo)
        out.lane_target          = m_share_diff
                                       ? std::max(target_from_diff(m_share_diff), out.mainchain_target)
                                       : out.mainchain_target;
        out.seed_hash            = t.seed_hash;
        out.next_seed_hash       = t.next_seed_hash;
        out.monero_major_version = t.major_version;
    }

    const MonerodTemplateProvider& m_provider;
    std::uint64_t m_share_diff;
};

} // namespace c2pool::v37n::xmr::o2
