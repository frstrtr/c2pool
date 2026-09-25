// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp   (GAP-2 stage 1)
//
// The MAIN-THREAD half of the relay: admitted receipts -> this node's lane.
//
// ORDER IS NODE-LOCAL (Ruling A, 09-12): every node pushes the receipts it
// admitted in its OWN order, and the winner's on-chain cut (P, spine) is the
// settlement authority (fold at the winner's cut; repair by winner-order
// replay when our own order does not reproduce it). This class adds only a
// LOCAL SCHEDULING POLICY (design §4.4, OQ-1 ruling owed) that makes two
// honest nodes' orders coincide in the common case, so the repair is the
// exception rather than the per-block rule:
//
//   canonical (default): hold the admitted receipts of origin bin b; once this
//                        node's template height has been >= b + L for `grace`
//                        (the next Monero block plus the in-flight window),
//                        push bin b SORTED BY receipt_id. Two nodes holding the
//                        same SET for b publish the same lane prefix digest.
//                        A receipt for an already-closed bin (late) is pushed at
//                        the tail -- the residual case the repair covers.
//   arrival:             push on admit (the btc-dash Stage-1 semantics).
//
// FeeModelGate OFF (the default): each receipt is ONE lane push {payee,
// kReceiptWeight, flags 0} -- the record shape the credit-feed stand-in wrote,
// so for a given order the lane is byte-identical to the stand-in's (master).
// FeeModelGate ON (Options::fee_model, ruling S3): each receipt is pushed at
// fee::kFeeReceiptWeight split by the give-author u16 it CARRIES in its
// PoW-committed side_data_v2 -- (payee, 65535 - d) then (donation, d) iff
// d > 0 (fee::receipt_lane_pushes) -- so one receipt spans 1 or 2 lane
// positions, recorded as (pos_first, n_pushes) for the vault / repair.
//
// DURABILITY: every pushed receipt is appended to <data-dir>/lane<chain>.receipts
// as [u32 LE len][fb_receipt]. At boot the file is replayed IN ITS OWN ORDER
// (this node's historical lane) without re-hashing -- we verified each record
// before we wrote it -- which rebuilds the lane byte-identically across a
// restart; a torn tail record is truncated away.
// ===========================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "xmr_relay_node.hpp"
#include "../xmr_fee_model.hpp"     // receipt_lane_pushes (fee model S3)

namespace c2pool::v37n::xmr::relay {

class XmrReceiptIngest {
public:
    enum class Order { Canonical, Arrival };
    struct Options {
        u32         chain = 0;
        Order       order = Order::Canonical;
        u64         bin_lag = 1;          // L
        u32         grace_ms = 4000;      // in-flight window after the tip moved
        std::string durable_path;         // "" = no durable log
        bool        fee_model = false;    // LaneParams::fee ON: split by the receipt's give_author u16
        u8          network = 0;          // HELLO network byte == fee::DonationNet: the donation payee (DON-NET)
    };
    struct Stats {
        u64 pushed = 0, push_failed = 0, late = 0, bins_closed = 0, reloaded = 0, reload_torn = 0, durable_writes = 0;
        u64 lane_pushes = 0;   // lane records written (== pushed with the fee model OFF)
    };
    // Engine push, done by the daemon (it owns the engine + the replay log).
    // Returns false if the record was not applied; fills the lane tip after it.
    using PushFn = std::function<bool(const ::v37::ScriptRef& payee, u64 w, u64& next_after, bytes32& digest_after)>;
    // After a successful receipt push (vault + spine probe + ledger learn_ref):
    // the receipt occupies lane positions [pos_first, pos_first + n_pushes).
    using AfterFn = std::function<void(const Admitted&, u64 pos_first, u32 n_pushes, u64 next_after, const bytes32& digest_after)>;

    XmrReceiptIngest(Options o, PushFn push, AfterFn after)
        : m_o(std::move(o)), m_push(std::move(push)), m_after(std::move(after)) {}

    // Replay the durable log (boot). on_loaded(Admitted) runs BEFORE the push so
    // the caller can re-seed the relay's dedup set. Returns records re-pushed.
    std::size_t reload(const std::function<void(const Admitted&)>& on_loaded) {
        if (m_o.durable_path.empty()) return 0;
        std::ifstream in(m_o.durable_path, std::ios::binary);
        if (!in) return 0;
        std::vector<u8> all((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();
        std::size_t off = 0, n = 0, good_end = 0;
        while (off + 4 <= all.size()) {
            const u32 len = le::get32(all.data() + off);
            if (len == 0 || len > kFbReceiptMaxBytes || off + 4 + len > all.size()) break;
            Admitted a;
            a.raw.assign(all.begin() + static_cast<std::ptrdiff_t>(off + 4),
                         all.begin() + static_cast<std::ptrdiff_t>(off + 4 + len));
            if (!decode_fb_receipt(a.raw, a.r)) break;
            a.id = receipt_id(a.r);
            off += 4 + len;
            good_end = off;
            if (on_loaded) on_loaded(a);
            if (!push_one(a, /*durable=*/false)) break;
            ++n;
        }
        if (good_end < all.size()) {
            ++m_st.reload_torn;
            std::error_code ec;
            std::filesystem::resize_file(m_o.durable_path, good_end, ec);
        }
        m_st.reloaded += n;
        return n;
    }

    void on_admitted(Admitted a) {
        if (m_o.order == Order::Arrival) { push_one(a, true); return; }
        if (m_any_closed && a.bin <= m_closed_through) { ++m_st.late; push_one(a, true); return; }
        m_bins[a.bin].emplace(a.id, std::move(a));
    }

    // Close every bin whose window has passed. `template_height` = the height
    // of the block this node is currently building on top of the tip.
    void tick(u64 template_height, Clock::time_point now = Clock::now()) {
        if (template_height) m_tip_seen.try_emplace(template_height, now);
        while (m_tip_seen.size() > 4096) m_tip_seen.erase(m_tip_seen.begin());
        while (!m_bins.empty()) {
            auto bit = m_bins.begin();
            const u64 b = bit->first;
            auto seen = m_tip_seen.lower_bound(b + m_o.bin_lag);
            if (seen == m_tip_seen.end()) break;
            if (now - seen->second < std::chrono::milliseconds(m_o.grace_ms)) break;
            for (auto& [id, a] : bit->second) { (void)id; push_one(a, true); }
            ++m_st.bins_closed;
            if (!m_any_closed || b > m_closed_through) m_closed_through = b;
            m_any_closed = true;
            m_bins.erase(bit);
        }
    }

    std::size_t pending_receipts() const {
        std::size_t n = 0; for (const auto& [b, m] : m_bins) { (void)b; n += m.size(); } return n;
    }
    std::size_t pending_bins() const { return m_bins.size(); }
    const Stats& stats() const { return m_st; }
    const Options& options() const { return m_o; }

private:
    bool push_one(const Admitted& a, bool durable) {
        u64 next_after = 0; bytes32 dig{};
        const auto pushes = ::c2pool::v37n::xmr::fee::receipt_lane_pushes(a.r.payee, a.r.side.give_author,
                                                                         m_o.fee_model, kReceiptWeight,
                                                                         static_cast<::c2pool::v37n::xmr::fee::DonationNet>(m_o.network));
        u32 n = 0;
        for (const auto& [ref, w] : pushes) {
            if (!m_push(ref, w, next_after, dig)) { ++m_st.push_failed; return false; }
            ++n;
        }
        if (n == 0) { ++m_st.push_failed; return false; }
        ++m_st.pushed;
        m_st.lane_pushes += n;
        if (durable && !m_o.durable_path.empty()) {
            std::ofstream o(m_o.durable_path, std::ios::binary | std::ios::app);
            std::vector<u8> hdr; le::put32(hdr, static_cast<u32>(a.raw.size()));
            o.write(reinterpret_cast<const char*>(hdr.data()), 4);
            o.write(reinterpret_cast<const char*>(a.raw.data()), static_cast<std::streamsize>(a.raw.size()));
            o.flush();
            ++m_st.durable_writes;
        }
        if (m_after) m_after(a, next_after - n, n, next_after, dig);
        return true;
    }

    Options m_o;
    PushFn  m_push;
    AfterFn m_after;
    Stats   m_st;
    std::map<u64, std::map<bytes32, Admitted>> m_bins;   // origin bin -> (receipt_id -> receipt), id-sorted
    std::map<u64, Clock::time_point> m_tip_seen;          // template height -> first seen
    u64  m_closed_through = 0;
    bool m_any_closed = false;
};

} // namespace c2pool::v37n::xmr::relay
