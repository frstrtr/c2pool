// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// v37_xmr_epoch_ckpt_kat -- LANE-EPOCH BOOTSTRAP: the settlement checkpoint a
// fresh node fetches when it joins a LIVE epoch it does not hold
// (xmr/xmr_lane_epoch_ckpt.hpp).
//
//   A  a real XmrNode ledger (the SERVER: 6 rows over 3 fe groups, one
//      negative row) -> snapshot -> encode -> decode round-trip, byte-exact.
//   B  HONEST: the joiner's chain carries an Own lane block committing the
//      state's root above C -> accepted; adopted into a FRESH XmrNode the
//      ledger's owed_digest (and every row's finalW / first_eligible) equals
//      the server's; the cursor jumps to C; a restart replays the same digest.
//   C  LYING PEERS, each refused with its reason: a row's finalW +1 (V1), a
//      row's payee swapped (V1 ref), an unwitnessed state (V2), an unwitnessed
//      hist digest (V3), a wrong epoch seq (V5), a C below the joiner's cursor,
//      truncated / trailing bytes (codec).
//   D  a node holding a settled row cannot adopt; one that only finalized
//      EMPTY-ledger blocks (the epoch's first blocks) still can.
// ---------------------------------------------------------------------------
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_node.hpp"
#include "c2pool/v37/xmr/xmr_node_smoke.hpp"
#include "c2pool/v37/xmr/xmr_lane_epoch_ckpt.hpp"

namespace ep  = c2pool::v37n::xmr::epoch;
namespace eck = c2pool::v37n::xmr::epoch::ckpt;
namespace credit = c2pool::v37n::xmr::credit;
namespace smoke = c2pool::v37n::xmr::smoke;
using bytes32 = ::v37::bytes32;

namespace {
int g_fail = 0, g_pass = 0;
void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what.c_str()); }
    else    { ++g_fail; std::printf("  FAIL %s\n", what.c_str()); }
}
constexpr std::uint32_t kChain = 7;
constexpr std::uint64_t kD = 3;

::v37::ScriptRef ref_n(std::uint8_t n) {
    std::array<std::uint8_t, 32> s{}, v{};
    s[0] = n; s[31] = 0x11; v[0] = static_cast<std::uint8_t>(0x80 | n); v[31] = 0x22;
    return ::v37::xmr::make_xmr_std(s, v);
}
bytes32 key_n(std::uint8_t n) { return ::v37::xmr::xmr_identity_key(ref_n(n)); }

struct NodeBox {
    c2pool::xmr::node::MockMonerodTransport mock;
    c2pool::v37n::xmr::XmrNodeConfig cfg;
    std::unique_ptr<c2pool::v37n::xmr::XmrNode> node;
    explicit NodeBox(const std::filesystem::path& dir) {
        using namespace c2pool::v37n::xmr;
        cfg.network = MoneroNetwork::Regtest; cfg.lane_chain = kChain; cfg.d_conf = kD;
        cfg.settle_db_path = dir.string();
        std::filesystem::create_directories(dir);
        node = std::make_unique<XmrNode>(cfg, mock, &smoke::test_point_check);
        node->bring_up();
    }
};

// The joiner's chain: Own facts by height.
struct Chain {
    std::map<std::uint64_t, ep::ChainFact> f;
    void own(std::uint64_t h, const bytes32& digest, std::uint32_t seq = 0) {
        ep::ChainFact c; c.h = h; c.bid[0] = static_cast<std::uint8_t>(h); c.bid[1] = 0xB1;
        c.own = true; c.has_root = true; c.has_cut = true; c.root = ep::mm_root_of(kChain, digest);
        if (seq) { c.ep = credit::EpochParse::Present; c.f = credit::EpochField{seq, ep::kEpochRuleVersion, bytes32{}}; }
        f[h] = c;
    }
    const ep::ChainFact* at(std::uint64_t h) const { auto it = f.find(h); return it == f.end() ? nullptr : &it->second; }
    ep::State state_before(std::uint64_t h) const {
        ep::Rule r; r.n_dead = 1000; r.empty_root = ep::empty_root(kChain); r.origin_h = 1;
        ep::State s;
        for (const auto& [hh, c] : f) { if (hh >= h) break; apply(s, c, classify(r, s, c)); }
        return s;
    }
};

eck::Verified verify(const eck::Checkpoint& c, const Chain& ch, std::uint64_t tip, std::uint64_t joiner_cursor) {
    return eck::verify(c, kChain, [&](std::uint64_t h) { return ch.at(h); }, tip,
                       [&](std::uint64_t h) { return ch.state_before(h); }, joiner_cursor);
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / ("v37_epoch_ckpt_kat_" + std::to_string(::getpid()));
    fs::remove_all(tmp);
    std::printf("v37_xmr_epoch_ckpt_kat: LANE-EPOCH bootstrap checkpoint (D_conf %llu)\n", static_cast<unsigned long long>(kD));

    // ── A: the SERVER's settled state (3 fe groups + one negative row) ──
    std::printf("A. server ledger -> snapshot -> codec\n");
    eck::Checkpoint ck; std::vector<std::uint8_t> wire; bytes32 server_digest{};
    std::map<bytes32, std::pair<long long, std::uint64_t>> server_rows;
    std::map<bytes32, ::v37::ScriptRef> refs;
    for (std::uint8_t n = 1; n <= 6; ++n) refs[key_n(n)] = ref_n(n);
    auto pay_of = [&](const bytes32& k) { return refs.count(k) ? refs[k] : ::v37::ScriptRef{}; };
    std::vector<eck::Hist> hist;
    {
        NodeBox s(tmp / "server");
        auto& n = *s.node;
        (void)n.seed_settled_owed("b10", {{key_n(1), 1000}, {key_n(2), 2000}}, 10);
        hist.push_back({n.ledger().owed_digest(), 7});
        (void)n.seed_settled_owed("b14", {{key_n(3), 3000}, {key_n(4), 400}}, 14);
        hist.push_back({n.ledger().owed_digest(), 11});
        (void)n.seed_settled_owed("b17", {{key_n(5), 555}, {key_n(1), -1000}, {key_n(6), -60}}, 17);
        server_digest = n.ledger().owed_digest();
        hist.push_back({server_digest, 14});
        for (const auto& [k, w] : n.ledger().finalW()) if (w) server_rows[k] = {w, n.ledger().first_eligible_of(k)};
        ck = eck::snapshot(n.ledger(), pay_of, credit::EpochField{0, ep::kEpochRuleVersion, bytes32{}}, 14, hist);
        wire = eck::encode(ck);
    }
    check(ck.rows.size() == server_rows.size() && ck.rows.size() == 5, "snapshot carries every non-zero row (5: key1 zeroed, key6 negative)");
    check(eck::rows_digest(ck.rows) == server_digest, "rows_digest(rows) == OwedLedger::owed_digest() (the 'V37Q' preimage, fe included)");
    {
        eck::Checkpoint rt; std::string why;
        const bool ok = eck::decode(wire, rt, &why);
        check(ok && eck::encode(rt) == wire, "decode(encode(ck)) re-encodes byte-identically (" + std::to_string(wire.size()) + " B)");
        std::vector<std::uint8_t> t = wire; t.pop_back();
        check(!eck::decode(t, rt, &why), "truncated checkpoint -> codec refusal (" + why + ")");
        t = wire; t.push_back(0);
        check(!eck::decode(t, rt, &why), "trailing byte -> codec refusal (" + why + ")");
    }

    // ── B: HONEST checkpoint, verified against the joiner's chain, adopted ──
    std::printf("B. honest checkpoint -> verified -> adopted into a FRESH node\n");
    Chain ch;
    ch.own(12, hist[0].digest);        // witnesses of the hist states
    ch.own(16, hist[1].digest);
    ch.own(19, server_digest);         // the builder that cut at C committed the state
    const std::uint64_t tip = 22;
    {
        const eck::Verified v = verify(ck, ch, tip, 0);
        check(v.ok() && v.witness_h == 19, std::string("honest checkpoint accepted (") + eck::to_string(v.r) + ", witness h=" +
                                           std::to_string(v.witness_h) + ")");
        NodeBox j(tmp / "joiner");
        auto& n = *j.node;
        std::string why;
        const bool ad = eck::adopt(n, ck, &why);
        check(ad, "adopted into the fresh node" + (why.empty() ? std::string() : " (" + why + ")"));
        check(n.ledger().owed_digest() == server_digest, "joiner owed_digest == server owed_digest (byte-equal)");
        bool rows_eq = true;
        for (const auto& [k, wf] : server_rows) {
            auto it = n.ledger().finalW().find(k);
            if (it == n.ledger().finalW().end() || it->second != wf.first || n.ledger().first_eligible_of(k) != wf.second) rows_eq = false;
        }
        check(rows_eq, "every row's finalW AND first_eligible (the K_fair age clock) equal the server's");
        check(n.finalize_driver().cursor_height() == 14, "finalize cursor jumped to C=14");
        check(n.finalize_driver().digest_since() == 14, "digest since == C (the RECON ring's since)");
        check(!eck::adopt(n, ck, &why), "a second adoption is refused (the ledger now holds rows)");
    }
    {
        NodeBox j(tmp / "joiner");   // RESTART: the adoption was written through the event log
        check(j.node->ledger().owed_digest() == server_digest, "restarted joiner replays the adopted digest");
        check(j.node->finalize_driver().cursor_height() == 14, "restarted joiner keeps cursor C=14");
    }

    // ── C: LYING PEERS ──
    std::printf("C. forged checkpoints are refused\n");
    auto expect = [&](const eck::Checkpoint& c, eck::Refusal want, const std::string& what, std::uint64_t jc = 0) {
        const eck::Verified v = verify(c, ch, tip, jc);
        check(v.r == want, what + " -> " + eck::to_string(v.r) + (v.why.empty() ? "" : " (" + v.why + ")"));
    };
    { eck::Checkpoint c = ck; c.rows[1].w += 1; expect(c, eck::Refusal::Rows, "a row's finalW +1"); }
    { eck::Checkpoint c = ck; c.rows[1].w += 1; c.owed_digest = eck::rows_digest(c.rows);
      expect(c, eck::Refusal::NoWitness, "a row's finalW +1 with a self-consistent digest (no chain commits it)"); }
    { eck::Checkpoint c = ck; c.rows[0].ref = ref_n(9); expect(c, eck::Refusal::Ref, "a row's payee swapped to the liar's address"); }
    { eck::Checkpoint c = ck; std::swap(c.rows[0], c.rows[1]); expect(c, eck::Refusal::Rows, "rows out of key order"); }
    { eck::Checkpoint c = ck; c.hist.insert(c.hist.begin(), eck::Hist{key_n(42), 3}); expect(c, eck::Refusal::Hist, "an unwitnessed hist digest (ring poisoning)"); }
    { eck::Checkpoint c = ck; c.ep.seq = 1; expect(c, eck::Refusal::Epoch, "the checkpoint names epoch 1 (chain: epoch 0)"); }
    expect(ck, eck::Refusal::Behind, "C=14 below the joiner's cursor 15", 15);
    { Chain bare = ch; bare.f.erase(19);
      const eck::Verified v = verify(ck, bare, tip, 0);
      check(v.r == eck::Refusal::NoWitness, std::string("the honest state before any block committed it -> ") + eck::to_string(v.r) + " (the server serves an older witnessed state)"); }

    // ── D: a node with history never adopts ──
    std::printf("D. a node that holds settlement history cannot adopt\n");
    {
        NodeBox h(tmp / "holder");
        (void)h.node->seed_settled_owed("own", {{key_n(2), 5}}, 4);
        std::string why;
        check(!eck::adopt(*h.node, ck, &why), "adopt refused on a node holding a settled row (" + why + ")");
    }
    {
        NodeBox e(tmp / "empty-booked");   // booked + finalized a zero-credit block (the opener): still fresh
        (void)e.node->seed_settled_owed("opener", {}, 2);
        std::string why;
        check(e.node->finalize_driver().event_seq() != 0 && e.node->finalize_driver().bootstrap_fresh(),
              "a node that only settled an EMPTY-ledger block is still bootstrap-fresh");
        check(eck::adopt(*e.node, ck, &why) && e.node->ledger().owed_digest() == server_digest,
              "... and adopts the checkpoint to the server's digest" + (why.empty() ? std::string() : " (" + why + ")"));
    }

    fs::remove_all(tmp);
    std::printf("v37_xmr_epoch_ckpt_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
