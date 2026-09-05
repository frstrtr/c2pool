#pragma once
// V37 coinbase assembly — Track A2 bring-up step W5. CONSUMER-tree code: it
// lives here (src/c2pool/v37/), NOT in src/sharechain/v37/ (the pure
// header-only consensus module). W5 is a READER of W4's OWED ledger and the
// W0/W1 identity view; it owns no ledger state, mutates nothing in W4, and
// touches no Lane/Roundabout/LaneExecutor internal.
//
// Binding specs:
//   /home/ubuntu/v37-work/v37-a2-w4-settlement-spec.md  (§1.4 the W4→W5
//     contract, §4.6 K_fair + h_min, §12 W5 scope fence)
//   frstrtr/the docs/c2pool-v37-coinbase-prioritization.md  (the selection-rule
//     note: Rule 0 byte-denominated floor, Rule 5 carry-forward, Rule 6
//     finality gate, the fixed-budget rule; its Rule 2/3 value-per-byte
//     tranche is the QUEUED successor and is OUT OF SCOPE here — see below)
// Design of record: whitepaper §9 (accounting/payment split; oldest-owed-first;
//   bounded budget; carry-forward; no dust) + §13 (Merkle-root-in-coinbase,
//   O(log n) balance proof) + the M4 accounting boundary (OWED off the coin
//   chain; on-chain emit = SETTLED + opaque; no address monitoring) +
//   byte-denominated h_min (PayoutDescriptor encodes the script type).
//
// ── SELECTION ORDER: OLDEST-OWED-FIRST, NOT LARGEST-FIRST (whitepaper E-1) ──
// The RATIFIED K_fair F1 rule (2026-06-27, proto/refimpl/settlement_kfair_ref.py
// kfair_key) selects by the sort key
//       (first_eligible_height ASC, identity_key ASC)
// i.e. the OLDEST unpaid balance is paid first, ties broken by the canonical
// 32-byte identity key ascending. This is EXACTLY whitepaper erratum E-1: the
// public paper's §7.2 "largest-first" text is WRONG; W5 puts the corrected rule
// into code. The value-per-byte (eff = owed/size) successor described in the
// coinbase-prioritization note's Rule 2/3 is the QUEUED, not-yet-ratified
// successor and is deliberately NOT implemented here. W5 does not re-sort: it
// consumes W4's OwedLedger::propose_coinbase(), which is the single place the
// K_fair order lives, so the order is W4's and cannot drift.

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>          // OwedLedger, CutToken (W4)
#include <sharechain/v37/v37_descriptor.hpp>     // ScriptRef, ScriptKind
#include <sharechain/v37/v37_fixed.hpp>          // u64
#include <sharechain/v37/v37_hash.hpp>           // bytes32, sha256d
#include <sharechain/v37/v37_lane.hpp>           // Lane::MerkleProof + verify_proof (§13 reuse)

namespace c2pool::v37n::coinbase {

using ::v37::bytes32;
using ::v37::ScriptKind;
using ::v37::ScriptRef;
using ::v37::u64;
using ::c2pool::v37n::settle::OwedLedger;

// ─────────────────────────────────────────────────────────────────────────
// (A) Byte accounting — the coinbase-prioritization note's `size[m]` and the
// byte-denominated eligibility floor h_min. The output script serialized from
// the identity-view ScriptRef, and the full tx-output serialized size (the
// 8-byte value + the 1-byte compact script-length prefix + the script). The
// note's numbers (P2WPKH ~31, P2SH ~32, P2PKH ~34, P2TR ~43) fall out exactly.
// ─────────────────────────────────────────────────────────────────────────

// The scriptPubKey bytes for a canonical ScriptRef kind. Known templates are
// reconstructed from the ScriptRef payload; kind-255 (RAW) is NOT reconstructible
// from the identity view alone (the view keeps only sha256d(script), spec §1.3),
// so its raw script must be supplied by the caller from the share store's
// PayoutDescriptor::raw_script — see output_script(ref, raw).
inline std::vector<std::uint8_t> output_script(const ScriptRef& r,
                                               const std::vector<std::uint8_t>* raw = nullptr) {
    std::vector<std::uint8_t> s;
    switch (r.kind) {
        case ScriptKind::P2PKH:   // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
            s = {0x76, 0xa9, 0x14};
            s.insert(s.end(), r.payload.begin(), r.payload.end());
            s.push_back(0x88); s.push_back(0xac);
            return s;
        case ScriptKind::P2SH:    // OP_HASH160 <20> OP_EQUAL
            s = {0xa9, 0x14};
            s.insert(s.end(), r.payload.begin(), r.payload.end());
            s.push_back(0x87);
            return s;
        case ScriptKind::P2WPKH:  // OP_0 <20>
            s = {0x00, 0x14};
            s.insert(s.end(), r.payload.begin(), r.payload.end());
            return s;
        case ScriptKind::P2WSH:   // OP_0 <32>
            s = {0x00, 0x20};
            s.insert(s.end(), r.payload.begin(), r.payload.end());
            return s;
        case ScriptKind::P2TR:    // OP_1 <32>
            s = {0x51, 0x20};
            s.insert(s.end(), r.payload.begin(), r.payload.end());
            return s;
        case ScriptKind::RAW:
        default:
            if (raw) return *raw;   // kind-255: the caller supplies the script
            return s;               // no raw available → empty (caller must guard)
    }
}

// scriptPubKey length for a kind (independent of payload contents; kind-255
// needs its raw length, defaulted to the sha256d-payload placeholder length so
// the floor is never zero for RAW).
inline u64 script_len(ScriptKind k) {
    switch (k) {
        case ScriptKind::P2PKH:  return 25;
        case ScriptKind::P2SH:   return 23;
        case ScriptKind::P2WPKH: return 22;
        case ScriptKind::P2WSH:  return 34;
        case ScriptKind::P2TR:   return 34;
        case ScriptKind::RAW:
        default:                 return 34;  // conservative RAW placeholder
    }
}

// Serialized tx-output byte size = 8 (value, u64 LE) + 1 (compact script-length
// prefix; every template script is < 253 B so the prefix is one byte) + script.
inline u64 output_size(ScriptKind k) { return 8 + 1 + script_len(k); }

// The byte-denominated eligibility floor (coinbase-prioritization Rule 0):
// h_min(kind) = k_floor * output_size(kind). An owed balance must at least cover
// the block-space cost of its own output type before it may be emitted; below
// the floor the balance is NOT dropped — it carries forward (Rule 5) and grows
// across blocks until it clears the floor as one output (no dust ever emitted,
// no worker ever excluded).
inline u64 h_min(ScriptKind k, u64 k_floor) { return k_floor * output_size(k); }

// ─────────────────────────────────────────────────────────────────────────
// (B) The fixed budget (coinbase-prioritization "The byte budget is fixed by
// rule, not by the finder"). Two consensus-fixed caps, identical on every node:
//   slot_budget_C  — the ASIC/extranonce output-count cap (spec §4.6 "the first
//                    C"); passed straight through to W4's K_fair selection.
//   max_payout_bytes (K_max) — the total payout-output byte budget; caps
//                    coinbase bloat so the rest of the block holds fee-paying
//                    txs. W5 fills outputs in K_fair (oldest-first) order and
//                    STOPS at the first output that would exceed K_max; every
//                    remaining balance carries forward (strict oldest-first
//                    priority — never a younger output jumping an older one).
//   k_floor        — the per-byte floor coefficient k for h_min.
// ─────────────────────────────────────────────────────────────────────────

struct CoinbaseBudget {
    unsigned slot_budget_C = 0;     // fixed output-count cap
    u64      max_payout_bytes = 0;  // K_max: fixed payout byte budget (0 = unbounded)
    u64      k_floor = 0;           // h_min = k_floor * output_size(kind)
};

// One assembled coinbase output. `key` is the canonical identity (the K_fair
// name); `script` is the serialized scriptPubKey emitted on-chain.
struct AssembledOutput {
    bytes32                   key{};
    ScriptRef                 pay{};
    std::vector<std::uint8_t> script;
    u64                       amount = 0;
};

// ─────────────────────────────────────────────────────────────────────────
// (C) The §13 committed state — a Merkle tree over (summary leaf + per-key
// balance leaves), reusing the v37_lane digest/proof machinery (the SAME
// domain-separated leaf/interior rule; verification runs the SHIPPED static
// ::v37::Lane::verify_proof, so a headers-only device verifies one balance with
// an O(log n) proof against the root committed in the coinbase). We do NOT add
// a new tree kind: leaf = sha256d(0x00||payload), interior = sha256d(0x01||L||R),
// promote-odd — identical to Lane::{leaf_hash,interior_hash,merkle_root}, which
// are private, so W5 mirrors the construction here and verifies with the public
// Lane::verify_proof. Leaf order (fixed, canonical):
//   [0] summary leaf  "V37S" || chain(u64 LE) || ledger_seq(u64 LE)
//                          || num_balances(u64 LE) || owed_digest(32)
//   [1..] balance leaves "V37E" || key(32) || balance(u64 LE), key ASC.
// ─────────────────────────────────────────────────────────────────────────

class StateCommitment {
public:
    // Build from W4's ledger. Balances are the FINALIZED partition (finalW),
    // the same rows W4's owed_digest commits — positive rows only, key ASC.
    StateCommitment(const OwedLedger& ledger, u64 chain) {
        std::vector<std::pair<bytes32, u64>> rows;
        for (const auto& [k, w] : ledger.finalW())
            if (w > 0) rows.emplace_back(k, static_cast<u64>(w));
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        // [0] summary leaf.
        {
            std::vector<std::uint8_t> p;
            const char tag[4] = {'V', '3', '7', 'S'};
            p.insert(p.end(), tag, tag + 4);
            put_u64(p, chain);
            put_u64(p, ledger.ledger_seq());
            put_u64(p, static_cast<u64>(rows.size()));
            bytes32 od = ledger.owed_digest();
            p.insert(p.end(), od.begin(), od.end());
            m_leaves.push_back(leaf_hash(p));
            m_keys.push_back(bytes32{});  // summary has no key
        }
        // [1..] balance leaves.
        for (const auto& [k, w] : rows) {
            std::vector<std::uint8_t> p;
            const char tag[4] = {'V', '3', '7', 'E'};
            p.insert(p.end(), tag, tag + 4);
            p.insert(p.end(), k.begin(), k.end());
            put_u64(p, w);
            m_leaves.push_back(leaf_hash(p));
            m_keys.push_back(k);
        }
    }

    // The state root committed in the coinbase (whitepaper §13).
    bytes32 root() const { return merkle_root(m_leaves); }

    std::size_t leaf_count() const { return m_leaves.size(); }

    // Inclusion proof for one balance key. Fills the leaf hash and a
    // Lane::MerkleProof that ::v37::Lane::verify_proof accepts against root().
    // Returns false if the key has no positive finalized balance.
    bool prove(const bytes32& key, bytes32& leaf_out,
               ::v37::Lane::MerkleProof& proof_out) const {
        for (std::size_t i = 1; i < m_keys.size(); ++i) {  // skip [0] summary
            if (m_keys[i] == key) {
                leaf_out = m_leaves[i];
                proof_out = make_proof(m_leaves, static_cast<u64>(i));
                return true;
            }
        }
        return false;
    }

private:
    // ── the v37_lane tree rule, mirrored (Lane's copies are private) ──────
    static void put_u64(std::vector<std::uint8_t>& b, u64 x) {
        for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
    }
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return ::v37::sha256d(b);
    }
    static bytes32 interior_hash(const bytes32& l, const bytes32& r) {
        std::uint8_t b[65];
        b[0] = 0x01;
        std::copy(l.begin(), l.end(), b + 1);
        std::copy(r.begin(), r.end(), b + 33);
        return ::v37::sha256d(b, 65);
    }
    static bytes32 merkle_root(std::vector<bytes32> level) {
        if (level.empty()) return bytes32{};
        while (level.size() > 1) {
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);  // promote odd
            level = std::move(next);
        }
        return level[0];
    }
    static ::v37::Lane::MerkleProof make_proof(const std::vector<bytes32>& leaves,
                                               u64 idx) {
        ::v37::Lane::MerkleProof p;
        p.leaf_count = static_cast<u64>(leaves.size());
        p.index = idx;
        std::vector<bytes32> level = leaves;
        while (level.size() > 1) {
            bool odd_last = (level.size() & 1) && idx == level.size() - 1;
            if (!odd_last) p.path.push_back(level[idx ^ 1]);
            std::vector<bytes32> next;
            next.reserve((level.size() + 1) / 2);
            std::size_t i = 0;
            for (; i + 1 < level.size(); i += 2)
                next.push_back(interior_hash(level[i], level[i + 1]));
            if (i < level.size()) next.push_back(level[i]);
            level = std::move(next);
            idx /= 2;
        }
        return p;
    }

    std::vector<bytes32> m_leaves;
    std::vector<bytes32> m_keys;  // parallel to m_leaves; empty bytes32 for [0]
};

// ─────────────────────────────────────────────────────────────────────────
// (D) The assembled coinbase.
// ─────────────────────────────────────────────────────────────────────────

struct CoinbaseAssembly {
    std::vector<AssembledOutput> outputs;    // K_fair order (OLDEST-OWED-FIRST)
    bytes32     state_root{};                // §13 committed state root
    u64         total_paid = 0;              // Σ outputs[].amount
    u64         payout_bytes = 0;            // Σ output_size(kind), ≤ max_payout_bytes
    std::size_t carried = 0;                 // balances deferred (owed unchanged)
    bool        emitted = true;              // false when the buried-gate withheld all
};

// ─────────────────────────────────────────────────────────────────────────
// (E) assemble() — the W5 entry point. Consumes W4's K_fair selection verbatim
// (OwedLedger::propose_coinbase = oldest-owed-first + h_min carry), then applies
// the fixed byte budget K_max and serializes the outputs, and commits the §13
// state root. It MUTATES NOTHING in W4: the owed record for every unpaid balance
// is left untouched (carry-forward is simply the absence of an output; the next
// block's assemble() sees the same balance, now older, and pays it).
//
// `pay_of(key) -> ScriptRef`   resolves a canonical key to its payout ScriptRef
//                              (from the identity view; spec §2.4 / OI-W4-1).
// `raw_of(key) -> const std::vector<uint8_t>*`  optional: the kind-255 raw
//                              script for a RAW key (nullptr / omitted otherwise).
// ─────────────────────────────────────────────────────────────────────────

template <typename PayOf, typename RawOf>
inline CoinbaseAssembly assemble(const OwedLedger& ledger, u64 block_reward,
                                 const CoinbaseBudget& budget, PayOf&& pay_of,
                                 RawOf&& raw_of) {
    CoinbaseAssembly out;
    auto h_min_of = [&](ScriptKind k) { return h_min(k, budget.k_floor); };

    // K_fair selection is W4's — oldest-owed-first, h_min carry, value-bounded,
    // count-capped at C. W5 does not sort and does not re-implement E-1.
    OwedLedger::Proposal prop =
        ledger.propose_coinbase(block_reward, budget.slot_budget_C,
                                std::forward<PayOf>(pay_of), h_min_of);

    for (std::size_t i = 0; i < prop.outs.size(); ++i) {
        const auto& o = prop.outs[i];
        u64 sz = output_size(o.pay.kind);
        // Fixed byte budget (K_max): fill in strict K_fair order; the first
        // output that would exceed the budget STOPS assembly — it and every
        // remaining (younger) balance carry forward. A greedy skip-and-continue
        // would let a younger cheap output jump an older expensive one, breaking
        // oldest-first priority, so we stop.
        if (budget.max_payout_bytes != 0 &&
            out.payout_bytes + sz > budget.max_payout_bytes) {
            out.carried += (prop.outs.size() - i);
            break;
        }
        const std::vector<std::uint8_t>* raw = raw_of(o.key);
        AssembledOutput a;
        a.key = o.key;
        a.pay = o.pay;
        a.script = output_script(o.pay, raw);
        a.amount = o.amount;
        out.total_paid += o.amount;
        out.payout_bytes += sz;
        out.outputs.push_back(std::move(a));
    }

    StateCommitment sc(ledger, ledger.chain());
    out.state_root = sc.root();
    return out;
}

// Overload without a RAW resolver (all payees are known templates).
template <typename PayOf>
inline CoinbaseAssembly assemble(const OwedLedger& ledger, u64 block_reward,
                                 const CoinbaseBudget& budget, PayOf&& pay_of) {
    return assemble(ledger, block_reward, budget, std::forward<PayOf>(pay_of),
                    [](const bytes32&) -> const std::vector<std::uint8_t>* {
                        return nullptr;
                    });
}

// ─────────────────────────────────────────────────────────────────────────
// (F) The buried gate (whitepaper §9 / spec §4.7, coinbase-prioritization
// Rule 6). A payment is EMITTED only once the paying block is buried beyond
// D_conf on its own coin chain (the SETTLED gate W4 applies at FINALIZE), so
// nothing is ever paid twice; a block orphaned before D_conf is never emitted.
// W5 does not itself track depth — the caller passes the block's own-chain
// confirmation depth and canonical flag (block_confirm.hpp oracle shape, spec
// §4.7) — W5 decides emission. On the withheld path the returned assembly is
// EMPTY and `emitted=false` (nothing is put on-chain); the owed ledger is
// untouched, so a later, buried block re-mints the same balances.
// ─────────────────────────────────────────────────────────────────────────

struct BurialGate {
    u64  d_conf = 0;            // per-chain confirmation depth (>= coinbase maturity)
    bool canonical = true;      // false ⇒ the block is orphaned
    u64  confirmations = 0;     // the block's own-chain depth
    bool buried() const { return canonical && confirmations >= d_conf; }
};

template <typename PayOf, typename RawOf>
inline CoinbaseAssembly assemble_if_buried(const OwedLedger& ledger,
                                           u64 block_reward,
                                           const CoinbaseBudget& budget,
                                           const BurialGate& gate, PayOf&& pay_of,
                                           RawOf&& raw_of) {
    if (!gate.buried()) {
        CoinbaseAssembly withheld;
        withheld.emitted = false;   // orphaned-or-unburied: emit nothing
        return withheld;
    }
    return assemble(ledger, block_reward, budget, std::forward<PayOf>(pay_of),
                    std::forward<RawOf>(raw_of));
}

template <typename PayOf>
inline CoinbaseAssembly assemble_if_buried(const OwedLedger& ledger,
                                           u64 block_reward,
                                           const CoinbaseBudget& budget,
                                           const BurialGate& gate, PayOf&& pay_of) {
    return assemble_if_buried(ledger, block_reward, budget, gate,
                              std::forward<PayOf>(pay_of),
                              [](const bytes32&) -> const std::vector<std::uint8_t>* {
                                  return nullptr;
                              });
}

}  // namespace c2pool::v37n::coinbase
