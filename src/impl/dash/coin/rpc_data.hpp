// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Parsed getblocktemplate response with Dash-specific fields.
// Reference: ref/p2pool-dash/p2pool/dash/helper.py::getwork()

#include "transaction.hpp"

#include <atomic>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

namespace dash
{
namespace coin
{

// gbt_xcheck_dashd_only_collateral.hpp: the committed fold kept for the
// GBT-xcheck label (DashWorkData::m_xcheck_collateral_aid). Complete only
// where it is built (embedded_gbt.hpp) and read (stratum/work_source.cpp).
struct XcheckCollateralAid;

// One masternode / superblock / platform payment entry after normalization.
// payee == "!" + hex_script when the payment is a raw script (OP_RETURN
// platform payment); otherwise payee is a base58 address.
struct PackedPayment {
    std::string payee;
    uint64_t    amount{0};
};

// Normalize ONE masternode / superblock / platform payment entry from a dashd
// getblocktemplate/getwork response into a PackedPayment.
//
// bad-cb-payee TRAP: dashd surfaces the platform credit-pool OP_RETURN burn as
// a masternode[] entry shaped {"payee":"", "script":"6a", "amount":N} -- the
// payee field is PRESENT but an EMPTY string. The empty string must NOT win the
// address branch: a "" payee flows into the base58 decode path downstream, fails
// to decode, and the whole burn output is silently dropped -> missing-payee /
// bad-cb-payee on submit. Require a NON-EMPTY payee before treating it as a
// base58 address; otherwise fall through to the raw "!"+script form so the burn
// output is preserved byte-for-byte.
inline PackedPayment normalize_payment(const nlohmann::json& entry)
{
    PackedPayment pp;
    if (entry.is_object())
    {
        if (entry.contains("payee") && entry["payee"].is_string()
            && !entry["payee"].get<std::string>().empty())
            pp.payee = entry["payee"].get<std::string>();
        else if (entry.contains("script") && entry["script"].is_string())
            pp.payee = "!" + entry["script"].get<std::string>();
        if (entry.contains("amount"))
            pp.amount = entry["amount"].get<uint64_t>();
    }
    return pp;
}

// Classify a dashd `submitblock` RPC result under the dual-path won-block
// contract (M1). submitblock returns null on accept; a non-null string is a
// reject reason. A "duplicate" / "inconclusive" / "already-have" result means
// the block is ALREADY on the network — the OTHER broadcast arm (embedded P2P
// relay, or a peer) landed it first — which is SUCCESS (the block reached the
// network), NOT a failure. "duplicate-invalid" is the one exception: the block
// was rejected as invalid, a genuine failure. Pure over the JSON so the KAT can
// pin it without a live RPC client.
inline bool submitblock_result_accepted(const nlohmann::json& result)
{
    if (result.is_null()) return true;
    if (!result.is_string()) return false;
    std::string code = result.get<std::string>();
    for (char& c : code)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    const bool already_have = code == "duplicate"
                           || code.find("inconclusive") != std::string::npos
                           || code.find("already") != std::string::npos;
    return already_have && code.find("invalid") == std::string::npos;
}

// ── NON-CONSENSUS: what happened to each configured pinned local tx on THIS
// template. One entry per configured pin, in file order, written by the splice
// that judges it.
//
// It exists because a pin that is simply ABSENT is indistinguishable from a pin
// that was never considered, and that ambiguity cost the donation on block
// 2518044 (2026-08-07): the embedded builder logged four `pinned tx INCLUDED`
// lines, the GBT-xcheck backstop swapped in dashd's template 57 ms later, and
// the served template carried neither the pins nor one word about them.
//
// Never serialized, never hashed, never read by any consensus path -- the block
// assembler reads m_txs / m_tx_data_hex only. It is the ANSWER a test can assert
// on without scraping a log line.
struct PinOutcome {
    uint256     txid;
    bool        included{false};
    /// Named refusal reason when !included; empty when included.
    std::string cause;
    /// The height the pin GATE judged at (our tip + 1), and the height of the
    /// template the pin was offered to. They are separate numbers because the
    /// gate runs beside the coin state and the template may come from dashd.
    uint32_t    gate_height{0};
    uint32_t    template_height{0};
    /// Sum of the pin's outputs, in satoshi. This is WHAT IS LOST when the pin
    /// does not ride a template that then wins: the donation is a zero-fee
    /// self-spend, so its output total is the whole amount at stake. Recorded
    /// so the drop alarm can name a number instead of a count.
    int64_t     value{0};
};

// ── ONE SHARED TX-HEX VECTOR PER STORED TEMPLATE ─────────────────────────
// Hex characters held by every live TemplateTxHex vector, process-wide: up
// when the work source's template store encodes one, down when the last job
// referencing it is dropped. Relaxed atomic: a gauge, not a synchronization
// point.
inline std::atomic<int64_t>& live_template_hex_chars_counter() noexcept
{
    static std::atomic<int64_t> n{0};
    return n;
}
inline int64_t live_template_hex_chars() noexcept
{
    return live_template_hex_chars_counter().load(std::memory_order_relaxed);
}

// The tx-hex vector every stratum job (and every v36 frozen mint job) built
// over ONE stored template carries. Before, each job copied the template's
// m_tx_data_hex into a vector of its own: once per session per notify on the
// io thread, and one copy per retained job.
//
// Encoded once by DASHWorkSource's template store, just before the template
// becomes the immutable cached snapshot (shared_ptr<const DashWorkData>), from
// that template's own m_tx_data_hex. It lives inside the template it was
// encoded from, so a job can never pair one template's merkle branches with
// another template's bodies, on any thread.
//
// REUSE. A rebuild whose bodies are the previous stored template's bodies, in
// the same order (template_tx_hex_reusable below), takes the previous vector
// (reuse()) instead of encoding the same strings again. The vector holds the
// tx bodies and nothing else, so that vector IS the new template's bodies; the
// new template still gets its own seq.
//
// A COPY STARTS EMPTY. Copying a DashWorkData makes another template instance,
// which may then be mutated (a pin splice, a test that drops a body); it must
// never inherit a vector encoded from the original. Readers holding a template
// without one fall back to a fresh copy (job_tx_hex below), which is exactly
// what every job carried before. Moves keep the vector (the store moves the
// template into its cached snapshot).
class TemplateTxHex {
public:
    TemplateTxHex() = default;
    TemplateTxHex(const TemplateTxHex&) noexcept {}
    TemplateTxHex& operator=(const TemplateTxHex& other) noexcept
    {
        if (this != &other) *this = TemplateTxHex{};
        return *this;
    }
    TemplateTxHex(TemplateTxHex&&) noexcept = default;
    TemplateTxHex& operator=(TemplateTxHex&&) noexcept = default;

    /// Encode `bodies` once. `seq` names the stored template instance (the
    /// store's own counter; > 0). The copy is the only O(bytes) step.
    static TemplateTxHex encode(const std::vector<std::string>& bodies, uint64_t seq)
    {
        int64_t chars = 0;
        for (const auto& h : bodies) chars += static_cast<int64_t>(h.size());
        std::unique_ptr<std::vector<std::string>> v(new std::vector<std::string>(bodies));
        live_template_hex_chars_counter().fetch_add(chars, std::memory_order_relaxed);
        TemplateTxHex t;
        // On a throw here the deleter runs and takes the count back down.
        t.m_hex = std::shared_ptr<const std::vector<std::string>>(
            v.release(), [chars](const std::vector<std::string>* p) {
                live_template_hex_chars_counter().fetch_sub(chars, std::memory_order_relaxed);
                delete p;
            });
        t.m_body_bytes = static_cast<uint64_t>(chars) / 2;
        t.m_seq        = seq;
        return t;
    }

    /// The vector `from` holds, for the stored template `seq` names. Only for
    /// a template whose bodies are byte-identical to the ones `from` was
    /// encoded from, in the same order (template_tx_hex_reusable). Moves no
    /// gauge: still one vector, counted once, until its last holder drops it.
    static TemplateTxHex reuse(const TemplateTxHex& from, uint64_t seq) noexcept
    {
        TemplateTxHex t;
        t.m_hex        = from.m_hex;
        t.m_body_bytes = from.m_body_bytes;
        t.m_seq        = seq;
        return t;
    }

    explicit operator bool() const noexcept { return static_cast<bool>(m_hex); }
    const std::shared_ptr<const std::vector<std::string>>& hex() const noexcept { return m_hex; }
    /// Serialized bytes of the bodies (hex characters / 2).
    uint64_t body_bytes() const noexcept { return m_body_bytes; }
    /// The store sequence of the template it was encoded for, or reused by
    /// (0: none).
    uint64_t seq() const noexcept { return m_hex ? m_seq : 0; }

private:
    std::shared_ptr<const std::vector<std::string>> m_hex;
    uint64_t m_body_bytes{0};
    uint64_t m_seq{0};
};

struct DashWorkData {
    // Raw getblocktemplate JSON response (kept for fallback access to fields
    // we haven't promoted to members yet).
    nlohmann::json m_raw;

    // Standard Bitcoin-family fields.
    int32_t               m_version{0};
    uint256               m_previous_block;
    uint32_t              m_height{0};
    uint64_t              m_coinbase_value{0};   // "coinbasevalue" in sat
    uint32_t              m_bits{0};
    uint32_t              m_curtime{0};
    uint32_t              m_mintime{0};
    std::string           m_coinbase_flags_hex;

    // Transactions from GBT (parsed into full tx objects + their ids).
    std::vector<Transaction> m_txs;
    std::vector<uint256>  m_tx_hashes;
    std::vector<uint64_t> m_tx_fees;
    // Raw "data" hex for each transaction — kept so we can assemble a full
    // block to submit via submitblock when a miner wins.
    std::vector<std::string> m_tx_data_hex;
    // m_tx_data_hex encoded ONCE for every job built over this template (see
    // TemplateTxHex), or the previous stored template's vector when it holds
    // the same bodies (template_tx_hex_reusable). Set only by the work
    // source's template store, on the instance it then caches; empty on every
    // other DashWorkData and on any copy. Read it through job_tx_hex().
    TemplateTxHex m_tx_hex_shared;

    // Dash-specific ------------------------------------------------------------
    // Normalized list of masternode + superblock + platform payments, in the
    // exact order they must appear in the coinbase outputs.
    std::vector<PackedPayment> m_packed_payments;

    // Sum of all m_packed_payments[i].amount — this is the portion of the
    // block reward that miners do NOT receive (masternode+treasury share).
    uint64_t m_payment_amount{0};

    // DIP3/DIP4 coinbase extra payload (raw bytes, hex-decoded from GBT).
    // Empty if the daemon did not return one.
    std::vector<uint8_t> m_coinbase_payload;

    // RPC round-trip latency (seconds).
    int64_t m_latency{0};

    // ── NON-CONSENSUS diagnostic: "this template's tx set is empty ON PURPOSE"
    // Empty string = normal template (mempool selection ran as usual). Non-empty
    // = the embedded builder DELIBERATELY served a coinbase-only body and this
    // names WHY (currently only "utxo-immature-serving"). Never serialized, never
    // read by any consensus path -- it exists so the node can SAY it is in the
    // degraded-but-valid serving mode instead of running there silently, and so a
    // soak can measure both the duration and the price.
    //
    // m_txset_forgone_fees is the mempool's total KNOWN fees at build time: the
    // upper bound on what a fully-populated template could have collected. It is
    // an upper bound, not the exact loss (selection also drops unknown-fee,
    // special, and MN-collateral-spending txs), so read it as "at most this much".
    std::string m_txset_empty_cause;
    uint64_t    m_txset_forgone_fees{0};

    // ── THE CANDIDATE SET (observe-without-arming) ────────────────────────
    // What selection WOULD have chosen, recorded when the served body is
    // deliberately coinbase-only. NEVER served: these ids/fees are not in
    // m_txs, m_tx_hashes, m_tx_fees or m_tx_data_hex, contribute nothing to
    // m_coinbase_value, and no consensus path reads them.
    //
    // They exist because the gate that must pass BEFORE fee-carrying
    // templates are enabled cannot be evaluated from templates built while
    // that flag is OFF: the served set is empty by construction, so a
    // coverage measurement over it reads 0% forever and the only ways left to
    // evaluate the gate are to arm the money path first (exactly what the
    // gate prevents) or to enable on faith. Measuring the candidate set is
    // what makes the fee lane completable at all.
    std::vector<uint256>  m_txset_candidates;
    std::vector<uint64_t> m_txset_candidate_fees;
    // Wire-form hex of each candidate, parallel to m_txset_candidates. The
    // MEMPOOL VALIDITY GATE (mempool_validity_gate.hpp) feeds these to dashd's
    // testmempoolaccept: the condition that decides whether
    // --embedded-serve-mempool-txs may be armed cannot be evaluated from ids
    // alone, and while the flag is OFF the candidate set is the ONLY place the
    // transactions we would serve exist. Diagnostic: no consensus path reads it.
    std::vector<std::string> m_txset_candidate_data_hex;

    // ── THE MEMPOOL-SOURCED RANGE OF THE SERVED BODY ──────────────────────
    // When the template DOES carry mempool transactions they are appended
    // LAST, after the consensus-mandatory type-6 quorum commitments and any
    // pinned local tx, so they occupy the contiguous range
    // [m_mempool_tx_first_index, m_mempool_tx_first_index + m_mempool_tx_count)
    // of m_txs / m_tx_hashes / m_tx_fees / m_tx_data_hex.
    //
    // The validity gate must probe EXACTLY that range and nothing else: a
    // type-6 commitment and a zero-fee pinned tx are both refused by relay
    // policy BY DESIGN, so probing them would manufacture INVALID verdicts out
    // of correct behaviour. Carried as a RANGE rather than a second copy of
    // the hex so the money path does not grow a duplicate block body for a
    // diagnostic. count == 0 means "no mempool-sourced tx in this body".
    uint32_t m_mempool_tx_first_index{0};
    uint32_t m_mempool_tx_count{0};

    // ── GBT-XCHECK CLASSIFICATION AID: EXCLUDED COLLATERAL SPENDS ─────────
    // The embedded builder EXCLUDES every type-0 tx that spends a masternode
    // collateral (sml_projection.hpp tx_spends_mn_collateral), plus its
    // in-body descendants. dashd's miner includes such a tx and removes the
    // MN, so the two templates' merkleRootMNList legitimately differ while
    // the spend sits in the mempool.
    //
    // m_xcheck_collateral_alt_mnroot is the root the builder's OWN fold
    // (fold_mn_special_txs, same projected list, same fold context as the
    // committed root) gives for the served body PLUS those excluded txs; null
    // when nothing was excluded or the fold path was not armed. The GBT-xcheck
    // uses it ONLY to LABEL an MN-root difference (gbt_xcheck_collateral.hpp):
    // serving is unchanged, any root difference still swaps to dashd. No
    // consensus path reads these fields.
    uint256              m_xcheck_collateral_alt_mnroot;
    std::vector<uint256> m_xcheck_collateral_excluded_txids;

    // ── GBT-XCHECK CLASSIFICATION AID: COLLATERAL SPENDS ONLY DASHD HAS ───
    // The committed fold's result list and its collateral index
    // (gbt_xcheck_dashd_only_collateral.hpp), for a spend our candidate set
    // never had (testnet h=1592649: not in our pool, so no builder exclusion).
    // Set only when the node runs the GBT-xcheck (want_xcheck_aid); null
    // otherwise, so a daemonless node pays nothing. Shared, never served, and
    // no consensus path reads it.
    std::shared_ptr<const XcheckCollateralAid> m_xcheck_collateral_aid;

    // Per-entry "this tx spends an output of an EARLIER entry of the same
    // probe set" flag, parallel to whichever probe set is populated (the
    // served range above, or the candidate set). dashd's testmempoolaccept
    // takes ONE transaction, so a child probed alone answers `missing-inputs`
    // when its parent is only in OUR template — an artefact of the probe, not
    // a defect of the transaction. The flag is computed at build time from the
    // real vins, so the exemption is a FACT about the set rather than an
    // inference from a reject string. Diagnostic: no consensus path reads it.
    std::vector<uint8_t>  m_mempool_probe_depends_in_set;

    // -- EMBEDDED TX-SERVE INTERNAL-CONSISTENCY STAMP -----------------------
    // Written ONLY by the embedded builder when it produces a mempool-tx-
    // carrying body (embedded_gbt.hpp; armed == !suppress_mempool_txs). The
    // serve-time internal-consistency referee (tx_serve_referee.hpp) reads it
    // to decide whether c2pool may serve ITS OWN valid tx set instead of
    // falling back to dashd merely because our tx-merkle-root differs. A
    // divergent-but-internally-consistent set is a NORMAL, perfectly valid
    // block; the safety requirement is per-tx validity + no double-spend +
    // coinbase fee-consistency, NOT tx-set parity with dashd.
    //
    // The two facts here are the ones the referee cannot re-derive from the
    // wire body alone: whether every mempool-range tx passed the fee-fold
    // proof (mempool.hpp exclusion-discipline: the vin-present/unspent,
    // in_sum>=out_sum guarantee), and the treasury/superblock slice that was
    // added to m_coinbase_value on a funded superblock height (so the referee
    // can assert m_coinbase_value == subsidy + Sum(m_tx_fees) + superblock).
    // armed == false on every non-serving build (coinbase-only, dashd
    // fallback) -> the referee never runs and behaviour is byte-identical.
    struct EmbeddedTxServeStamp {
        // The mempool-serving path produced this body (--embedded-serve-
        // mempool-txs ON at build time). When false the referee is dormant.
        bool     armed{false};
        // Every tx in the mempool-sourced range [m_mempool_tx_first_index,
        // +m_mempool_tx_count) passed the fee-fold proof at selection. The
        // selector already refuses non-proven entries (mempool.hpp:~1018
        // "if(!e.fee_fold_proven) continue;"); this records that guarantee so
        // the referee can fail-close if a future selection path ever admits an
        // unproven tx.
        bool     all_mempool_fee_fold_proven{false};
        // Treasury payout total added to m_coinbase_value at a funded
        // superblock height (0 on every ordinary block). Lets the referee
        // reconstruct the coinbase value exactly from (subsidy + fees +
        // superblock) rather than approximating it.
        uint64_t superblock_total{0};
    };
    EmbeddedTxServeStamp m_tx_serve_stamp;

    // ── PIN OUTCOMES (see PinOutcome above) ───────────────────────────────
    // One entry per configured pinned local tx, written by the splice on the
    // SERVED dashd-fallback arm. Empty on the embedded arm (which splices in
    // its own builder and logs there) and empty when no pin is configured.
    std::vector<PinOutcome> m_pin_outcomes;

    // ── THE DROP ALARM (non-consensus) ────────────────────────────────────
    // Non-empty when this SERVED template is missing at least one configured
    // pin. It names the count, the height, the satoshi value at stake and the
    // cause(s), because "pins=0/4" on its own does not tell an operator that
    // money is going missing or why.
    //
    // The flag-off xcheck-swap arm is the case this exists for: with
    // --pin-splice-xcheck-arm at its default the donation is DELIBERATELY not
    // spliced, and a deliberate loss that is only visible as an INFO line is
    // operationally identical to the silent loss that cost h=2518044.
    std::string m_pin_drop_alarm;

    // ── BLOCK-BUDGET NOT ENFORCED (non-consensus) ─────────────────────────
    // True when a pin was appended even though it pushed the template past
    // kMaxPinnedBlockBytes, because --pin-splice-block-budget is OFF (the
    // default: enforcing it CHANGES SERVED BYTES on the already-live
    // declined-embedded arm, so it may not be on by default). The block may be
    // rejected as bad-blk-length if it wins. Always accompanied by a WARNING.
    bool m_pin_block_budget_unenforced{false};
};

// The tx-hex vector a job built over `wd` carries: the template's own shared
// vector when the store encoded one, else a fresh copy of its bodies (the only
// form before the shared vector existed, kept for templates that never went
// through the store and for copies).
inline std::shared_ptr<const std::vector<std::string>> job_tx_hex(const DashWorkData& wd)
{
    if (wd.m_tx_hex_shared) return wd.m_tx_hex_shared.hex();
    return std::make_shared<const std::vector<std::string>>(wd.m_tx_data_hex);
}

// Whether a body's txid may leave some of the body's bytes out. A Dash txid is
// the SHA256d of the whole serialization, with one exception: the Dash Core
// v24 stable txid of a version-2 asset unlock (special tx type 9) zeroes the
// last 132 bytes (requestedHeight, quorumHash, quorumSig) first
// (dash_txid.hpp), so every re-signed instance of one withdrawal has the same
// txid and other bytes. Read off the serialized version field (int32 LE of
// nVersion | nType << 16, so bytes 2..3 are nType): no parse, and no type-9
// body is missed. It flags every type-9 body; a flag costs one string compare.
inline bool txid_may_omit_body_bytes(const std::string& body_hex) noexcept
{
    return body_hex.size() >= 8 && body_hex[4] == '0' && body_hex[5] == '9'
        && body_hex[6] == '0' && body_hex[7] == '0';
}

// Whether two index-aligned body lists that sit under EQUAL tx-hash lists hold
// the same bodies. Equal txids pin equal bytes for every body except one whose
// txid may leave bytes out (txid_may_omit_body_bytes): those must be
// byte-equal too, or a re-signed asset unlock would be served with its old
// instance's bytes. Lists of different sizes never match.
inline bool bodies_match_under_equal_txids(const std::vector<std::string>& was,
                                           const std::vector<std::string>& now) noexcept
{
    if (was.size() != now.size()) return false;
    for (size_t i = 0; i < now.size(); ++i) {
        if ((txid_may_omit_body_bytes(now[i]) || txid_may_omit_body_bytes(was[i]))
            && was[i] != now[i])
            return false;
    }
    return true;
}

// The template store's reuse rule: may the template `next` carry the vector
// `prev` carries (TemplateTxHex::reuse) instead of a fresh encode? Only when
// that vector holds exactly next's bodies, in next's order:
//   * prev carries a vector, and both templates are on the same tip (below);
//   * the tx-hash lists are equal as ORDERED lists. The order is the block
//     body: the same txs in another order are another body, a fresh vector;
//   * the counts agree: next's hashes, next's bodies, the vector;
//   * every body whose txid may leave bytes out (txid_may_omit_body_bytes) is
//     byte-equal to the vector's body at that index. A re-signed asset unlock
//     keeps its txid and changes its bytes, and the coinbase's v24
//     merkleRootAssetUnlocks commits the bytes. Every other body is pinned by
//     its txid, the SHA256d of all of its bytes.
//
// A TIP CHANGE NEVER REUSES, even with an equal list. The vector holds the tx
// bodies only (no coinbase, height or header), so the bodies alone decide its
// content. But the one txid that does not cover all of its body's bytes
// changes those bytes at a height boundary: a withdrawal is re-signed when its
// requestedHeight window or its quorum runs out. The byte check covers that;
// the tip rule is a second, independent barrier at exactly that boundary. It
// costs nothing measurable: a new block nearly always mines some of the
// template's txs, and a coinbase-only template's vector is empty. The memo in
// build_producer_job (mint_runloop.hpp) applies the same body rule
// (bodies_match_under_equal_txids), on any tip.
inline bool template_tx_hex_reusable(const DashWorkData& prev, const DashWorkData& next)
{
    const auto& v = prev.m_tx_hex_shared.hex();
    if (!v) return false;
    if (prev.m_previous_block != next.m_previous_block) return false;
    const size_t n = next.m_tx_hashes.size();
    if (next.m_tx_data_hex.size() != n || v->size() != n) return false;
    if (prev.m_tx_hashes != next.m_tx_hashes) return false;
    return bodies_match_under_equal_txids(*v, next.m_tx_data_hex);
}

} // namespace coin
} // namespace dash