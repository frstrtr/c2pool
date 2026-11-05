// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Hybrid MWEB extension (#2137 S3, DESIGN option b): with a local litecoind
/// the embedded LTC template carries litecoind's MWEB extension -- its
/// mw::Block, its HogEx and the peg-in transactions the HogEx spends --
/// instead of the empty body, after checking it against c2pool's own
/// PoW-bound MWEB state of the tip (MWEBTracker). Any failure leaves the
/// template as it is today: the empty body and c2pool's own HogEx, never a
/// template without a HogEx.
///
/// What is imported from G = litecoind getblocktemplate {rules:[mweb,segwit]}
/// (only when G.previousblockhash is the tip):
///   - the HogEx (G's last entry) and G.mweb;
///   - every entry with a pegin output (OP_9 PUSH32 <kernel id>), with the
///     closure of its "depends" inside G (the ancestors ship with it), in G
///     order;
///   - litecoind's per-entry "fee" of each (a peg-in's includes its kernel
///     fee) and the HogEx's (the fees of the MWEB-only txs).
///
/// Checks before use (check_extension; any failure -> the empty body):
///   0 G is for the tip: previousblockhash and height (prev-mismatch);
///   1 HogEx vin[0] is the tip's HogEx output 0 (prev-hogex-mismatch);
///   2 HogEx vin[1..] are exactly the pegin outputs of the imported txs, in
///     order (template_txs_check rule 7: pegins-missing, pegin-mismatch,
///     extra-hogex-input);
///   3 the HogAddr commits to blake3(mweb header), the header height is the
///     next height, its kernel count is the body's and the body walks to its
///     last byte (mweb-hash-mismatch, mweb-height-mismatch,
///     kernel-count-mismatch, mweb-body-malformed);
///   4 the value: peg-in coins == the body's peg-in kernels (litecoind
///     ValidatePegInCoins), HogEx vout[1..] == the body's peg-outs as a
///     multiset (ValidatePegOutCoins), HogAddr value == the tip's HogAddr
///     value + peg-ins - peg-outs - kernel fees (mweb-amount-mismatch), HogEx
///     fee == the body's kernel fees (bad-txns-mweb-fee-mismatch); the listed
///     fees never claim more than the body and G carry;
///   5 the carried state: with an empty body the header is exactly
///     next_empty_header(tip's header); otherwise its txo count is the tip's
///     plus the body's outputs, and the roots no output / no input can
///     change are the tip's.
/// What stays trusted (not re-derivable without the MWEB UTXO state): the
/// body's validity (signatures, range proofs, sums), the new output and
/// leafset roots and the kernel offset of a non-empty body, and each
/// imported entry's fee -- the trust --coin-rpc mode places in litecoind for
/// the whole block, confined to the extension.
///
/// Header-only and pure apart from MwebExtSource, the thread-safe holder of
/// the latest G and of the /local_stats counters.

#include "mweb_builder.hpp"
#include "mweb_tx_wire.hpp"
#include "transaction.hpp"

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/coin/mweb_shape.hpp>
#include <core/coin/template_txs_check.hpp>
#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ltc {
namespace coin {
namespace mweb_ext {

// ─── Reason codes ───────────────────────────────────────────────────────────

// G is not for the tip, or there is no G: expected around tip changes and
// while litecoind is unreachable (counted, logged at INFO once per height).
inline constexpr const char* kPrevMismatch = "prev-mismatch";
inline constexpr const char* kUnavailable = "unavailable";
// Everything else is a consistency failure (counted, one WARNING per height).
inline constexpr const char* kGMalformed = "g-malformed";
inline constexpr const char* kNoMweb = "no-mweb";
inline constexpr const char* kGHeightMismatch = "g-height-mismatch";
inline constexpr const char* kHogexNotLast = "hogex-not-last";
inline constexpr const char* kHogexMalformed = "hogex-malformed";
inline constexpr const char* kEntryMalformed = "entry-malformed";
inline constexpr const char* kEntryCarriesMwebData = "entry-carries-mweb-data";
inline constexpr const char* kTxidMismatch = "txid-mismatch";
inline constexpr const char* kWtxidMismatch = "wtxid-mismatch";
inline constexpr const char* kStateNotForTip = "state-not-for-tip";
inline constexpr const char* kPrevHogexMismatch = "prev-hogex-mismatch";
inline constexpr const char* kMwebBodyMalformed = "mweb-body-malformed";
inline constexpr const char* kKernelCountMismatch = "kernel-count-mismatch";
inline constexpr const char* kPeginKernelMismatch = "pegin-kernel-mismatch";
inline constexpr const char* kPegoutMismatch = "pegout-mismatch";
inline constexpr const char* kHogaddrValueMismatch = "hogaddr-value-mismatch";
inline constexpr const char* kHogexFeeMismatch = "hogex-fee-mismatch";
inline constexpr const char* kHogexFeeEntryTooHigh = "hogex-fee-entry-too-high";
inline constexpr const char* kPeginFeeBelowKernelFee = "pegin-fee-below-kernel-fee";
inline constexpr const char* kFeeExceedsG = "fee-exceeds-g";
inline constexpr const char* kCarriedStateMismatch = "carried-state-mismatch";
inline constexpr const char* kTxoCountMismatch = "txo-count-mismatch";
// The merged template failed core::coin::check_template_txs / fee-reconcile
// (prefix; the rule's code follows).
inline constexpr const char* kMergedCheckPrefix = "merged-";

// Templates that never import (counted under "skipped").
inline constexpr const char* kSkipNotFull = "not-full-template";
inline constexpr const char* kSkipNoMwebState = "no-mweb-state";

/// True for the reasons that are no consistency failure (INFO, not WARNING).
inline bool reason_is_expected(const std::string& r)
{
    return r == kPrevMismatch || r == kUnavailable;
}

inline constexpr int64_t kMaxMoney = 84'000'000LL * 100'000'000LL;  // litecoind MAX_MONEY
inline bool money_range(int64_t v) { return v >= 0 && v <= kMaxMoney; }

// ─── The parsed extension ───────────────────────────────────────────────────

using Outpoint = std::pair<uint256, uint32_t>;

/// One imported G entry, walked.
struct ImportedTx {
    std::string hex;            // G "data"
    uint256 txid;               // computed (== G "txid")
    uint256 wtxid;              // computed (== G "hash" when present)
    int64_t fee{0};             // G "fee"
    uint64_t weight{0};         // litecoind GetTransactionWeight
    size_t g_index{0};          // into G.transactions
    bool pegin{false};          // has a pegin output
    std::vector<Outpoint> prevouts;
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> vout;
    MutableTransaction tx;      // the same, deserialized (WorkData m_txs)
};

/// litecoind's extension for the block on `prev`, parsed (parse_extension).
struct ExtensionBundle {
    uint256 prev;
    uint32_t height{0};
    int64_t coinbasevalue{0};
    std::vector<ImportedTx> txs;     // peg-ins and their ancestors, G order
    ImportedTx hogex;                // G's last entry
    MutableTransaction hogex_tx;     // the same, deserialized
    std::string mweb_hex;            // G "mweb" (an mw::Block, no OptionalPtr byte)
    MWEBHeader header;
    mweb_wire::MwebBodySummary body;
    std::set<Outpoint> spent;        // every input of txs
    std::set<uint256> txids;         // of txs

    int64_t fee_hogex() const { return hogex.fee; }
    int64_t txs_fee() const
    {
        int64_t s = 0;
        for (const auto& t : txs)
            s += t.fee;
        return s;
    }
    uint64_t weight() const
    {
        uint64_t w = hogex.weight;
        for (const auto& t : txs)
            w += t.weight;
        return w;
    }
    size_t n_pegins() const
    {
        return static_cast<size_t>(std::count_if(txs.begin(), txs.end(),
                                                 [](const ImportedTx& t) { return t.pegin; }));
    }
    bool body_empty() const
    {
        return body.n_inputs == 0 && body.n_outputs == 0 && body.kernels.empty();
    }
};

struct ParseResult {
    std::shared_ptr<const ExtensionBundle> bundle;  // set when it parsed
    std::string reason;                              // else why not
    std::string detail;
};

namespace detail {

inline bool is_hex64(const std::string& s)
{
    if (s.size() != 64)
        return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

inline ParseResult fail(const char* reason, std::string detail)
{
    ParseResult r;
    r.reason = reason;
    r.detail = std::move(detail);
    return r;
}

/// The wtxid of a walked transaction: its txid without a witness, else
/// SHA256d of the whole serialization (an imported entry carries no MWEB
/// data, so that is litecoind's ComputeWitnessHash).
inline uint256 wtxid_of(const core::coin::TxShape& t, const std::vector<unsigned char>& bytes)
{
    if (t.witness_size == 0)
        return t.txid;
    return Hash(std::span<const unsigned char>(bytes.data(), bytes.size()));
}

} // namespace detail

/// Parse G (the "result" of getblocktemplate). Pure; never throws.
inline ParseResult parse_extension(const nlohmann::json& g)
{
    using detail::fail;
    try {
        if (!g.is_object())
            return fail(kGMalformed, "not an object");
        if (!g.contains("previousblockhash") || !g["previousblockhash"].is_string()
            || !detail::is_hex64(g["previousblockhash"].get<std::string>()))
            return fail(kGMalformed, "previousblockhash");
        if (!g.contains("height") || !g["height"].is_number_integer() || g["height"].get<int64_t>() <= 0
            || g["height"].get<int64_t>() > 0x7fffffff)
            return fail(kGMalformed, "height");
        if (!g.contains("coinbasevalue") || !g["coinbasevalue"].is_number_integer()
            || !money_range(g["coinbasevalue"].get<int64_t>()))
            return fail(kGMalformed, "coinbasevalue");
        // Before the transactions: without MWEB (not active on that chain)
        // litecoind's template has no HogEx, and may have no tx at all.
        if (!g.contains("mweb") || !g["mweb"].is_string() || g["mweb"].get<std::string>().empty())
            return fail(kNoMweb, "no mweb field (MWEB not active on litecoind?)");
        if (!g.contains("transactions") || !g["transactions"].is_array() || g["transactions"].empty())
            return fail(kGMalformed, "transactions");

        auto x = std::make_shared<ExtensionBundle>();
        x->prev.SetHex(g["previousblockhash"].get<std::string>());
        x->height = static_cast<uint32_t>(g["height"].get<int64_t>());
        x->coinbasevalue = g["coinbasevalue"].get<int64_t>();

        const auto& entries = g["transactions"];
        const size_t n = entries.size();
        std::vector<core::coin::TxShape> shapes(n);
        std::vector<std::vector<unsigned char>> raw(n);
        for (size_t i = 0; i < n; ++i) {
            const auto& e = entries[i];
            if (!e.is_object() || !e.contains("data") || !e["data"].is_string()
                || !e.contains("txid") || !e["txid"].is_string()
                || !e.contains("fee") || !e["fee"].is_number_integer()
                || !money_range(e["fee"].get<int64_t>()))
                return fail(kGMalformed, "entry " + std::to_string(i));
            const std::string& hex = e["data"].get_ref<const std::string&>();
            auto bytes = core::coin::template_txs_detail::decode_hex(hex);
            auto t = core::coin::walk_tx_hex(hex);
            if (!bytes || !t || !t->consumed_all || (t->flags & ~0x09))
                return fail(i + 1 == n ? kHogexMalformed : kEntryMalformed,
                            "entry " + std::to_string(i) + " does not deserialize");
            if (t->mweb_presence && *t->mweb_presence == 0x01)
                return fail(kEntryCarriesMwebData, "entry " + std::to_string(i) + " carries an mw::Transaction");
            const bool hogex_flag = (t->flags & 0x08) != 0;
            if (hogex_flag && i + 1 != n)
                return fail(kHogexNotLast, "MWEB flag on entry " + std::to_string(i));
            if (i + 1 == n && !hogex_flag)
                return fail(kHogexNotLast, "the last entry is not a HogEx");
            shapes[i] = std::move(*t);
            raw[i] = std::move(*bytes);
        }

        // Peg-ins and the closure of their in-template parents.
        std::vector<bool> take(n, false);
        std::deque<size_t> work;
        for (size_t i = 0; i + 1 < n; ++i) {
            for (const auto& [value, spk] : shapes[i].vout) {
                if (mweb_wire::pegin_kernel_of(std::span<const unsigned char>(spk.data(), spk.size()))) {
                    take[i] = true;
                    work.push_back(i);
                    break;
                }
            }
        }
        while (!work.empty()) {
            const size_t i = work.front();
            work.pop_front();
            const auto& e = entries[i];
            if (!e.contains("depends"))
                continue;
            if (!e["depends"].is_array())
                return fail(kGMalformed, "depends of entry " + std::to_string(i));
            for (const auto& d : e["depends"]) {
                // 1-based, a parent precedes its child (litecoind GBT).
                if (!d.is_number_integer() || d.get<int64_t>() < 1 || d.get<int64_t>() > static_cast<int64_t>(i))
                    return fail(kGMalformed, "depends of entry " + std::to_string(i));
                const size_t p = static_cast<size_t>(d.get<int64_t>() - 1);
                if (!take[p]) {
                    take[p] = true;
                    work.push_back(p);
                }
            }
        }

        auto make = [&](size_t i, ImportedTx& out) -> std::optional<ParseResult> {
            const auto& e = entries[i];
            const auto& t = shapes[i];
            out.hex = e["data"].get<std::string>();
            out.txid = t.txid;
            out.wtxid = detail::wtxid_of(t, raw[i]);
            out.fee = e["fee"].get<int64_t>();
            out.weight = core::coin::ltc_tx_weight(t);
            out.g_index = i;
            out.prevouts = t.prevouts;
            out.vout = t.vout;
            {
                PackStream ps(raw[i]);
                ps >> TX_WITH_WITNESS(out.tx);
                if (ps.cursor_size() != 0)
                    return fail(i + 1 == n ? kHogexMalformed : kEntryMalformed,
                                "entry " + std::to_string(i) + " does not deserialize");
            }
            if (e["txid"].get<std::string>() != t.txid.GetHex())
                return fail(kTxidMismatch, "entry " + std::to_string(i));
            if (e.contains("hash") && (!e["hash"].is_string() || e["hash"].get<std::string>() != out.wtxid.GetHex()))
                return fail(kWtxidMismatch, "entry " + std::to_string(i));
            return std::nullopt;
        };

        for (size_t i = 0; i + 1 < n; ++i) {
            if (!take[i])
                continue;
            const auto& t = shapes[i];
            if (t.n_vin == 0 || t.n_vout == 0)
                return fail(kEntryMalformed, "entry " + std::to_string(i) + " has no inputs or outputs");
            ImportedTx it;
            if (auto f = make(i, it))
                return *f;
            for (const auto& [value, spk] : t.vout)
                it.pegin = it.pegin || mweb_wire::pegin_kernel_of(
                    std::span<const unsigned char>(spk.data(), spk.size())).has_value();
            for (const auto& op : it.prevouts)
                if (!x->spent.insert(op).second)
                    return fail(kEntryMalformed, "entry " + std::to_string(i) + " double-spends an imported input");
            x->txids.insert(it.txid);
            x->txs.push_back(std::move(it));
        }

        // The HogEx.
        {
            const size_t i = n - 1;
            const auto& t = shapes[i];
            if (t.flags != 0x08 || !t.mweb_presence || *t.mweb_presence != 0x00 || t.n_vin == 0 || t.n_vout == 0)
                return fail(kHogexMalformed, "the last entry is not a HogEx");
            if (auto f = make(i, x->hogex))
                return *f;
            x->hogex_tx = x->hogex.tx;
            if (!x->hogex_tx.m_hogEx)
                return fail(kHogexMalformed, "the last entry is not a HogEx");
        }

        // The mw::Block.
        {
            const auto bytes = ParseHex(g["mweb"].get<std::string>());
            if (bytes.size() * 2 != g["mweb"].get<std::string>().size())
                return fail(kMwebBodyMalformed, "mweb is not hex");
            try {
                PackStream ps(bytes);
                MWEBBlock blk;
                ps >> blk;
                if (ps.cursor_size() != 0)
                    return fail(kMwebBodyMalformed, std::to_string(ps.cursor_size()) + " bytes after the mw::Block");
                x->header = blk.header;
                x->body = std::move(blk.body.summary);
            } catch (const std::exception& e) {
                return fail(kMwebBodyMalformed, e.what());
            }
            x->mweb_hex = g["mweb"].get<std::string>();
        }

        ParseResult r;
        r.bundle = std::move(x);
        return r;
    } catch (const std::exception& e) {
        return detail::fail(kGMalformed, e.what());
    }
}

struct Failure {
    std::string reason;
    std::string detail;
};

/// Checks 0-5 (see the file comment) of `x` against `state`, the tip's MWEB
/// state (MWEBTracker, captured from the tip block), for a block on
/// `tip_hash` at `tip_height` + 1 whose subsidy is `subsidy`. nullopt: the
/// extension may be merged.
inline std::optional<Failure> check_extension(const ExtensionBundle& x, const MWEBState& state,
                                              const uint256& tip_hash, uint32_t tip_height,
                                              int64_t subsidy)
{
    auto fail = [](const char* r, std::string d) { return std::optional<Failure>(Failure{r, std::move(d)}); };
    const uint32_t next_h = tip_height + 1;

    // 0. For the tip.
    if (x.prev != tip_hash)
        return fail(kPrevMismatch, "G prev " + x.prev.GetHex().substr(0, 16) + ", tip " + tip_hash.GetHex().substr(0, 16));
    if (x.height != next_h)
        return fail(kGHeightMismatch, "G height " + std::to_string(x.height) + ", next " + std::to_string(next_h));
    if (!state.valid || state.captured_block_hash != tip_hash || state.captured_at_height != tip_height)
        return fail(kStateNotForTip, "MWEB state h=" + std::to_string(state.captured_at_height));

    const auto& hog = x.hogex_tx;
    // 1. The HogEx spends the tip's HogEx.
    if (hog.vin.empty() || hog.vin[0].prevout.hash != state.prev_hogex_txid
        || hog.vin[0].prevout.index != state.prev_hogex_vout)
        return fail(kPrevHogexMismatch, "HogEx vin[0] " + (hog.vin.empty() ? std::string("none")
                    : hog.vin[0].prevout.hash.GetHex().substr(0, 16) + ":" + std::to_string(hog.vin[0].prevout.index))
                    + ", the tip's HogEx " + state.prev_hogex_txid.GetHex().substr(0, 16) + ":0");

    // 2. HogEx vin[1..] == the pegin outputs of the imported txs, in order
    //    (rule 7 as litecoind's ContextualCheckBlock checks it).
    {
        std::vector<core::coin::TxShape> shapes;
        shapes.reserve(x.txs.size() + 1);
        for (const auto& t : x.txs) {
            core::coin::TxShape s;
            s.txid = t.txid;
            s.prevouts = t.prevouts;
            s.vout = t.vout;
            shapes.push_back(std::move(s));
        }
        core::coin::TxShape h;
        h.flags = 0x08;
        h.txid = x.hogex.txid;
        h.prevouts = x.hogex.prevouts;
        h.vout = x.hogex.vout;
        shapes.push_back(std::move(h));
        if (auto r = core::coin::check_hogex_pegins(shapes))
            return Failure{r->code, r->detail};
    }

    // 3. The commitment, the height and the kernel count.
    if (auto why = MWEBBuilder::check_commitment(hog, x.header, next_h)) {
        const char* code = *why == "mweb-height-mismatch" ? "mweb-height-mismatch"
                         : *why == "mweb-hash-mismatch" ? "mweb-hash-mismatch" : kHogexMalformed;
        return fail(code, *why + " (mweb header height " + std::to_string(x.header.height) + ")");
    }
    if (x.header.kernel_mmr_size != x.body.kernels.size())
        return fail(kKernelCountMismatch, "header " + std::to_string(x.header.kernel_mmr_size)
                    + ", body " + std::to_string(x.body.kernels.size()));

    // 4. The value.
    {
        // Peg-in coins: the pegin outputs (kernel id, value) == the body's
        // peg-in kernels (kernel id, amount).
        std::multiset<std::pair<uint256, int64_t>> canonical, body;
        int64_t pegin_outputs = 0;
        std::map<std::pair<uint256, uint32_t>, int64_t> pegin_value;
        for (const auto& t : x.txs) {
            for (uint32_t n = 0; n < t.vout.size(); ++n) {
                const auto& [value, spk] = t.vout[n];
                if (auto id = mweb_wire::pegin_kernel_of(std::span<const unsigned char>(spk.data(), spk.size()))) {
                    if (!money_range(value))
                        return fail(kPeginKernelMismatch, "pegin output out of range");
                    canonical.emplace(*id, value);
                    pegin_value[{t.txid, n}] = value;
                    pegin_outputs += value;
                    if (!money_range(pegin_outputs))
                        return fail(kPeginKernelMismatch, "pegin outputs out of range");
                }
            }
        }
        int64_t pegin_kernel_fees = 0;
        std::map<uint256, int64_t> kernel_fee;
        for (const auto& k : x.body.kernels) {
            if (k.pegin) {
                body.emplace(k.kernel_id, *k.pegin);
                pegin_kernel_fees += k.fee;
            }
            kernel_fee[k.kernel_id] = k.fee;
        }
        if (canonical != body)
            return fail(kPeginKernelMismatch, std::to_string(canonical.size()) + " pegin output(s), "
                        + std::to_string(body.size()) + " peg-in kernel(s)");

        // Peg-outs: HogEx vout[1..] == the body's peg-outs (a multiset).
        std::multiset<std::pair<int64_t, std::vector<uint8_t>>> hog_out, body_out;
        int64_t hog_value_out = 0;
        for (size_t i = 0; i < hog.vout.size(); ++i) {
            if (!money_range(hog.vout[i].value))
                return fail(kPegoutMismatch, "HogEx output out of range");
            hog_value_out += hog.vout[i].value;
            if (!money_range(hog_value_out))
                return fail(kPegoutMismatch, "HogEx outputs out of range");
            if (i > 0)
                hog_out.emplace(hog.vout[i].value, hog.vout[i].scriptPubKey.m_data);
        }
        int64_t pegouts = 0;
        for (const auto& p : x.body.pegouts()) {
            body_out.emplace(p.amount, p.script);
            pegouts += p.amount;
            if (!money_range(p.amount) || !money_range(pegouts))
                return fail(kPegoutMismatch, "peg-outs out of range");
        }
        if (hog_out != body_out)
            return fail(kPegoutMismatch, std::to_string(hog_out.size()) + " HogEx peg-out(s), "
                        + std::to_string(body_out.size()) + " in the body");

        // Every term is within MAX_MONEY (checked), so no sum below leaves
        // int64_t.
        const int64_t fees = x.body.total_fee();
        const int64_t pegins = x.body.pegin_amount();
        if (!money_range(fees) || !money_range(pegins) || !money_range(state.hogaddr_value))
            return fail(kHogaddrValueMismatch, "kernel fees, peg-ins or the tip's HogAddr out of range");
        // HogAddr value = the tip's + peg-ins - peg-outs - kernel fees
        // (litecoind ConnectBlock mweb-amount-mismatch).
        const int64_t expect = state.hogaddr_value + pegins - pegouts - fees;
        if (expect != hog.vout[0].value)
            return fail(kHogaddrValueMismatch, "HogAddr " + std::to_string(hog.vout[0].value) + ", expected "
                        + std::to_string(expect));
        // HogEx fee = (the tip's HogAddr + its pegin inputs) - its outputs ==
        // the kernel fees (bad-txns-mweb-fee-mismatch).
        int64_t value_in = state.hogaddr_value;
        for (size_t i = 1; i < hog.vin.size(); ++i) {
            auto it = pegin_value.find({hog.vin[i].prevout.hash, hog.vin[i].prevout.index});
            if (it == pegin_value.end())
                return fail(kHogexFeeMismatch, "HogEx input " + std::to_string(i) + " is no imported pegin output");
            value_in += it->second;
        }
        if (value_in - hog_value_out != fees)
            return fail(kHogexFeeMismatch, "HogEx fee " + std::to_string(value_in - hog_value_out)
                        + ", kernel fees " + std::to_string(fees));

        // The listed fees. The HogEx lists the MWEB-only txs' fees: at most
        // the kernel fees outside the imported peg-ins' kernels. A peg-in
        // lists its canonical fee plus its kernels': at least its peg-in
        // kernel's. All of them together: at most what G's coinbasevalue
        // carries.
        if (x.hogex.fee > fees - pegin_kernel_fees)
            return fail(kHogexFeeEntryTooHigh, "HogEx fee entry " + std::to_string(x.hogex.fee)
                        + " > kernel fees outside the peg-ins " + std::to_string(fees - pegin_kernel_fees));
        int64_t listed = x.hogex.fee;
        for (const auto& t : x.txs) {
            int64_t own_kernel_fees = 0;
            for (const auto& [value, spk] : t.vout)
                if (auto id = mweb_wire::pegin_kernel_of(std::span<const unsigned char>(spk.data(), spk.size())))
                    if (auto k = kernel_fee.find(*id); k != kernel_fee.end())
                        own_kernel_fees += k->second;
            if (t.fee < own_kernel_fees)
                return fail(kPeginFeeBelowKernelFee, "entry " + std::to_string(t.g_index) + " fee "
                            + std::to_string(t.fee) + " < its peg-in kernel fee " + std::to_string(own_kernel_fees));
            listed += t.fee;
        }
        if (listed > x.coinbasevalue - subsidy)
            return fail(kFeeExceedsG, "imported fees " + std::to_string(listed) + " > G fees "
                        + std::to_string(x.coinbasevalue - subsidy));
    }

    // 5. The carried state.
    const MWEBHeader& prev = state.prev_header;
    if (x.body_empty()) {
        PackStream a, b;
        a << x.header;
        b << MWEBBuilder::next_empty_header(prev, next_h);
        const auto sa = a.get_span(), sb = b.get_span();
        if (sa.size() != sb.size() || std::memcmp(sa.data(), sb.data(), sa.size()) != 0)
            return fail(kCarriedStateMismatch, "an empty body whose header is not the tip's carried forward");
    } else {
        if (x.header.output_mmr_size != prev.output_mmr_size + x.body.n_outputs)
            return fail(kTxoCountMismatch, "txos " + std::to_string(x.header.output_mmr_size) + ", the tip's "
                        + std::to_string(prev.output_mmr_size) + " + " + std::to_string(x.body.n_outputs) + " outputs");
        if (x.body.n_outputs == 0 && x.header.output_root != prev.output_root)
            return fail(kCarriedStateMismatch, "output root moved without an output");
        if (x.body.n_outputs == 0 && x.body.n_inputs == 0 && x.header.leafset_root != prev.leafset_root)
            return fail(kCarriedStateMismatch, "leafset root moved without an input or an output");
    }
    return std::nullopt;
}

// ─── The holder: the latest G and the counters ──────────────────────────────

/// What a template did with the extension (MwebExtSource::note).
struct Outcome {
    enum Kind { imported, fallback, skipped } kind{skipped};
    std::string reason;   // fallback / skipped
    std::string detail;
    size_t txs{0}, pegins{0}, kernels{0};
    int64_t fee_sat{0};   // imported entries + the HogEx entry
    int64_t g_age_ms{-1};
};

/// Thread-safe: the poller stores G (any thread), the template builder reads
/// it and reports what it did (the io thread, or a refresh on another one),
/// /local_stats reads the counters (the HTTP thread).
class MwebExtSource {
public:
    using clock = std::chrono::steady_clock;

    explicit MwebExtSource(std::string mode = "none") : m_mode(std::move(mode)) {}

    const std::string& mode() const { return m_mode; }
    bool enabled() const { return m_mode == "litecoind"; }

    /// The latest fetch: a parsed G or why it did not parse.
    void set_parsed(ParseResult r, clock::time_point fetched_at)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_parsed = std::move(r);
        m_have = true;
        m_fetched_at = fetched_at;
        ++m_bundles;
    }

    /// A fetch that returned no G (litecoind unreachable, an RPC error, a
    /// timeout). The previous G is kept: bound to its prev, it stays usable
    /// while the tip does not move.
    void note_fetch(bool ok, bool timeout, int64_t ms, const std::string& error)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (ok) {
            ++m_fetch_ok;
        } else if (timeout) {
            ++m_fetch_timeouts;
        } else {
            ++m_fetch_errors;
        }
        m_fetch_last_ms = ms;
        if (!ok)
            m_fetch_last_error = error;
    }

    struct Current {
        std::shared_ptr<const ExtensionBundle> bundle;
        std::string reason, detail;   // when there is no bundle
        int64_t age_ms{-1};
    };

    Current current(clock::time_point now = clock::now()) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        Current c;
        if (!m_have) {
            c.reason = kUnavailable;
            c.detail = "no getblocktemplate from litecoind yet";
            return c;
        }
        c.bundle = m_parsed.bundle;
        c.reason = m_parsed.reason;
        c.detail = m_parsed.detail;
        c.age_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_fetched_at).count();
        return c;
    }

    /// The outcome of one template at `height`. A fallback logs one line per
    /// height: WARNING for a consistency failure, INFO for a G that is not
    /// for the tip (yet) or no G.
    void note(uint32_t height, const Outcome& o)
    {
        std::string log_reason;
        bool warn = false;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_last = o;
            m_last_height = height;
            switch (o.kind) {
            case Outcome::imported:
                ++m_templates_imported;
                m_total_txs += o.txs;
                m_total_kernels += o.kernels;
                m_total_fee += static_cast<uint64_t>(o.fee_sat);
                break;
            case Outcome::fallback:
                ++m_fallback[o.reason];
                if (m_last_logged_height != height) {
                    m_last_logged_height = height;
                    log_reason = o.reason;
                    warn = !reason_is_expected(o.reason);
                }
                break;
            case Outcome::skipped:
                ++m_skipped[o.reason];
                break;
            }
        }
        if (log_reason.empty())
            return;
        if (warn)
            LOG_WARNING << "[EMB-LTC] MWEB extension from litecoind NOT used at height " << height << ": "
                        << log_reason << " (" << o.detail << ") -- empty MWEB body, c2pool's own HogEx";
        else
            LOG_INFO << "[EMB-LTC] MWEB extension from litecoind not used at height " << height << ": "
                     << log_reason << " (" << o.detail << ") -- empty MWEB body for now";
    }

    uint64_t fallback_count(const std::string& reason) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_fallback.find(reason);
        return it == m_fallback.end() ? 0 : it->second;
    }
    uint64_t skipped_count(const std::string& reason) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_skipped.find(reason);
        return it == m_skipped.end() ? 0 : it->second;
    }
    uint64_t templates_imported() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_templates_imported;
    }
    Outcome last() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_last;
    }

    /// /local_stats "ltc_mweb_ext". imported_* are the last built
    /// template's (0 when it did not import); g_age_ms is the age of the
    /// latest G now (null: none).
    nlohmann::json to_json(clock::time_point now = clock::now()) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        const bool imp = m_last.kind == Outcome::imported;
        nlohmann::json j;
        j["mode"] = m_mode;
        j["imported_txs"] = imp ? m_last.txs : 0;
        j["imported_pegins"] = imp ? m_last.pegins : 0;
        j["imported_kernels"] = imp ? m_last.kernels : 0;
        j["imported_fee_sat"] = imp ? m_last.fee_sat : 0;
        nlohmann::json fb = nlohmann::json::object();
        for (const auto& [r, n] : m_fallback)
            fb[r] = n;
        j["fallback"] = std::move(fb);
        nlohmann::json sk = nlohmann::json::object();
        for (const auto& [r, n] : m_skipped)
            sk[r] = n;
        j["skipped"] = std::move(sk);
        j["g_age_ms"] = m_have ? nlohmann::json(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    now - m_fetched_at).count())
                               : nlohmann::json(nullptr);
        if (m_last_height != 0) {
            static const char* kinds[] = {"imported", "fallback", "skipped"};
            j["last"] = {{"height", m_last_height},
                         {"outcome", kinds[m_last.kind]},
                         {"reason", m_last.reason},
                         {"g_age_ms", m_last.g_age_ms}};
        } else {
            j["last"] = nullptr;
        }
        j["templates_imported"] = m_templates_imported;
        j["totals"] = {{"txs", m_total_txs}, {"kernels", m_total_kernels}, {"fee_sat", m_total_fee}};
        if (m_have) {
            nlohmann::json g;
            if (m_parsed.bundle) {
                g["prev"] = m_parsed.bundle->prev.GetHex();
                g["height"] = m_parsed.bundle->height;
                g["kernels"] = m_parsed.bundle->body.kernels.size();
                g["txs"] = m_parsed.bundle->txs.size();
                g["parse"] = "ok";
            } else {
                g["parse"] = m_parsed.reason;
            }
            j["g"] = std::move(g);
        } else {
            j["g"] = nullptr;
        }
        j["fetch"] = {{"ok", m_fetch_ok},
                      {"errors", m_fetch_errors},
                      {"timeouts", m_fetch_timeouts},
                      {"last_ms", m_fetch_last_ms},
                      {"last_error", m_fetch_last_error},
                      {"bundles", m_bundles}};
        return j;
    }

private:
    const std::string m_mode;
    mutable std::mutex m_mutex;
    ParseResult m_parsed;
    bool m_have{false};
    clock::time_point m_fetched_at{};
    uint64_t m_bundles{0};
    uint64_t m_fetch_ok{0}, m_fetch_errors{0}, m_fetch_timeouts{0};
    int64_t m_fetch_last_ms{0};
    std::string m_fetch_last_error;
    Outcome m_last;
    uint32_t m_last_height{0};
    uint32_t m_last_logged_height{0};
    std::map<std::string, uint64_t> m_fallback, m_skipped;
    uint64_t m_templates_imported{0}, m_total_txs{0}, m_total_kernels{0}, m_total_fee{0};
};

} // namespace mweb_ext
} // namespace coin
} // namespace ltc
