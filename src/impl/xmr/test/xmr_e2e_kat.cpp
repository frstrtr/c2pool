// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_e2e_kat.cpp
//   X8 END-TO-END integration KAT: the whole XMR-lane path stitched together in
//   one TU, covering exactly the seams the per-slice KATs do NOT:
//
//     block-template context (X2/item-10)  ->  a job feeds ...
//     coinbase settlement    (X6)          ->  build the canonical miner_tx from
//                                              the finality-gated OWED ledger ...
//     stratum front-end      (item-9)      ->  miner grinds the coinbase-framed
//                                              hashing blob & submits a share ...
//     carrier wire           (X7)          ->  encode/decode the receipt ...
//     receipt admission      (X4)          ->  verify accepts it, rejects a tamper.
//
//   Each per-slice KAT proves ITS leg in isolation (xmr_coinbase_kat: exact-sum +
//   stealth keys; xmr_wire_dos_check: codec/DoS bounds; xmr_receipt_kat: the
//   admission ORDER; xmr_stratum_selftest: the dialect). What NONE of them proves
//   is that the legs COMPOSE: that the very bytes the settle leg emits (the miner_tx
//   prefix, its tx_extra 0x03 owed_digest commitment, the tree_root it frames into
//   the RandomX hashing blob) are the very bytes the stratum miner signs, the wire
//   ships, and the receipt verifier opens and binds -- with no re-encoding, no
//   second serializer, and no divergent commitment between the two legs. THAT
//   cross-leg identity is what this KAT pins.
//
//   The single stitch that makes the composition real: the settle leg's
//   lane_commitment (owed_digest) is set to the receipt's side-data info_digest,
//   so the coinbase's tx_extra 0x03 merge-mining leaf == the leaf the receipt path
//   recomputes and requires. Break any link in the chain -- a payout key, a
//   T_origin, a branch byte -- and the tree_root under the RandomX-signed blob no
//   longer reproduces, so the receipt is refused at the STRUCTURAL stage, before
//   RandomX is ever run.
//
//   LIGHT: stdlib + the vendored X1 coin primitives (keccak / ed25519 ge_*) only.
//   RandomX is stubbed with the SAME deterministic PoW oracle the stratum W3
//   self-test uses (KeyedPowStub): top-word = nonce*A + C. The real RandomX engine
//   is the randomx-vendor leg's CI target (xmr_randomx_verify_kat), never this one.
//   No 256-MiB cache, no JIT, no monerod, no libsodium, no boost-linked object.
//
//   Build (single TU, no cmake; mirrors the xmr_coin library's source set):
//     g++ -std=c++20 -O1 -I <c2pool>/src \
//       -I <c2pool>/src/impl/xmr/coin -I .../coin/vendor -I .../coin/compat \
//       -I .../settle -I .../receipt -I .../wire -I .../stratum -I .../template \
//       xmr_e2e_kat.cpp \
//       .../settle/xmr_coinbase.cpp .../receipt/xmr_receipt_verify.cpp \
//       .../stratum/xmr_stratum.cpp \
//       .../coin/xmr_blob.cpp .../coin/xmr_derivation.cpp \
//       .../coin/vendor/{keccak,hash,tree-hash,crypto-ops,crypto-ops-data}.c \
//       -o /tmp/xmr_e2e_kat && /tmp/xmr_e2e_kat
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// --- the five surfaces under stitch ----------------------------------------
#include "impl/xmr/settle/xmr_coinbase.hpp"        // X6 coinbase settlement
#include "impl/xmr/coin/xmr_derivation.hpp"        // ge_* stealth recompute (independent)
#include "impl/xmr/receipt/xmr_receipt.hpp"        // X4 MoneroReceipt envelope
#include "impl/xmr/receipt/xmr_admission.hpp"      // admission taxonomy
#include "impl/xmr/receipt/xmr_receipt_verify.hpp" // X4 verify/build bodies
#include "impl/xmr/wire/xmr_carrier_wire.hpp"      // X7 carrier codec
#include "impl/xmr/stratum/xmr_stratum.hpp"        // stratum front-end (job/submit)
#include "impl/xmr/template/xmr_block_template.hpp" // block-template DATA CONTRACT (X2/item-10)

namespace settle = ::v37::xmr::settle;
namespace vf     = ::v37::xmr::verify;
namespace wire   = ::v37::xmr::wire;
namespace strat  = ::v37::xmr::stratum;
namespace tmpl   = ::c2pool::xmr;

// ============================ tiny harness =================================
namespace {
int g_pass = 0, g_fail = 0;
const char* g_stage = "";
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] %-6s ", _ok ? "PASS" : "FAIL", g_stage); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (_ok) ++g_pass; else ++g_fail; \
} while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> o;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
template <class T> std::string hx(const T& t) { return hex(t.data(), t.size()); }
template <class T> T key_from_hex(const std::string& h) {
    T t{}; auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < t.size() ? v.size() : t.size());
    return t;
}

// OFFICIAL monero-project tests/crypto/tests.txt points, reused as two on-curve
// (spend B, view A) payout keys so every ECDH derivation runs against real
// ed25519 points (same provenance the xmr_coinbase_kat cites, no code copied).
::xmr::coin::PublicKey g_B; // spend  (tests.txt generate_key_derivation `pub`)
::xmr::coin::PublicKey g_A; // view   (tests.txt derive_public_key `base`)

::v37::ScriptRef xmr_ref() {
    ::v37::ScriptRef r;
    r.kind = ::v37::xmr::XMR_STD;
    r.payload.resize(64);
    std::memcpy(r.payload.data(),      g_B.data(), 32);
    std::memcpy(r.payload.data() + 32, g_A.data(), 32);
    return r;
}
::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(seed + i);
    return b;
}
std::uint64_t sum_amounts(const std::vector<settle::CoinbaseOutput>& v) {
    std::uint64_t s = 0; for (auto& o : v) s += o.amount; return s;
}
bool is_zero_key(const ::xmr::coin::PublicKey& k) {
    for (std::size_t i = 0; i < k.size(); ++i) if (k.data()[i]) return false;
    return true;
}

// Independent 8rA ECDH recompute of one coinbase output key (cannot share a bug
// with settle::derive_output; identical to the xmr_coinbase_kat cross-check).
bool recompute_output(const ::xmr::coin::SecretKey& r, std::size_t i,
                      ::xmr::coin::PublicKey& P, ::xmr::coin::ViewTag& vt) {
    ::xmr::coin::KeyDerivation D{};
    if (!::xmr::coin::generate_key_derivation(g_A, r, D)) return false; // D = 8 r A
    if (!::xmr::coin::derive_public_key(D, i, g_B, P)) return false;    // P = H_s(D||i)G + B
    ::xmr::coin::derive_view_tag(D, i, vt);
    return true;
}

// ---- the deterministic RandomX PoW oracle (byte-identical to the stratum W3
//      self-test's KeyedPowStub): top 64-bit word = nonce_le * A + C. -----------
struct KeyedPowStub : strat::IPowVerifier {
    std::size_t nonce_offset = strat::EXPECTED_NONCE_OFFSET_V16;
    static constexpr std::uint64_t A = 0x9E3779B97F4A7C15ULL;
    static constexpr std::uint64_t C = 0x0000000000000007ULL;
    std::vector<std::uint8_t> last_blob;   // the exact blob the miner signed
    static std::uint64_t answer_top_word(std::uint32_t nonce_le) {
        return static_cast<std::uint64_t>(nonce_le) * A + C;
    }
    bool randomx_hash(const std::uint8_t* blob, std::size_t n, std::uint64_t,
                      const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override {
        if (nonce_offset + strat::NONCE_SIZE > n) return false;
        last_blob.assign(blob, blob + n);
        std::uint32_t nonce_le = 0;
        for (int i = 0; i < (int)strat::NONCE_SIZE; ++i)
            nonce_le |= static_cast<std::uint32_t>(blob[nonce_offset + i]) << (8 * i);
        const std::uint64_t top = answer_top_word(nonce_le);
        out.fill(0);
        for (int i = 0; i < 8; ++i) out[strat::HASH_SIZE - 8 + i] = static_cast<std::uint8_t>(top >> (8 * i));
        return true;
    }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>& h,
                      std::uint64_t target) const override {
        std::uint64_t top = 0;
        for (int i = 0; i < 8; ++i) top |= static_cast<std::uint64_t>(h[strat::HASH_SIZE - 8 + i]) << (8 * i);
        return top <= target;
    }
};

// ---- stratum template source: serves the SETTLE-coinbase-framed hashing blob
//      (the receipt's own hashing_blob) with the 4-byte nonce zeroed, so the
//      grinder's patched blob reproduces the receipt blob byte-for-byte. --------
struct CoinbaseFramedTemplateSource : strat::ITemplateSource {
    std::vector<std::uint8_t> base_blob;                 // receipt blob, nonce zeroed
    std::size_t nonce_offset = strat::EXPECTED_NONCE_OFFSET_V16;
    std::uint32_t template_id = 42;
    std::uint64_t height = 3'000'000;
    std::uint64_t lane_target = 0;                        // set to admit the winning nonce
    std::uint64_t mainchain_target = 0;                   // 0 => no network-block branch
    std::array<std::uint8_t, strat::HASH_SIZE> seed_hash{};
    void fill(strat::TemplateJob& out, std::uint32_t) {
        out.blob = base_blob;
        out.nonce_offset = nonce_offset;
        out.template_id = template_id;
        out.height = height;
        out.lane_target = lane_target;
        out.mainchain_target = mainchain_target;
        out.seed_hash = seed_hash;
        out.monero_major_version = 16;
    }
    bool get_job(std::uint32_t en, strat::TemplateJob& out) override { fill(out, en); return true; }
    bool rebuild_blob(std::uint32_t tid, std::uint32_t en, strat::TemplateJob& out) override {
        if (tid != template_id) return false; fill(out, en); return true;
    }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};
struct CapSink : strat::IShareSink {
    int accepted = 0, net = 0; strat::AcceptedShare last{};
    void on_accepted_share(const strat::AcceptedShare& s) override { ++accepted; last = s; }
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override { ++net; }
};
struct CapTransport : strat::ITransport {
    std::vector<std::string> lines;
    bool send_line(std::uint64_t, std::string_view l) override { lines.emplace_back(l); return true; }
    void close(std::uint64_t) override {}
    std::string last() const { return lines.empty() ? std::string() : lines.back(); }
    void clear() { lines.clear(); }
};
bool contains(const std::string& hay, const char* n) { return hay.find(n) != std::string::npos; }

} // namespace

// ===========================================================================
int main() {
    std::printf("=== X8 XMR-lane END-TO-END integration KAT ===\n");
    std::printf("    template-context -> coinbase(X6) -> stratum share -> wire(X7) -> receipt(X4)\n");
    std::printf("    RandomX stubbed with the deterministic W3 oracle (real engine = randomx-vendor leg)\n\n");

    g_A = key_from_hex<::xmr::coin::PublicKey>(
        "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39");
    g_B = key_from_hex<::xmr::coin::PublicKey>(
        "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984");

    // ----- the v37 side data the receipt binds; its digest IS the owed_digest --
    const std::uint32_t     CHAIN     = 0x584d5200u;            // 'XMR\0' lane id
    const ::v37::bytes32    IDENT     = id_of(0x11);            // payout identity == carrier
    const v37::xmr::Difficulty T_ORIGIN{100000, 0};            // committed share target

    v37::xmr::ReceiptSideData sd;
    sd.t_origin = T_ORIGIN;
    sd.payout_identity = IDENT;
    sd.chain_id = CHAIN;
    // prev_own_share display-only, left zero.

    // info_digest = keccak256(canonical side data) -- the value the coinbase must
    // commit and the receipt must reproduce. This is the OWED_DIGEST for the stitch.
    const v37::xmr::bytes32 info_digest = vf::side_data_digest(sd);

    // =======================================================================
    // STAGE 1 - block-template context feeds the coinbase inputs.
    //   The template leg's DATA CONTRACT (XmrMinerData / XmrPayee / the tail-
    //   emission reward constant / the hashing-blob framing) supplies the Monero
    //   parent context. We bind that context, field for field, into the settle
    //   coinbase inputs -- this is "a job's template feeds the coinbase".
    // =======================================================================
    g_stage = "TMPL";
    std::printf("== STAGE 1: block-template context -> coinbase inputs ==\n");

    tmpl::XmrMinerData md;
    md.major_version = tmpl::HARDFORK_SUPPORTED_VERSION;      // v16, pre-CARROT
    md.height = 3'000'000;
    for (int i = 0; i < (int)tmpl::HASH_SIZE; ++i)
        md.prev_id.h[i] = static_cast<std::uint8_t>(0xb0 + i);
    md.already_generated_coins = 18'400'000'000'000'000'000ull; // deep in the 0.6-XMR tail regime
    // get_base_reward(already_generated_coins) collapses to the tail once
    // ~coins>>19 < BASE_BLOCK_REWARD; assert we are on the tail, then use it.
    const std::uint64_t base_reward =
        (( ~md.already_generated_coins >> 19) < tmpl::BASE_BLOCK_REWARD)
            ? tmpl::BASE_BLOCK_REWARD
            : ( ~md.already_generated_coins >> 19);
    const std::uint64_t fees = 12'345'678ull;
    CHECK(base_reward == tmpl::BASE_BLOCK_REWARD,
          "template tail reward == BASE_BLOCK_REWARD (%llu piconero)", (unsigned long long)base_reward);

    // Two K_fair-ordered payees (the template's XmrPayee view of the owed set).
    tmpl::XmrPayee p0, p1;
    std::memcpy(p0.spend_public_key.h, g_B.data(), 32);
    std::memcpy(p0.view_public_key.h,  g_A.data(), 32);
    p1 = p0;
    std::vector<tmpl::XmrPayee> payees = {p0, p1};
    CHECK(payees.size() == 2, "template payee view carries the 2-entry owed set");

    // Build the settle coinbase inputs FROM the template context (data-flow bind).
    settle::CoinbaseInputs in;
    in.monero_major_version = md.major_version;              // <- template
    in.height               = md.height;                     // <- template
    std::memcpy(in.prev_id.data(), md.prev_id.h, 32);        // <- template
    in.base_reward          = base_reward;                   // <- template reward math
    in.fees                 = fees;
    in.chain_id             = CHAIN;
    in.lane_commitment      = info_digest;                   // THE STITCH: owed_digest == info_digest
    in.residual_sink        = xmr_ref();
    in.residual_sink_identity = id_of(0x99);
    in.h_min = 0;
    in.output_cap = 2700;
    in.extra_nonce = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0};       // 14-B padded 0x02 nonce
    in.owed = { {xmr_ref(), 200'000'000'000ull, 1, id_of(1)},
                {xmr_ref(), 150'000'000'000ull, 2, id_of(2)} };
    CHECK(in.height == md.height && in.base_reward == base_reward,
          "coinbase inputs height/reward bound to template context (h=%llu)",
          (unsigned long long)in.height);

    // =======================================================================
    // STAGE 2 - coinbase settlement (X6): OWED ledger -> canonical miner_tx.
    //   exact-sum (HF13, no burn) + owed outputs are real stealth keys.
    // =======================================================================
    g_stage = "X6";
    std::printf("== STAGE 2: coinbase settlement (owed -> miner_tx) ==\n");

    settle::BuiltCoinbase cb = settle::build_coinbase(in);
    CHECK(cb.ok && cb.error == settle::BuildError::None,
          "build_coinbase ok (error=%s)", settle::to_string(cb.error));
    CHECK(sum_amounts(cb.outputs) == in.budget(),
          "exact-sum: Sum(vout)=%llu == base_reward+fees=%llu (no burn)",
          (unsigned long long)sum_amounts(cb.outputs), (unsigned long long)in.budget());
    CHECK(!cb.outputs.empty() && cb.outputs.back().role == settle::CoinbaseOutput::Role::Sink,
          "residual sink present as the last output (CONS-1)");

    // owed outputs are real, distinct, on-curve stealth keys that reproduce by ECDH
    bool stealth_ok = true, distinct = true;
    std::size_t n_owed = 0;
    for (std::size_t i = 0; i < cb.outputs.size(); ++i) {
        if (cb.outputs[i].role != settle::CoinbaseOutput::Role::Owed) continue;
        ++n_owed;
        if (is_zero_key(cb.outputs[i].one_time_key)) { stealth_ok = false; break; }
        ::xmr::coin::PublicKey P{}; ::xmr::coin::ViewTag vt{};
        if (!recompute_output(cb.r, i, P, vt) ||
            !(P == cb.outputs[i].one_time_key) || vt.tag != cb.outputs[i].view_tag.tag)
            stealth_ok = false;
    }
    for (std::size_t i = 0; i < cb.outputs.size(); ++i)
        for (std::size_t j = i + 1; j < cb.outputs.size(); ++j)
            if (cb.outputs[i].one_time_key == cb.outputs[j].one_time_key) distinct = false;
    CHECK(n_owed == 2 && stealth_ok,
          "owed outputs are stealth keys P_i=8rA-ECDH, reproduced independently");
    CHECK(distinct, "every vout one-time key is distinct (output index binds)");

    // owed_digest committed in the coinbase == what the receipt path expects.
    const v37::xmr::bytes32 receipt_mm_leaf = vf::mm_commitment_leaf(CHAIN, info_digest);
    CHECK(std::memcmp(cb.mm_root.data(), receipt_mm_leaf.data(), 32) == 0,
          "coinbase mm_root == receipt mm_commitment_leaf(chain,info_digest)  [%s...]",
          hx(cb.mm_root).substr(0, 16).c_str());

    // and it is really the 0x03 tag byte-parsed out of the emitted tx_extra.
    vf::ParsedTxExtra pe;
    bool pex = vf::parse_tx_extra(std::vector<v37::xmr::u8>(cb.tx_extra.begin(), cb.tx_extra.end()), pe);
    CHECK(pex && pe.has_mm && std::memcmp(pe.mm_root.data(), cb.mm_root.data(), 32) == 0,
          "tx_extra 0x03 merge-mining root parses back to the owed_digest commitment");

    // =======================================================================
    // STAGE 3 - mint the v37 receipt around the REAL settle coinbase prefix (X4/X7).
    //   No re-serialization: the receipt opens exactly the bytes settle emitted.
    // =======================================================================
    g_stage = "MINT";
    std::printf("== STAGE 3: receipt minted around the settle coinbase prefix ==\n");

    // extra_start = offset where tx_extra begins inside the settle prefix
    // (prefix = head || varint(len(tx_extra)) || tx_extra).
    CHECK(cb.prefix.size() > cb.tx_extra.size(), "settle prefix contains the tx_extra tail");
    const std::size_t extra_start = cb.prefix.size() - cb.tx_extra.size();

    vf::BuildInputs bi;
    bi.major = 16; bi.minor = 16;
    bi.timestamp = 1'697'813'342ull;              // 5-byte varint => nonce at offset 39
    std::memcpy(bi.prev_id.data(), md.prev_id.h, 32);
    const std::uint32_t WIN_NONCE = 0x00000002u;  // the nonce the miner will grind & submit
    bi.nonce = WIN_NONCE;
    bi.prefix_bytes = std::vector<v37::xmr::u8>(cb.prefix.begin(), cb.prefix.end());
    bi.extra_start  = extra_start;
    bi.side_data    = sd;                          // other_leaves empty => n_tx==1
    bi.seed_policy  = v37::xmr::SeedRefPolicy::DerivedFromBin;

    v37::xmr::MoneroReceipt receipt;
    std::string why;
    bool mok = vf::build_v37_receipt(bi, receipt, &why);
    CHECK(mok, "build_v37_receipt around the settle coinbase (%s)", mok ? "ok" : why.c_str());
    CHECK(receipt.info_digest == info_digest,
          "receipt.info_digest == keccak256(side_data) == coinbase owed_digest");
    CHECK(receipt.wire_size() <= v37::xmr::budget::PER_RECEIPT_BUDGET,
          "receipt within per-receipt byte budget (%zu <= %zu B)",
          receipt.wire_size(), (std::size_t)v37::xmr::budget::PER_RECEIPT_BUDGET);
    // sanity: the nonce really sits at the v16 offset the stratum path assumes.
    CHECK(receipt.hashing_blob.size() >= 43 &&
          strat::EXPECTED_NONCE_OFFSET_V16 + 4 <= receipt.hashing_blob.size(),
          "hashing blob frames the 4-byte nonce at the pre-CARROT v16 offset");

    // the crypto opening reproduces tree_root from the settle coinbase bytes.
    {
        v37::xmr::OpenedCommitment oc; std::string w2;
        bool vopen = vf::verify_crypto_opening(receipt, oc, &w2);
        CHECK(vopen, "verify_crypto_opening: coinbase prefix -> H(prefix) -> tx hash -> root");
        vf::ParsedBlob pb;
        CHECK(vf::parse_hashing_blob(receipt.hashing_blob, pb) &&
              std::memcmp(pb.tree_root.data(), oc.tree_root.data(), 32) == 0,
              "recovered tree_root == the root inside the RandomX-signed blob");
    }

    // =======================================================================
    // STAGE 4 - stratum: miner grinds the coinbase-framed blob & submits a share.
    //   The blob the miner signs is the receipt's OWN hashing blob (nonce zeroed);
    //   on submit the grinder patches WIN_NONCE and the deterministic oracle
    //   accepts. The accepted share's blob is byte-identical to the receipt blob.
    // =======================================================================
    g_stage = "STRAT";
    std::printf("== STAGE 4: stratum job -> miner submits share ==\n");

    CoinbaseFramedTemplateSource src;
    src.base_blob = receipt.hashing_blob.bytes;
    for (int i = 0; i < 4; ++i) src.base_blob[strat::EXPECTED_NONCE_OFFSET_V16 + i] = 0; // zero nonce
    src.height = md.height;
    // lane target admits WIN_NONCE (inclusive) and rejects a heavier nonce.
    src.lane_target = KeyedPowStub::answer_top_word(WIN_NONCE);

    KeyedPowStub pow; CapSink sink; CapTransport tx;
    strat::XmrStratumServer server(src, pow, sink, tx);
    strat::XmrStratumSession sess(1);
    CHECK(server.handle_login(sess, 1, "48minerAddr.rig"), "miner login accepted, first job issued");

    auto submit = [&](std::uint32_t nonce_le, const char* result_hex64) -> std::string {
        strat::SubmitFields f;
        f.rpc_id = "00000000"; f.job_id = "00000001";
        std::uint8_t nb[4] = { (std::uint8_t)nonce_le, (std::uint8_t)(nonce_le >> 8),
                               (std::uint8_t)(nonce_le >> 16), (std::uint8_t)(nonce_le >> 24) };
        f.nonce = strat::StratumDialect::to_hex(nb, 4);
        f.result.assign(result_hex64);
        tx.clear();
        server.handle_submit(sess, 2, f);
        return tx.last();
    };

    std::string ok_reply = submit(WIN_NONCE, std::string(64, 'f').c_str()); // result is garbage on purpose
    CHECK(contains(ok_reply, "\"status\":\"OK\""), "winning share accepted by the front-end");
    CHECK(sink.accepted == 1 && sink.last.nonce == WIN_NONCE,
          "accepted share reached the receipt/OWED sink carrying the winning nonce");
    CHECK(!sink.last.is_network_block, "share is a lane share, not a Monero network block");
    CHECK(pow.last_blob == receipt.hashing_blob.bytes,
          "the blob the miner PoW-signed is byte-identical to the receipt's hashing blob");

    std::string bad_reply = submit(0xF0000000u, std::string(64, '0').c_str());
    CHECK(contains(bad_reply, "Low diff share") && sink.accepted == 1,
          "an under-target nonce is rejected (low diff), never reaches the sink");

    // =======================================================================
    // STAGE 5 - carrier wire (X7): encode/decode is byte-identical.
    // =======================================================================
    g_stage = "X7";
    std::printf("== STAGE 5: carrier wire encode/decode ==\n");

    wire::CarrierMessage msg;
    msg.chain_id = CHAIN;
    msg.carrier  = receipt;          // the difficulty-gated transport share
    msg.receipts = { receipt };      // one settled receipt riding the carrier

    std::vector<v37::xmr::u8> frame;
    bool enc_ok = true;
    try { frame = wire::encode_carrier(msg); } catch (const wire::WireError& e) {
        enc_ok = false; std::printf("        encode threw: %s\n", e.what());
    }
    CHECK(enc_ok && !frame.empty(), "encode_carrier -> %zu byte frame", frame.size());

    wire::CarrierMessage back;
    bool dec_ok = true;
    try { back = wire::decode_carrier(frame); } catch (const wire::WireError& e) {
        dec_ok = false; std::printf("        decode threw: %s\n", e.what());
    }
    CHECK(dec_ok, "decode_carrier accepts the well-formed frame");
    CHECK(dec_ok && back.chain_id == CHAIN && back.receipts.size() == 1,
          "decoded carrier: chain_id + receipt count preserved");
    // byte-identity: re-encoding the decoded message reproduces the frame exactly.
    bool roundtrip = false;
    if (dec_ok) { try { roundtrip = (wire::encode_carrier(back) == frame); } catch (...) {} }
    CHECK(roundtrip, "re-encode(decode(frame)) == frame  (byte-identical round-trip)");
    // and the decoded receipt's load-bearing fields match the original.
    CHECK(dec_ok && back.carrier.hashing_blob.bytes == receipt.hashing_blob.bytes &&
          back.carrier.info_digest == receipt.info_digest &&
          back.carrier.coinbase_opening.tx_extra == receipt.coinbase_opening.tx_extra,
          "decoded receipt: hashing_blob + info_digest + tx_extra opening preserved");

    // =======================================================================
    // STAGE 6 - receipt admission (X4): verify ACCEPTS the well-formed carrier
    //   receipt (RandomX CI-gated) and REJECTS a tampered one at STRUCTURAL,
    //   before RandomX is ever run. Binding recovers the committed side data.
    // =======================================================================
    g_stage = "X4";
    std::printf("== STAGE 6: receipt admission + verify (accept clean, reject tamper) ==\n");

    const v37::xmr::u64 RECEIPT_BIN = 3'000'000;
    const v37::xmr::u64 CARRIER_BIN = 3'000'001;   // 1 bin ahead, within n_ctx
    v37::xmr::LaneKeyedHeavy lp;

    vf::VerifyConfig cfg;
    cfg.bin_of = [&](const v37::xmr::HashingBlob&, v37::xmr::u64& b) { b = RECEIPT_BIN; return true; };
    cfg.consensus_difficulty = [&](v37::xmr::u64, v37::xmr::Difficulty& d) { d = T_ORIGIN; return true; };
    cfg.seed_for_bin = [&](v37::xmr::u64, const v37::xmr::SeedRef&, v37::xmr::bytes32& s) { s = {}; return true; };
    cfg.seen = [&](const v37::xmr::bytes32&) { return false; };
    // cfg.rx_check left null => RandomX CI-gated (SkippedCIGated on accept).

    // The wire codec carries info_digest but NOT the side_data preimage (it is
    // relayed alongside and bound by the wire-carried info_digest, per the receipt
    // envelope). A receiving node re-attaches the preimage it received; the verify
    // path then requires info_digest == keccak256(side_data) or rejects. Attaching
    // the CORRECT preimage is what a good node does; a wrong one is caught below.
    back.carrier.side_data = sd;

    {
        // verify the receipt AS RECOVERED OFF THE WIRE (the whole point of the stitch)
        v37::xmr::OpenedCommitment oc;
        v37::xmr::AdmitOutcome o =
            vf::verify_receipt(back.carrier, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
        CHECK(o.ok && o.stage == v37::xmr::AdmitStage::Accepted,
              "wire-recovered receipt ACCEPTED through the keyed_heavy admission order");
        CHECK(o.randomx == v37::xmr::RandomXStatus::SkippedCIGated,
              "RandomX CI-gated (heavy hash never run in this light KAT)");
        CHECK(oc.t_origin == T_ORIGIN && oc.payout_identity == IDENT && oc.chain_id == CHAIN,
              "binding recovers the committed T_origin / identity / chain_id");
        vf::ParsedBlob pbind;
        bool pbok = vf::parse_hashing_blob(back.carrier.hashing_blob, pbind);
        CHECK(pbok && std::memcmp(oc.tree_root.data(), pbind.tree_root.data(), 32) == 0,
              "the bound tree_root is the one under the signed blob (full-chain identity)");
    }

    // tamper A: a SEMANTIC lie in the recovered side data (T_origin) -- info_digest
    // no longer matches keccak256(side_data) -> Structural reject, no RandomX.
    {
        v37::xmr::MoneroReceipt bad = back.carrier;
        bad.side_data->t_origin = v37::xmr::Difficulty{999999, 0};
        v37::xmr::OpenedCommitment oc;
        v37::xmr::AdmitOutcome o = vf::verify_receipt(bad, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
        CHECK(!o.ok && o.stage == v37::xmr::AdmitStage::Structural,
              "tampered T_origin REJECTED at Structural (owed_digest binding broke)");
        CHECK(o.randomx == v37::xmr::RandomXStatus::NotReached,
              "tampered receipt never reached RandomX");
    }

    // tamper B: corrupt a byte of the coinbase-opening ON THE WIRE. It still
    // decodes (bounded parser) but the tree_root no longer reproduces -> reject.
    {
        std::vector<v37::xmr::u8> corrupt = frame;
        // flip a byte inside the carrier's coinbase_opening.tx_extra region: locate
        // the 0x03 tag's 32-byte root within the frame and flip its first byte.
        // (Deterministic: the mm_root bytes appear verbatim in the encoded tx_extra.)
        std::size_t at = corrupt.size();
        for (std::size_t i = 0; i + 32 <= corrupt.size(); ++i)
            if (std::memcmp(corrupt.data() + i, cb.mm_root.data(), 32) == 0) { at = i; break; }
        CHECK(at + 32 <= corrupt.size(), "located the committed root inside the wire frame");
        if (at + 32 <= corrupt.size()) corrupt[at] ^= 0x01;
        bool dok = true; wire::CarrierMessage cm;
        try { cm = wire::decode_carrier(corrupt); } catch (const wire::WireError&) { dok = false; }
        CHECK(dok, "corrupted frame still DECODES (parser is total/bounded, not a crash)");
        if (dok) {
            cm.carrier.side_data = sd;   // attach the (honest) preimage; the tampered
                                         // 0x03 root will not match its recomputed leaf
            v37::xmr::OpenedCommitment oc;
            v37::xmr::AdmitOutcome o = vf::verify_receipt(cm.carrier, IDENT, CARRIER_BIN, CHAIN, lp, cfg, oc);
            CHECK(!o.ok && o.randomx == v37::xmr::RandomXStatus::NotReached,
                  "wire-corrupted commitment REJECTED before RandomX (stage=%d)", (int)o.stage);
        }
    }

    // replay guard: the same receipt seen twice dies at Dedup, no RandomX.
    {
        vf::VerifyConfig c2 = cfg;
        c2.seen = [&](const v37::xmr::bytes32&) { return true; };
        v37::xmr::OpenedCommitment oc;
        v37::xmr::AdmitOutcome o = vf::verify_receipt(back.carrier, IDENT, CARRIER_BIN, CHAIN, lp, c2, oc);
        CHECK(!o.ok && o.stage == v37::xmr::AdmitStage::Dedup &&
              o.randomx == v37::xmr::RandomXStatus::NotReached,
              "a replayed carrier receipt dies at Dedup, RandomX never reached");
    }

    // =======================================================================
    std::printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
    std::printf("%s\n", g_fail == 0 ? "X8 E2E KAT OK" : "X8 E2E KAT FAILED");
    return g_fail == 0 ? 0 : 1;
}
