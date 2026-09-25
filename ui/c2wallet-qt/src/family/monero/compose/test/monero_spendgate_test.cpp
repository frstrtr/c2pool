// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// M6 slice-2b KATs — the Family-B (Monero) Build/Sign page money-gate.
//
// These drive the SAME Qt-free compose gate (MoneroSpendGate) and the SAME
// artifact/prover facade the PageBuildTxMonero / PageSignMonero screens call,
// so the money-path logic is exercised without instantiating any Qt widget
// (design §2.3 — link the leaf, not the shell).
//
//  K7  End-to-end cold-sign through the facade with a FIXTURE ring:
//        outputs-export -> unsigned_txset -> parse -> sources_to_spend_inputs
//        -> assemble_ringct_tx(self_verify) -> self_verify_tx_public +
//        self_verify_key_images -> produce_signed_txset -> parse_signed_txset
//        (blob/hash/key-images equality).
//      Plus the refusals the pages enforce: wrong wallet, view-only, a
//        net-mismatch destination (T-2/T-12), an unbalanced set (Σ≠), and a
//        flipped byte in the unsigned/signed blob (keccak footer).
//      Plus the both-units integer-only amount helpers (T-1) and the
//        OWN/EXTERNAL classifier (T-3), incl. a change subaddress.
//
//  K8(B)  Secret zeroization (T-8 / GAP-6): after the page-side wipe every
//         SpendInput.one_time_sec is all-zero; and prover::SpendInput's own
//         destructor scrubs its one_time_sec storage.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/scan/MoneroScanner.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/prover/MoneroClsag.hpp"
#include "family/monero/prover/MoneroRingctBuilder.hpp"
#include "family/monero/artifact/MoneroArtifact.hpp"
#include "family/monero/compose/MoneroSpendGate.hpp"

using namespace c2wallet::monero;
namespace art = c2wallet::monero::artifact;
namespace pv  = c2wallet::monero::prover;
namespace cg  = c2wallet::monero::compose;

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string& what) {
    ++g_checks;
    std::printf(cond ? "  ok   : %s\n" : "  FAIL : %s\n", what.c_str());
    if (!cond) ++g_failures;
}

Bytes32 scalar_of(const char* label) {
    return mcrypto::reduce32(mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>(label), std::strlen(label)));
}
bool is_zero32(const Bytes32& b) {
    for (std::uint8_t x : b) if (x != 0) return false;
    return true;
}

MoneroKeys full_wallet(const char* seed) {
    KeyImportResult k = keys_from_spend_key(scalar_of(seed));
    return std::move(k.keys);
}

// Build a genuine owned output paid to `w` + the frozen source an online wallet
// would place in an unsigned_txset (mirrors the M5-X artifact KAT fixture).
struct OwnedFixture {
    ExportedOutput        exported;
    art::UnsignedTxSource source;
    Bytes32               one_time_sec;
};
OwnedFixture make_owned(const MoneroKeys& w, const char* src_seed,
                        std::uint64_t idx, std::uint64_t amount,
                        std::size_t ring_n, std::size_t real_index) {
    OwnedFixture f;
    const Bytes32 r_src = scalar_of(src_seed);
    Bytes32 R{}; mcrypto::secret_to_public(r_src, R);
    Bytes32 D{}; scanops::key_derivation(R, w.view_priv, D);
    Bytes32 P{}; scanops::derive_public_key(D, idx, w.spend_pub, P);
    const Bytes32 x    = scanops::derive_secret_key(D, idx, w.spend_priv);
    const Bytes32 mask = scanops::commitment_mask(scanops::derivation_to_scalar(D, idx));

    f.one_time_sec          = x;
    f.exported.one_time_pub = P;
    f.exported.tx_pubkey    = R;
    f.exported.output_index = idx;
    f.exported.subaddr      = SubaddressIndex{0, 0};
    f.exported.amount       = amount;
    f.exported.amount_mask  = mask;

    f.source.real_index              = real_index;
    f.source.real_out_tx_key         = R;
    f.source.real_output_in_tx_index = idx;
    f.source.amount                  = amount;
    f.source.mask                    = mask;
    f.source.ring.assign(ring_n, pv::CtKey{});
    for (std::size_t i = 0; i < ring_n; ++i) {
        f.source.ring_global_indices.push_back(1000 + i);
        if (i == real_index) {
            f.source.ring[i].dest = P;
            f.source.ring[i].mask = pv::commit(amount, mask);
        } else {
            char lbl[96];
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-d-%zu", src_seed, i);
            Bytes32 ds = scalar_of(lbl); mcrypto::secret_to_public(ds, f.source.ring[i].dest);
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-m-%zu", src_seed, i);
            f.source.ring[i].mask = pv::commit(500 + i, scalar_of(lbl));
        }
    }
    return f;
}

pv::TxDestination recipient(const char* seed, std::uint64_t amount) {
    pv::TxDestination d;
    Bytes32 ss = scalar_of((std::string(seed) + "-s").c_str());
    Bytes32 vs = scalar_of((std::string(seed) + "-v").c_str());
    mcrypto::secret_to_public(ss, d.spend_pub);
    mcrypto::secret_to_public(vs, d.view_pub);
    d.amount = amount;
    return d;
}

// ── T-1: both-units, integer-only amount helpers ─────────────────────────────
void test_amount_units() {
    std::printf("[K7] both-units integer-only amounts (T-1)\n");
    check(cg::format_xmr(1234500000000ULL) == "1.234500000000", "format_xmr(1.2345 XMR) exact 12-dp");
    check(cg::format_xmr(0ULL) == "0.000000000000", "format_xmr(0) exact");
    check(cg::format_xmr(1ULL) == "0.000000000001", "format_xmr(1 pico) exact");
    std::uint64_t p = 0; std::string e;
    check(cg::parse_xmr("2.5", p, e) && p == 2500000000000ULL, "parse_xmr(2.5) == 2.5e12 pico");
    check(cg::parse_xmr("0.000000000001", p, e) && p == 1ULL, "parse_xmr(1 pico) exact");
    check(!cg::parse_xmr("1.0000000000001", p, e), "parse_xmr rejects >12 dp (sub-piconero)");
    check(!cg::parse_xmr("1.2.3", p, e), "parse_xmr rejects two decimal points");
    check(!cg::parse_xmr("1e9", p, e), "parse_xmr rejects non-numeric (no double/sci notation)");
    check(cg::both_units(2500000000000ULL) == "2.500000000000 XMR (2500000000000 pico)", "both_units render");
}

// ── T-2/T-12: destination network check ──────────────────────────────────────
void test_net_check() {
    std::printf("[K7] destination address network check (T-2/T-12, the #961 analog)\n");
    MoneroKeys w = full_wallet("c2w-2b-net");
    MoneroAddress main_a = make_standard(w.spend_pub, w.view_pub, Network::Mainnet);
    MoneroAddress test_a = make_standard(w.spend_pub, w.view_pub, Network::Testnet);
    const std::string main_s = address_encode(main_a);
    const std::string test_s = address_encode(test_a);

    cg::DecodedDest dd; std::string err;
    check(cg::decode_dest(main_s, Network::Mainnet, dd, err), "mainnet address accepted for a mainnet build");
    check(!cg::decode_dest(test_s, Network::Mainnet, dd, err), std::string("testnet address REFUSED for a mainnet build (") + err + ")");
    check(cg::decode_dest(test_s, Network::Testnet, dd, err), "testnet address accepted for a testnet build");
    check(!cg::decode_dest("not-a-monero-address", Network::Mainnet, dd, err), "garbage address refused");
}

// ── T-3: OWN/EXTERNAL classifier, incl. a change subaddress ──────────────────
void test_ownership() {
    std::printf("[K7] OWN/EXTERNAL classifier incl. change subaddress (T-3)\n");
    MoneroKeys w = full_wallet("c2w-2b-own");
    SubaddressTable subs; subs.build(w.view_priv, w.spend_pub, 2, 200);

    pv::TxDestination change;   // standard change back to the primary
    change.spend_pub = w.spend_pub; change.view_pub = w.view_pub; change.amount = 1;
    check(cg::classify_dest(change, w, subs) == cg::Ownership::Own, "primary/standard change is OWN");

    pv::TxDestination ext = recipient("c2w-2b-ext", 1);
    check(cg::classify_dest(ext, w, subs) == cg::Ownership::External, "a foreign destination is EXTERNAL");

    // BLOCKER regression: OWN must bind BOTH keys. A dest carrying our real
    // spend pub but a FOREIGN view key (a change-key swap by a compromised host)
    // must be EXTERNAL — a spend-pub-only classifier wrongly called it OWN and
    // the change would be burned.
    pv::TxDestination spoof;
    spoof.spend_pub = w.spend_pub;                          // our real K_s
    spoof.view_pub  = recipient("c2w-2b-foreign-view", 1).spend_pub;  // a foreign point
    spoof.amount    = 1;
    check(cg::classify_dest(spoof, w, subs) == cg::Ownership::External,
          "owned spend_pub + FOREIGN view_pub => EXTERNAL (two-key OWN binding)");

    // A genuine subaddress we own still classifies OWN (defense-in-depth two-key
    // match) — but it is REFUSED as NOT-PAYABLE by this signer (no per-output tx
    // key), so the pages never let it through to signing.
    SubaddressResult sr = derive_subaddress(w.view_priv, w.spend_pub, 1, 5, Network::Mainnet);
    check(sr.ok, "derive_subaddress (1,5) ok");
    pv::TxDestination subchg;
    subchg.spend_pub = sr.sub_spend_pub; subchg.view_pub = sr.sub_view_pub; subchg.is_subaddress = true; subchg.amount = 1;
    check(cg::classify_dest(subchg, w, subs) == cg::Ownership::Own, "classifier: a genuine change SUBADDRESS two-key match is OWN");
    std::string sub_r, pid_r, std_r;
    const bool sub_ok = cg::dest_supported(/*is_subaddress*/true, /*has_payment_id*/false, sub_r);
    const bool pid_ok = cg::dest_supported(/*is_subaddress*/false, /*has_payment_id*/true, pid_r);
    const bool std_ok = cg::dest_supported(/*is_subaddress*/false, /*has_payment_id*/false, std_r);
    check(!sub_ok, std::string("a SUBADDRESS destination is refused NOT-PAYABLE (") + sub_r + ")");
    check(!pid_ok, std::string("an INTEGRATED/payment-id destination is refused NOT-PAYABLE (") + pid_r + ")");
    check(std_ok,  "a STANDARD destination is supported (payable)");
}

// ── K7: end-to-end cold-sign + refusals, through the facade ──────────────────
void test_cold_sign() {
    std::printf("[K7] end-to-end cold-sign through the facade (fixture ring) + refusals\n");
    MoneroKeys w = full_wallet("c2w-2b-cs-wallet");
    const std::uint64_t in_amt = 5000000000ULL;
    OwnedFixture f = make_owned(w, "c2w-2b-cs-src", 1, in_amt, 11, 4);

    // online: outputs-export produce -> parse (the composer's owned-output view).
    auto ob = art::produce_outputs_export({f.exported}, 0);
    std::vector<ExportedOutput> outs2; std::uint64_t off = 0; std::string oerr;
    check(art::parse_outputs_export(ob, outs2, off, oerr) && outs2.size() == 1, "outputs-export parses (1 owned output)");

    pv::TxDestination bob = recipient("c2w-2b-cs-bob", 3000000000ULL);
    const std::uint64_t fee = 30000000ULL;
    pv::TxDestination change;   // change back to w
    change.spend_pub = w.spend_pub; change.view_pub = w.view_pub;
    change.amount = in_amt - bob.amount - fee;

    art::UnsignedTxSet u;
    u.sources.push_back(f.source);
    u.dests.push_back(bob);
    u.dests.push_back(change);
    u.fee = fee;

    // balance gate (T-5 precondition).
    std::uint64_t sin = 0, sout = 0;
    check(cg::balance_ok(u.sources, u.dests, u.fee, sin, sout) && sin == in_amt && sout == bob.amount + change.amount,
          "balance gate: Σsources == Σdests + fee");

    // online -> offline: produce + re-parse the unsigned_txset (keccak footer).
    auto ub = art::produce_unsigned_txset(u);
    art::UnsignedTxSet u2; std::string err;
    check(art::parse_unsigned_txset(ub, u2, err), std::string("unsigned_txset parses") + (err.empty() ? "" : " ("+err+")"));
    check(u2.sources.size() == 1 && u2.dests.size() == 2 && u2.fee == fee && u2.sources[0].ring.size() == 11,
          "parsed unsigned_txset carries the frozen ring (11) + 2 dests + fee");

    // refuse: wrong wallet.
    MoneroKeys other = full_wallet("c2w-2b-cs-other");
    std::vector<pv::SpendInput> wrong; std::string werr;
    check(!art::sources_to_spend_inputs(u2, other, wrong, werr),
          "wrong wallet refused (re-derived one-time secret != real ring member)");

    // refuse: view-only.
    KeyImportResult vo = keys_view_only(bytes32_to_hex(w.spend_pub), bytes32_to_hex(w.view_priv));
    std::vector<pv::SpendInput> voi; std::string voerr;
    check(vo.ok && !vo.keys.can_sign(), "view-only key set reports can_sign()==false");
    check(!art::sources_to_spend_inputs(u2, vo.keys, voi, voerr), "view-only wallet refused (cannot form x_i)");

    // offline: re-derive x_i, assemble with self_verify, explicit self-verifies.
    std::vector<pv::SpendInput> inputs;
    check(art::sources_to_spend_inputs(u2, w, inputs, err), std::string("offline re-derives x_i") + (err.empty() ? "" : " ("+err+")"));
    check(!inputs.empty() && !is_zero32(inputs[0].one_time_sec), "re-derived SpendInput carries a non-zero x_i");

    pv::AssembleResult r = pv::assemble_ringct_tx(inputs, u2.dests, u2.fee, u2.tx_extra, /*self_verify*/true);
    check(r.ok, std::string("assemble_ringct_tx(self_verify) succeeds") + (r.ok ? "" : " ("+r.error+")"));
    if (!r.ok) return;
    std::string why;
    check(pv::self_verify_tx_public(r.tx, why), std::string("explicit self_verify_tx_public") + (why.empty() ? "" : " ("+why+")"));
    check(pv::self_verify_key_images(inputs, r.tx, why), std::string("explicit self_verify_key_images") + (why.empty() ? "" : " ("+why+")"));

    // emit + round-trip equality.
    auto sb = art::produce_signed_txset(r.tx);
    art::SignedTxSet s2;
    check(art::parse_signed_txset(sb, s2, err), std::string("signed_txset parses") + (err.empty() ? "" : " ("+err+")"));
    check(s2.tx_blob == r.tx.blob && s2.tx_hash == r.tx.tx_hash && s2.key_images == r.tx.key_images,
          "signed_txset round-trips blob/hash/key-images verbatim");

    // GAP-6: page-side scrub after the secrets are consumed (K8 also asserts this).
    cg::wipe_spend_inputs(inputs);
    bool allz = true; for (const auto& si : inputs) allz = allz && is_zero32(si.one_time_sec);
    check(allz, "K8(B): SpendInput.one_time_sec == 0 after the page-side wipe");

    // refuse: unbalanced set (Σ != ) — gate AND assembler both refuse.
    art::UnsignedTxSet ubad = u2;
    ubad.dests[0].amount += 1;                 // now Σout+fee > Σin
    std::uint64_t bi = 0, bo = 0;
    check(!cg::balance_ok(ubad.sources, ubad.dests, ubad.fee, bi, bo), "balance gate refuses an unbalanced set");
    std::vector<pv::SpendInput> binputs;
    check(art::sources_to_spend_inputs(ubad, w, binputs, err), "re-derive x_i for the unbalanced set");
    pv::AssembleResult rb = pv::assemble_ringct_tx(binputs, ubad.dests, ubad.fee, ubad.tx_extra, true);
    check(!rb.ok, "assemble_ringct_tx refuses the unbalanced set (Σin != Σout + fee)");
    cg::wipe_spend_inputs(binputs);

    // refuse: a flipped byte in the unsigned / signed blob (keccak footer).
    {
        auto bad = ub; bad[bad.size() - 9] ^= 0x01;
        art::UnsignedTxSet t; std::string te;
        check(!art::parse_unsigned_txset(bad, t, te), std::string("flipped-byte unsigned_txset rejected (") + te + ")");
    }
    {
        auto bad = sb; bad[bad.size() - 20] ^= 0x01;
        art::SignedTxSet t; std::string te;
        check(!art::parse_signed_txset(bad, t, te), std::string("flipped-byte signed_txset rejected (") + te + ")");
    }
}

// ── K8(B): the SpendInput destructor scrubs its one_time_sec storage ─────────
void test_dtor_scrub() {
    std::printf("[K8(B)] prover::SpendInput destructor zeroizes one_time_sec (GAP-6)\n");
    alignas(pv::SpendInput) unsigned char buf[sizeof(pv::SpendInput)];
    auto* p = new (buf) pv::SpendInput();
    p->one_time_sec = scalar_of("c2w-2b-dtor-secret");
    // offset of one_time_sec within the object's raw storage.
    const std::size_t off = reinterpret_cast<unsigned char*>(&p->one_time_sec) - buf;
    bool nonzero_before = false;
    for (std::size_t k = 0; k < 32; ++k) if (buf[off + k] != 0) nonzero_before = true;
    check(nonzero_before, "one_time_sec is non-zero before destruction");
    p->~SpendInput();
    // read the underlying char buffer (our own storage; well-defined).
    bool scrubbed = true;
    for (std::size_t k = 0; k < 32; ++k) if (buf[off + k] != 0) scrubbed = false;
    check(scrubbed, "one_time_sec storage is all-zero after ~SpendInput()");
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) M6-2b KATs: Build/Sign page money-gate ===\n");
    test_amount_units();
    test_net_check();
    test_ownership();
    test_cold_sign();
    test_dtor_scrub();
    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
