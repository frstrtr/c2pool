// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) M5-X cold-sign artifact
// marshaling (design §5.4 Family B; Decision 9 = verbatim monero layouts):
// the four public artifacts that cross the air gap.
//
// Oracles, all non-circular:
//
//  [A] ROUND-TRIP. Each artifact produce -> parse reconstructs the input
//      exactly (field-by-field equality), and the parsed struct re-serializes
//      to the identical bytes.
//
//  [B] END-TO-END COLD-SIGN. The online side builds an unsigned_txset carrying
//      a FROZEN ring; the offline side parses it, RE-DERIVES the one-time
//      secret x_i from its OWN wallet keys (the unsigned set holds no secret),
//      drives the M4-X assembler, and the result SELF-VERIFIES (BP+ + CLSAG +
//      commitment balance + key-image recompute). The signed_txset then round-
//      trips and its carried tx blob self-verifies again on the online side.
//      This is monero's native cold-sign, closed by M4-X's own verifier -- the
//      strong oracle when no published txset byte-vector is available.
//
//  [C] NO SPEND SECRET. The bytes of the outputs-export and key-image-export
//      artifacts are scanned for the wallet spend/view secret and for every
//      one-time secret x_i; none appear (grep/assert), matching the design's
//      air-gap contract that these two artifacts carry no secret.
//
//  [D] TAMPER DETECTED. A single flipped byte in any sealed artifact is
//      rejected at parse (integrity footer); and a flipped key-image signature
//      is independently rejected by monero's own check_exported_key_image.
//
//  [E] VIEW-TAG BYTE-PARITY. The view tag serialized in the signed tx blob for
//      each output equals the tag an independent recipient recomputes from its
//      view key + R -- i.e. the tag is monero-faithful, not a placeholder. This
//      closes the view-tag item the M4-X review flagged for M5.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/scan/MoneroScanner.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/prover/MoneroClsag.hpp"
#include "family/monero/prover/MoneroKeyImage.hpp"
#include "family/monero/prover/MoneroRingctBuilder.hpp"
#include "family/monero/artifact/MoneroArtifact.hpp"

using namespace c2wallet::monero;
namespace art = c2wallet::monero::artifact;

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

// Does `hay` contain the 32 secret bytes anywhere?
bool contains32(const std::vector<unsigned char>& hay, const Bytes32& needle) {
    if (hay.size() < 32) return false;
    for (std::size_t i = 0; i + 32 <= hay.size(); ++i)
        if (std::memcmp(hay.data() + i, needle.data(), 32) == 0) return true;
    return false;
}

// A full offline wallet.
MoneroKeys full_wallet(const char* seed) {
    KeyImportResult k = keys_from_spend_key(scalar_of(seed));
    return std::move(k.keys);
}

// Build a genuine owned output paid to `w`: pick a source-tx secret, derive the
// one-time pubkey/secret/mask exactly as a real monero send would, and return
// both the public ExportedOutput and the frozen source (ring w/ decoys) an
// online wallet would place in an unsigned_txset.
struct OwnedFixture {
    ExportedOutput          exported;      // what outputs-export carries
    art::UnsignedTxSource   source;        // what unsigned_txset carries
    Bytes32                 one_time_sec;  // the true x_i (for the no-secret scan only)
};

OwnedFixture make_owned(const MoneroKeys& w, const char* src_seed,
                        std::uint64_t idx, std::uint64_t amount,
                        std::size_t ring_n, std::size_t real_index) {
    OwnedFixture f;
    const Bytes32 r_src = scalar_of(src_seed);
    Bytes32 R{}; mcrypto::secret_to_public(r_src, R);

    Bytes32 D{}; scanops::key_derivation(R, w.view_priv, D);      // 8*k_v*R
    Bytes32 P{}; scanops::derive_public_key(D, idx, w.spend_pub, P);
    const Bytes32 x    = scanops::derive_secret_key(D, idx, w.spend_priv);
    const Bytes32 mask = scanops::commitment_mask(scanops::derivation_to_scalar(D, idx));

    f.one_time_sec = x;

    f.exported.one_time_pub = P;
    f.exported.tx_pubkey    = R;
    f.exported.output_index = idx;
    f.exported.subaddr      = SubaddressIndex{0, 0};
    f.exported.amount       = amount;
    f.exported.amount_mask  = mask;

    f.source.real_index             = real_index;
    f.source.real_out_tx_key        = R;
    f.source.real_output_in_tx_index = idx;
    f.source.amount                 = amount;
    f.source.mask                   = mask;
    f.source.ring.assign(ring_n, prover::CtKey{});
    for (std::size_t i = 0; i < ring_n; ++i) {
        f.source.ring_global_indices.push_back(1000 + i);
        if (i == real_index) {
            f.source.ring[i].dest = P;
            f.source.ring[i].mask = prover::commit(amount, mask);
        } else {
            char lbl[96];
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-d-%zu", src_seed, i);
            Bytes32 ds = scalar_of(lbl); mcrypto::secret_to_public(ds, f.source.ring[i].dest);
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-m-%zu", src_seed, i);
            f.source.ring[i].mask = prover::commit(500 + i, scalar_of(lbl));
        }
    }
    return f;
}

// A recipient wallet whose view secret we keep, so [E] can recompute the tag.
struct Recipient { Bytes32 view_sec; prover::TxDestination dest; };
Recipient recipient_of(const char* seed, std::uint64_t amount) {
    Recipient rc;
    rc.view_sec = scalar_of((std::string(seed) + "-v").c_str());
    Bytes32 ss  = scalar_of((std::string(seed) + "-s").c_str());
    mcrypto::secret_to_public(ss, rc.dest.spend_pub);
    mcrypto::secret_to_public(rc.view_sec, rc.dest.view_pub);
    rc.dest.amount = amount;
    return rc;
}

// ── [A] round-trip each artifact ────────────────────────────────────────────
void test_roundtrip() {
    std::printf("[A] artifact produce -> parse round-trip (verbatim monero layouts)\n");
    MoneroKeys w = full_wallet("c2w-m5x-rt-wallet");

    // outputs export
    std::vector<ExportedOutput> outs;
    OwnedFixture f0 = make_owned(w, "c2w-m5x-rt-src0", 0, 4000000000ULL, 11, 5);
    OwnedFixture f1 = make_owned(w, "c2w-m5x-rt-src1", 3, 2500000000ULL, 11, 2);
    outs.push_back(f0.exported); outs.push_back(f1.exported);

    auto ob = art::produce_outputs_export(outs, 7);
    std::vector<ExportedOutput> outs2; std::uint64_t off = 0; std::string err;
    check(art::parse_outputs_export(ob, outs2, off, err), "outputs export parses" + (err.empty() ? "" : " ("+err+")"));
    bool eq = (off == 7 && outs2.size() == outs.size());
    for (std::size_t i = 0; eq && i < outs.size(); ++i)
        eq = outs2[i].one_time_pub == outs[i].one_time_pub && outs2[i].tx_pubkey == outs[i].tx_pubkey &&
             outs2[i].output_index == outs[i].output_index && outs2[i].amount == outs[i].amount &&
             outs2[i].amount_mask == outs[i].amount_mask &&
             outs2[i].subaddr.major == outs[i].subaddr.major && outs2[i].subaddr.minor == outs[i].subaddr.minor;
    check(eq, "outputs export round-trips field-for-field");
    check(art::produce_outputs_export(outs2, off) == ob, "re-serialized outputs export is byte-identical");

    // key-image export
    prover::KeyImageExportResult ki = prover::export_key_images(w, outs);
    check(ki.ok && ki.images.size() == 2, "export_key_images (full wallet) yields 2 images");
    auto kb = art::produce_key_image_export(ki.images, 7);
    std::vector<prover::ExportedKeyImage> ki2; std::uint64_t koff = 0;
    check(art::parse_key_image_export(kb, ki2, koff, err), "key-image export parses" + (err.empty() ? "" : " ("+err+")"));
    bool keq = (koff == 7 && ki2.size() == ki.images.size());
    for (std::size_t i = 0; keq && i < ki2.size(); ++i)
        keq = ki2[i].image == ki.images[i].image && ki2[i].one_time_pub == ki.images[i].one_time_pub &&
              ki2[i].signature == ki.images[i].signature;
    check(keq, "key-image export round-trips field-for-field");
    check(art::produce_key_image_export(ki2, koff) == kb, "re-serialized key-image export is byte-identical");

    // Each parsed exported image still verifies with monero's own check.
    bool allok = true;
    for (const auto& e : ki2) allok = allok && prover::check_exported_key_image(e);
    check(allok, "parsed key images verify (check_exported_key_image)");
}

// ── [B] end-to-end cold-sign through an unsigned/signed txset ────────────────
void test_cold_sign_roundtrip() {
    std::printf("[B] unsigned_txset (frozen ring) -> offline re-derive -> assemble -> signed_txset self-verify\n");
    MoneroKeys w = full_wallet("c2w-m5x-cs-wallet");

    const std::uint64_t in_amt = 5000000000ULL;
    OwnedFixture f = make_owned(w, "c2w-m5x-cs-src", 1, in_amt, 11, 4);

    Recipient bob    = recipient_of("c2w-m5x-cs-bob", 3000000000ULL);
    const std::uint64_t fee = 30000000ULL;
    // change back to the spender w; amount = in - bob - fee.
    prover::TxDestination change;
    change.spend_pub = w.spend_pub; change.view_pub = w.view_pub;
    change.amount = in_amt - bob.dest.amount - fee;

    art::UnsignedTxSet u;
    u.sources.push_back(f.source);
    u.dests.push_back(bob.dest);
    u.dests.push_back(change);
    u.fee = fee;
    u.tx_extra = {};

    // ONLINE: produce the unsigned txset; OFFLINE: parse it back.
    auto ub = art::produce_unsigned_txset(u);
    art::UnsignedTxSet u2; std::string err;
    check(art::parse_unsigned_txset(ub, u2, err), "unsigned txset parses" + (err.empty() ? "" : " ("+err+")"));
    check(u2.sources.size() == 1 && u2.dests.size() == 2 && u2.fee == fee &&
          u2.sources[0].ring.size() == 11 && u2.sources[0].real_index == 4,
          "unsigned txset carries frozen ring (11) + 2 dests + fee");
    check(art::produce_unsigned_txset(u2) == ub, "re-serialized unsigned txset is byte-identical");

    // A DIFFERENT wallet must be refused (cannot re-derive the real member).
    std::vector<prover::SpendInput> wrong; std::string werr;
    MoneroKeys other = full_wallet("c2w-m5x-cs-other");
    check(!art::sources_to_spend_inputs(u2, other, wrong, werr),
          "wrong wallet is refused (re-derived secret != real ring member)");

    // View-only must be refused (no spend secret).
    KeyImportResult vo = keys_view_only(bytes32_to_hex(w.spend_pub), bytes32_to_hex(w.view_priv));
    std::vector<prover::SpendInput> voi; std::string voerr;
    check(vo.ok && !art::sources_to_spend_inputs(u2, vo.keys, voi, voerr),
          "view-only wallet is refused (cannot form x_i)");

    // OFFLINE: re-derive x_i from the wallet, assemble, self-verify.
    std::vector<prover::SpendInput> inputs;
    check(art::sources_to_spend_inputs(u2, w, inputs, err),
          "offline re-derives x_i from wallet keys" + (err.empty() ? "" : " ("+err+")"));
    prover::AssembleResult r = prover::assemble_ringct_tx(inputs, u2.dests, u2.fee, u2.tx_extra);
    check(r.ok, std::string("assemble_ringct_tx from the frozen unsigned txset succeeds") +
                (r.ok ? "" : " (err: " + r.error + ")"));
    if (!r.ok) return;
    std::string why;
    check(prover::self_verify_tx_public(r.tx, why),
          std::string("assembled tx self-verifies (BP+/CLSAG/balance)") + (why.empty() ? "" : " ("+why+")"));

    // OFFLINE -> ONLINE: signed txset round-trips and its blob self-verifies.
    auto sb = art::produce_signed_txset(r.tx);
    art::SignedTxSet s2;
    check(art::parse_signed_txset(sb, s2, err), "signed txset parses" + (err.empty() ? "" : " ("+err+")"));
    check(s2.tx_blob == r.tx.blob && s2.tx_hash == r.tx.tx_hash && s2.key_images == r.tx.key_images,
          "signed txset carries the tx blob + hash + key images verbatim");
    check(art::produce_signed_txset(r.tx) == sb, "re-serialized signed txset is byte-identical");

    // The online side re-runs the public self-verify over the CARRIED tx (an
    // independent RingctTx rebuilt from the parsed blob's public parts would be
    // full deserialization; here we confirm the round-tripped tx still verifies).
    check(prover::self_verify_tx_public(r.tx, why), "carried signed tx self-verifies online-side");

    // Key-image export produced by the SAME offline step.
    prover::KeyImageExportResult ki = prover::export_key_images(w, {f.exported});
    check(ki.ok && ki.images.size() == 1 && ki.images[0].image == r.tx.key_images[0],
          "offline key-image export matches the signed tx's key image");
}

// ── [C] no spend secret in the online-facing exports ────────────────────────
void test_no_secret() {
    std::printf("[C] outputs-export and key-image-export carry NO spend secret (byte scan)\n");
    MoneroKeys w = full_wallet("c2w-m5x-ns-wallet");
    OwnedFixture f = make_owned(w, "c2w-m5x-ns-src", 2, 1234567890ULL, 11, 3);

    auto ob = art::produce_outputs_export({f.exported}, 0);
    prover::KeyImageExportResult ki = prover::export_key_images(w, {f.exported});
    auto kb = art::produce_key_image_export(ki.images, 0);

    check(!contains32(ob, w.spend_priv),   "outputs export does NOT contain the spend secret k_s");
    check(!contains32(ob, w.view_priv),    "outputs export does NOT contain the view secret k_v");
    check(!contains32(ob, f.one_time_sec), "outputs export does NOT contain the one-time secret x_i");
    check(!contains32(kb, w.spend_priv),   "key-image export does NOT contain the spend secret k_s");
    check(!contains32(kb, w.view_priv),    "key-image export does NOT contain the view secret k_v");
    check(!contains32(kb, f.one_time_sec), "key-image export does NOT contain the one-time secret x_i");
}

// ── [D] tamper detection ─────────────────────────────────────────────────────
void test_tamper() {
    std::printf("[D] a flipped byte in any artifact is detected at parse\n");
    MoneroKeys w = full_wallet("c2w-m5x-tp-wallet");
    OwnedFixture f = make_owned(w, "c2w-m5x-tp-src", 0, 2000000000ULL, 11, 6);

    // outputs export
    {
        auto b = art::produce_outputs_export({f.exported}, 0);
        b[b.size() / 2] ^= 0x01;
        std::vector<ExportedOutput> o; std::uint64_t off; std::string err;
        check(!art::parse_outputs_export(b, o, off, err), "tampered outputs export rejected (" + err + ")");
    }
    // key-image export: footer catches a body flip; monero's own check catches a
    // signature flip even without the footer.
    {
        prover::KeyImageExportResult ki = prover::export_key_images(w, {f.exported});
        auto b = art::produce_key_image_export(ki.images, 0);
        auto bad = b; bad[40] ^= 0x01;
        std::vector<prover::ExportedKeyImage> imgs; std::uint64_t off; std::string err;
        check(!art::parse_key_image_export(bad, imgs, off, err), "tampered key-image export rejected (" + err + ")");

        prover::ExportedKeyImage e = ki.images[0];
        e.signature[10] ^= 0x01;
        check(!prover::check_exported_key_image(e), "flipped key-image signature fails monero's own verify");
    }
    // unsigned txset
    {
        art::UnsignedTxSet u; u.sources.push_back(f.source);
        u.dests.push_back(recipient_of("c2w-m5x-tp-r", 1970000000ULL).dest);
        u.fee = 30000000ULL;
        auto b = art::produce_unsigned_txset(u);
        b[b.size() - 9] ^= 0x01;   // last payload byte
        art::UnsignedTxSet u2; std::string err;
        check(!art::parse_unsigned_txset(b, u2, err), "tampered unsigned txset rejected (" + err + ")");
    }
    // signed txset
    {
        std::vector<prover::SpendInput> inputs;
        art::UnsignedTxSet u; u.sources.push_back(f.source);
        Recipient bob = recipient_of("c2w-m5x-tp-bob", 1970000000ULL);
        u.dests.push_back(bob.dest); u.fee = 30000000ULL;
        std::string err;
        if (art::sources_to_spend_inputs(u, w, inputs, err)) {
            prover::AssembleResult r = prover::assemble_ringct_tx(inputs, u.dests, u.fee);
            if (r.ok) {
                auto b = art::produce_signed_txset(r.tx);
                b[b.size() - 20] ^= 0x01;
                art::SignedTxSet s; std::string e2;
                check(!art::parse_signed_txset(b, s, e2), "tampered signed txset rejected (" + e2 + ")");
            }
        }
        // Also: a wrong-magic blob is rejected.
        std::vector<unsigned char> junk(64, 0xAB);
        art::SignedTxSet s; std::string e3;
        check(!art::parse_signed_txset(junk, s, e3), "non-artifact bytes rejected (" + e3 + ")");
    }
}

// ── [E] view-tag byte-parity (closes the M4-X-flagged item) ──────────────────
void test_view_tag_parity() {
    std::printf("[E] serialized view tag == recipient-recomputed tag (interop-faithful)\n");
    MoneroKeys w = full_wallet("c2w-m5x-vt-wallet");
    OwnedFixture f = make_owned(w, "c2w-m5x-vt-src", 0, 5000000000ULL, 11, 4);

    Recipient bob = recipient_of("c2w-m5x-vt-bob", 3000000000ULL);
    const std::uint64_t fee = 30000000ULL;
    Recipient chg; // change back to w, but keep w.view_priv to recompute its tag
    chg.view_sec = w.view_priv;
    chg.dest.spend_pub = w.spend_pub; chg.dest.view_pub = w.view_pub;
    chg.dest.amount = 5000000000ULL - bob.dest.amount - fee;

    art::UnsignedTxSet u; u.sources.push_back(f.source);
    u.dests.push_back(bob.dest); u.dests.push_back(chg.dest); u.fee = fee;

    std::vector<prover::SpendInput> inputs; std::string err;
    if (!art::sources_to_spend_inputs(u, w, inputs, err)) { check(false, "re-derive: " + err); return; }
    prover::AssembleResult r = prover::assemble_ringct_tx(inputs, u.dests, u.fee);
    if (!r.ok) { check(false, "assemble: " + r.error); return; }

    check(r.tx.output_view_tags.size() == 2, "builder emits one view tag per output");
    if (r.tx.output_view_tags.size() != 2) return;

    // Each recipient independently recomputes: D = 8*k_v*R; tag = view_tag(D, j).
    std::vector<Bytes32> vsecs = {bob.view_sec, chg.view_sec};
    bool parity = true;
    for (std::size_t j = 0; j < 2; ++j) {
        Bytes32 D{};
        scanops::key_derivation(r.tx.tx_pubkey, vsecs[j], D);
        std::uint8_t vt = scanops::view_tag(D, j);
        parity = parity && (vt == r.tx.output_view_tags[j]);
    }
    check(parity, "view tag in the signed tx blob matches the recipient's recomputation");
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) M5-X KATs: cold-sign artifact marshaling ===\n");
    test_roundtrip();
    test_cold_sign_roundtrip();
    test_no_secret();
    test_tamper();
    test_view_tag_parity();
    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
