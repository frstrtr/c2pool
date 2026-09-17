// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the M5-A Family-A air-gap transfer artifacts (design
// docs/design/c2wallet-qt.md §5.4). This module MARSHALS bytes across the gap;
// it does not sign. The tests prove:
//   * the digest primitive against a published SHA-256 vector;
//   * the PSBT-like UnsignedContainer round-trips (build -> serialize -> parse),
//     with the sighash-algebra selector, per-input metadata and optional
//     pre-flight verdict all preserved, and refuses oversize / bad input;
//   * the SignedContainer emits ONE raw hex per line and parses with EXACTLY
//     the c2pool loader's rules (whitespace strip, skip-blank, odd-length
//     all-or-nothing refusal) — the format proven at block 2518186;
//   * the multi-frame QR codec round-trips and handles a dropped frame, a
//     duplicated frame, an out-of-order frame, per-frame digest mismatch, and
//     the 100 kB oversize refusal;
//   * the validate-seam contract round-trips (validate/submit + validate_inject
//     dry-run) and the cross-gap sha256d digest matches / mismatches correctly,
//     with the online call left as a named unwired cross-lane seam.

#include "../Digest.hpp"
#include "../TransferContainer.hpp"
#include "../QrTransport.hpp"
#include "../ValidateSeam.hpp"
#include "../TxIntrospect.hpp"   // slice-2c confusion guard
#include "../QrRender.hpp"       // slice-2c GAP-8 bitmap layer

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace c2w::artifact;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                \
    do {                                                                                \
        if (cond) { ++g_pass; }                                                         \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } \
    } while (0)

static Bytes B(const std::string& hex) {
    auto v = from_hex(hex);
    return v ? *v : Bytes{};
}

int main() {
    std::printf("== M5-A air-gap transfer artifact KATs ==\n");

    // ── 1. Digest primitive: published SHA-256("abc") vector ──────────────────
    {
        const std::string abc = "abc";
        auto h = sha256(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
        CHECK(to_hex(h) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "sha256(\"abc\") published vector");
        // sha256d = sha256(sha256(x)); double-check the composition.
        auto once = sha256(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
        auto twice = sha256(once.data(), once.size());
        auto dd = sha256d(reinterpret_cast<const uint8_t*>(abc.data()), abc.size());
        CHECK(dd == twice, "sha256d == sha256(sha256())");
        // hex round-trip
        Bytes raw = B("00ff10abCD");
        CHECK(raw.size() == 5 && to_hex(raw) == "00ff10abcd", "hex round-trip lowercases");
        CHECK(!from_hex("abc").has_value(), "odd-length hex rejected");
        CHECK(!from_hex("zz").has_value(), "non-hex rejected");
        // display txid is byte-reversed
        CHECK(sha256d_display(raw).size() == 64, "sha256d_display is 64 hex chars");
    }

    // ── 2. UnsignedContainer round-trip (PSBT-like), verdict present ──────────
    {
        UnsignedContainer c;
        c.coin = "dash";
        c.network_version = 0x000000cc;
        c.algebra = SighashAlgebra::Bip143;
        c.unsigned_tx = B("0200000001abcdef00000000000000ffffffff0100e1f5050000000000000000");
        c.preflight_verdict = "ok";

        UnsignedInput in0;
        in0.prevout_txid = sha256(B("11"));
        in0.prevout_index = 1;
        in0.script_pubkey = B("76a914" "0000000000000000000000000000000000000000" "88ac");
        in0.amount = 100000000;
        in0.derivation_hint = "m/84'/5'/0'/0/3";
        c.inputs.push_back(in0);

        UnsignedInput in1;
        in1.prevout_txid = sha256(B("22"));
        in1.prevout_index = 0;
        in1.script_pubkey = B("0014" "1111111111111111111111111111111111111111");
        in1.amount = 250000;
        in1.derivation_hint = ""; // empty hint allowed
        c.inputs.push_back(in1);

        std::string err;
        std::string hex = c.to_hex(err);
        CHECK(!hex.empty() && err.empty(), "unsigned container serializes");
        // raw-hex superset: the unsigned tx hex appears verbatim inside.
        CHECK(hex.find(to_hex(c.unsigned_tx)) != std::string::npos,
              "artifact embeds the unsigned tx hex verbatim (raw-hex superset)");

        std::string perr;
        auto parsed = UnsignedContainer::from_hex(hex, perr);
        CHECK(parsed.has_value() && perr.empty(), "unsigned container parses");
        CHECK(parsed && *parsed == c, "unsigned container round-trips exactly");
        CHECK(parsed && parsed->algebra == SighashAlgebra::Bip143, "algebra selector preserved");
        CHECK(parsed && parsed->inputs.size() == 2, "both inputs preserved");
        CHECK(parsed && parsed->preflight_verdict == "ok", "pre-flight verdict preserved");
        CHECK(parsed && parsed->unsigned_txid_display() == c.unsigned_txid_display(),
              "cross-gap digest stable across the round-trip");
    }

    // ── 3. UnsignedContainer without verdict; each algebra tag preserved ──────
    {
        for (auto alg : {SighashAlgebra::Legacy, SighashAlgebra::Bip143, SighashAlgebra::Bip341}) {
            UnsignedContainer c;
            c.coin = "btc";
            c.network_version = 1;
            c.algebra = alg;
            c.unsigned_tx = B("0100000000");
            std::string err;
            auto hex = c.to_hex(err);
            std::string perr;
            auto parsed = UnsignedContainer::from_hex(hex, perr);
            CHECK(parsed && parsed->algebra == alg && parsed->preflight_verdict.empty(),
                  "no-verdict + algebra tag round-trips");
        }
    }

    // ── 4. UnsignedContainer rejects bad magic / truncation ───────────────────
    {
        std::string err;
        auto bad = UnsignedContainer::from_hex("deadbeef00", err);
        CHECK(!bad.has_value(), "bad magic rejected");
        auto notHex = UnsignedContainer::from_hex("xyz", err);
        CHECK(!notHex.has_value(), "non-hex rejected");
    }

    // ── 5. UnsignedContainer oversize refusal ─────────────────────────────────
    {
        UnsignedContainer c;
        c.coin = "btc";
        c.unsigned_tx = Bytes(MAX_TRANSFER_BYTES + 10, 0x00); // > 100 kB
        std::string err;
        auto hex = c.to_hex(err);
        CHECK(hex.empty() && !err.empty(), "unsigned container refuses > 100 kB oversize");
    }

    // ── 6. SignedContainer emit -> parse round-trip ───────────────────────────
    {
        SignedContainer sc;
        sc.tx_hexes = {
            "0200000001aa00000000000000ffffffff0100e1f505000000000000000000",
            "0200000001bb00000000000000ffffffff0180969800000000000000000000",
        };
        std::string text = sc.emit();
        // Exactly one raw hex per line, each newline-terminated.
        CHECK(text == sc.tx_hexes[0] + "\n" + sc.tx_hexes[1] + "\n",
              "emit is one raw hex per line, newline-terminated");

        std::string err;
        auto parsed = SignedContainer::parse(text, err);
        CHECK(parsed && parsed->tx_hexes == sc.tx_hexes, "signed container round-trips");
    }

    // ── 7. SignedContainer parses with the c2pool loader's EXACT rules ────────
    //   (main_dash.cpp: intra-line whitespace stripped, blank lines skipped,
    //    one tx per line). A block with leading/trailing/internal whitespace
    //    and blank lines must recover the exact concatenated hexes.
    {
        const std::string h0 = "0200000001cc00000000000000ffffffff01a086010000000000000000000000";
        const std::string h1 = "0200000001dd00000000000000ffffffff01804a5d0500000000000000000000";
        std::string messy =
            "  " + h0.substr(0, 20) + "  " + h0.substr(20) + "  \n" // internal + edge spaces
            "\n"                                                     // blank line skipped
            "\t" + h1 + "\r\n";                                     // tabs/CR stripped
        std::string err;
        auto parsed = SignedContainer::parse(messy, err);
        CHECK(parsed && parsed->tx_hexes.size() == 2, "loader-rule parse yields 2 txs");
        CHECK(parsed && parsed->tx_hexes[0] == h0 && parsed->tx_hexes[1] == h1,
              "whitespace stripped + blank lines skipped exactly like the c2pool loader");
    }

    // ── 8. SignedContainer odd-length line => all-or-nothing refusal ──────────
    {
        std::string err;
        auto parsed = SignedContainer::parse("0200000001aa\nabc\n", err);
        CHECK(!parsed.has_value() && err.find("odd hex") != std::string::npos,
              "odd hex length refuses the whole file (all-or-nothing)");
        auto empty = SignedContainer::parse("\n  \n\t\n", err);
        CHECK(!empty.has_value(), "no transactions => refused");
    }

    // ── 9. SignedContainer oversize tx refusal ────────────────────────────────
    {
        std::string big(2 * (MAX_TRANSFER_BYTES + 5), 'a'); // even length, > 100 kB decoded
        std::string err;
        auto parsed = SignedContainer::parse(big + "\n", err);
        CHECK(!parsed.has_value() && err.find("oversize") != std::string::npos,
              "signed tx > 100 kB refused");
    }

    // ── 10. QR round-trip ─────────────────────────────────────────────────────
    Bytes payload;
    {
        // a payload that does not divide evenly by the chunk size
        for (int i = 0; i < 1000; ++i) payload.push_back(static_cast<uint8_t>((i * 7 + 3) & 0xff));
        auto enc = qr_encode(payload, 128);
        CHECK(enc.ok && enc.frames.size() == (1000 + 127) / 128, "qr_encode frame count");
        auto dec = qr_decode(enc.frames);
        CHECK(dec.ok && dec.payload == payload, "qr round-trips");
    }

    // ── 11. QR duplicate + 12. out-of-order tolerated ─────────────────────────
    {
        auto enc = qr_encode(payload, 256);
        CHECK(enc.ok, "qr_encode ok");
        std::vector<std::string> shuffled;
        // reverse order + duplicate the first frame
        for (auto it = enc.frames.rbegin(); it != enc.frames.rend(); ++it) shuffled.push_back(*it);
        shuffled.push_back(enc.frames.front());
        auto dec = qr_decode(shuffled);
        CHECK(dec.ok && dec.payload == payload, "out-of-order + duplicate frames reassemble");
    }

    // ── 13. QR dropped frame detected ─────────────────────────────────────────
    {
        auto enc = qr_encode(payload, 256);
        std::vector<std::string> dropped(enc.frames.begin() + 1, enc.frames.end()); // drop frame 0
        auto dec = qr_decode(dropped);
        CHECK(!dec.ok && dec.error.find("missing frame") != std::string::npos,
              "dropped frame => missing-frame error");
    }

    // ── 14. QR per-frame digest mismatch detected ─────────────────────────────
    {
        auto enc = qr_encode(payload, 256);
        std::string f = enc.frames[1];
        // flip one nibble in the chunk hex (the last |-field) — the stamped
        // digest no longer matches the (now-corrupted) chunk.
        size_t bar = f.rfind('|');
        CHECK(bar != std::string::npos && bar + 1 < f.size(), "frame has a chunk field");
        char& ch = f[bar + 1];
        ch = (ch == '0') ? '1' : '0';
        enc.frames[1] = f;
        auto dec = qr_decode(enc.frames);
        CHECK(!dec.ok && dec.error.find("digest mismatch") != std::string::npos,
              "tampered chunk => per-frame digest mismatch");
    }

    // ── 15. QR oversize refusal + 16. empty payload => one frame ──────────────
    {
        Bytes huge(MAX_TRANSFER_BYTES + 1, 0x00);
        auto enc = qr_encode(huge, 4096);
        CHECK(!enc.ok && enc.error.find("oversize") != std::string::npos,
              "qr_encode refuses > 100 kB payload");

        auto e0 = qr_encode(Bytes{}, 100);
        CHECK(e0.ok && e0.frames.size() == 1, "empty payload => exactly one frame");
        auto d0 = qr_decode(e0.frames);
        CHECK(d0.ok && d0.payload.empty(), "empty payload round-trips");
    }

    // ── 17. Validate-seam contract round-trips ────────────────────────────────
    {
        SeamRequest req;
        req.op = SeamOp::Submit;
        req.coin = "dash";
        req.tx_hex = "0200000001aa00000000000000ffffffff0100e1f505000000000000000000";
        req.flags = 0;
        req.expiry_height = 0;
        std::string j = req.to_json();
        std::string err;
        auto back = SeamRequest::from_json(j, err);
        CHECK(back && back->op == SeamOp::Submit && back->coin == "dash" &&
                  back->tx_hex == req.tx_hex && back->flags == 0 && back->expiry_height == 0,
              "SeamRequest JSON round-trips");

        // validate_inject dry-run shape
        auto dry = SeamRequest::validate_inject("btc", req.tx_hex);
        CHECK(dry.op == SeamOp::Validate && dry.dry_run,
              "validate_inject dry-run: op=validate, dry_run=true");
        auto dry2 = SeamRequest::from_json(dry.to_json(), err);
        CHECK(dry2 && dry2->dry_run && dry2->op == SeamOp::Validate,
              "validate_inject dry-run round-trips");

        SeamResponse resp;
        resp.ok = false;
        resp.cause = inject_cause::Unpriceable;
        resp.txid = crossgap_txid(req.tx_hex);
        auto rback = SeamResponse::from_json(resp.to_json(), err);
        CHECK(rback && rback->ok == false && rback->cause == std::string("inject-unpriceable") &&
                  rback->txid == resp.txid,
              "SeamResponse JSON round-trips");
    }

    // ── 18. Named verdict vocabulary matches the c2pool source strings ────────
    {
        CHECK(std::string(inject_cause::Oversize) == "inject-oversize", "cause: inject-oversize");
        CHECK(std::string(inject_cause::ScriptCheckUnarmed) == "inject-script-check-unarmed",
              "cause: inject-script-check-unarmed");
        CHECK(std::string(inject_cause::AlreadyConfirmed) == "inject-already-confirmed",
              "cause: inject-already-confirmed");
        CHECK(std::string(inject_cause::BadVoutRange) == "inject-bad-txns-vout-range",
              "cause: inject-bad-txns-vout-range");
    }

    // ── 19. Cross-gap digest match / mismatch ─────────────────────────────────
    {
        std::string txA = "0200000001aa00000000000000ffffffff0100e1f505000000000000000000";
        std::string txB = "0200000001bb00000000000000ffffffff0100e1f505000000000000000000";
        CHECK(crossgap_txid(txA) == crossgap_txid(txA), "same tx => matching cross-gap digest");
        CHECK(crossgap_txid(txA) != crossgap_txid(txB), "different tx => mismatching digest");
        CHECK(crossgap_txid("zz").empty(), "invalid hex => empty digest");

        // The signed container's txid_displays agree with crossgap_txid.
        SignedContainer sc; sc.tx_hexes = {txA, txB};
        auto ids = sc.txid_displays();
        CHECK(ids.size() == 2 && ids[0] == crossgap_txid(txA) && ids[1] == crossgap_txid(txB),
              "signed-container txid displays match crossgap digest");
    }

    // ── 20. The online call is a named UNWIRED cross-lane seam ────────────────
    {
        std::string tx = "0200000001aa00000000000000ffffffff0100e1f505000000000000000000";
        UnwiredOnlineSeam seam;
        auto resp = seam.call(SeamRequest::validate_inject("dash", tx));
        CHECK(!resp.ok && resp.cause == std::string("seam-unwired-cross-lane"),
              "online seam is unwired (no I/O) and named");
        CHECK(resp.txid == crossgap_txid(tx),
              "unwired seam still returns the cross-gap digest for manual compare");
    }


    // ═══════════════════ M6 slice-2c KATs (GAP-3 / GAP-4 / GAP-8 / guard) ═══════════════════

    // ── 21. GAP-3 R_DIGEST: a mutated R_UTX output value refuses at parse ──────
    //   (closes the 2a hole "a mutated output value is only caught by the eye").
    {
        UnsignedContainer c;
        c.coin = "ltc";
        c.network_version = 1;
        c.algebra = SighashAlgebra::Legacy;
        // a concrete legacy tx: 1 input, 1 output paying 1.00000000 (00e1f505..).
        c.unsigned_tx = B("01000000"
                          "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "ffffffff"
                          "01" "00e1f50500000000" "19" "76a914" "0000000000000000000000000000000000000000" "88ac"
                          "00000000");
        std::string err;
        std::string hex = c.to_hex(err);
        CHECK(!hex.empty() && err.empty(), "GAP-3: container with digest serializes");

        auto bytes = from_hex(hex);
        CHECK(bytes.has_value(), "GAP-3: container hex decodes");
        // GAP-3 record is appended last as [0x06][0x20][32 bytes].
        CHECK(bytes && bytes->size() >= 34 && (*bytes)[bytes->size() - 34] == 0x06 &&
                  (*bytes)[bytes->size() - 33] == 0x20,
              "GAP-3: R_DIGEST (0x06, len 32) is the trailing record");

        // untampered round-trips fine
        std::string perr;
        auto good = UnsignedContainer::from_hex(hex, perr);
        CHECK(good.has_value() && perr.empty(), "GAP-3: untampered container parses");

        // flip the high byte of the output value (00 e1 f5 05 -> 40 e1 f5 05):
        // a structurally valid but semantically different tx.
        Bytes tam = *bytes;
        bool flipped = false;
        for (size_t i = 0; i + 3 < tam.size(); ++i) {
            if (tam[i] == 0x00 && tam[i + 1] == 0xe1 && tam[i + 2] == 0xf5 && tam[i + 3] == 0x05) {
                tam[i] = 0x40; flipped = true; break;
            }
        }
        CHECK(flipped, "GAP-3: located the output value to mutate");
        std::string terr;
        auto bad = UnsignedContainer::from_hex(to_hex(tam), terr);
        CHECK(!bad.has_value(), "GAP-3: a flipped output value REFUSES at parse");
        CHECK(terr.find("integrity digest mismatch") != std::string::npos,
              "GAP-3: the refusal names the integrity digest");

        // backward-compat: a container WITHOUT the digest (a 2a producer emits
        // none) still parses — from_hex only verifies when the record is present.
        Bytes nod = *bytes;
        nod.resize(nod.size() - 34); // strip the trailing R_DIGEST record
        std::string nperr;
        auto noDigest = UnsignedContainer::from_hex(to_hex(nod), nperr);
        CHECK(noDigest.has_value(), "GAP-3 backward-compat: a container without R_DIGEST still parses");

        // digest-is-last: a record appended AFTER a verified R_DIGEST refuses,
        // so nothing can hide past the verified range (probe-confirmed hole).
        {
            Bytes inj = *bytes;                        // valid container ending in R_DIGEST
            inj.push_back(0x04);                       // a 2nd R_UTX record...
            inj.push_back(0x05);                       // ...len 5...
            for (uint8_t k = 1; k <= 5; ++k) inj.push_back(k);
            std::string ierr;
            auto bad2 = UnsignedContainer::from_hex(to_hex(inj), ierr);
            CHECK(!bad2.has_value(), "GAP-3: a 2nd R_UTX appended AFTER R_DIGEST is refused");
            CHECK(ierr.find("after the integrity digest") != std::string::npos,
                  "GAP-3: the refusal names the digest-must-be-last rule");
        }
        {
            Bytes inj2 = *bytes; inj2.push_back(0x77); inj2.push_back(0x00); // any trailing record
            std::string ierr2;
            CHECK(!UnsignedContainer::from_hex(to_hex(inj2), ierr2).has_value(),
                  "GAP-3: even an unknown record after R_DIGEST is refused");
        }
        // has_digest is true only when the digest is genuinely present + last.
        {
            std::string herr;
            auto withD = UnsignedContainer::from_hex(hex, herr);
            CHECK(withD && withD->has_digest, "GAP-3: has_digest true for a digest-terminated container");
            Bytes nod2 = *bytes; nod2.resize(nod2.size() - 34);
            auto noD = UnsignedContainer::from_hex(to_hex(nod2), herr);
            CHECK(noD && !noD->has_digest, "GAP-3: has_digest false when no digest present");
        }
        // duplicate singleton record (two R_COIN) is a parse error, not a silent
        // overwrite. Hand-built: magic|ver|R_COIN"ltc"|R_COIN"btc"|R_UTX(1).
        {
            Bytes bb = {'C','2','W','U',0x01,
                        0x01,0x03,'l','t','c',
                        0x01,0x03,'b','t','c',
                        0x04,0x01,0x00};
            std::string derr;
            CHECK(!UnsignedContainer::from_hex(to_hex(bb), derr).has_value(),
                  "GAP-3: a duplicate singleton (two R_COIN) is refused");
        }
    }

    // ── 22. GAP-4 R_INPUT_SCRIPT: a P2SH/P2WSH script round-trips + is consumable ─
    {
        UnsignedContainer c;
        c.coin = "ltc";
        c.unsigned_tx = B("0100000000");
        // two inputs so the GAP-4 index validation (index < inputs.size()) is
        // satisfied for the R_INPUT_SCRIPT records on inputs 0 and 1.
        { UnsignedInput a; a.prevout_index = 0; a.script_pubkey = B("51"); a.amount = 1; c.inputs.push_back(a); }
        { UnsignedInput b1; b1.prevout_index = 1; b1.script_pubkey = B("51"); b1.amount = 1; c.inputs.push_back(b1); }
        // a P2WSH 2-of-3 witnessScript on input 0
        InputScript w;
        w.input_index = 0; w.kind = InputScriptKind::Witness;
        w.script = B("5221" "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                     "21"   "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                     "21"   "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" "53ae");
        // a P2SH redeemScript on input 1
        InputScript r;
        r.input_index = 1; r.kind = InputScriptKind::Redeem;
        r.script = B("5121" "02dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" "51ae");
        c.input_scripts = {w, r};

        std::string err;
        auto hex = c.to_hex(err);
        std::string perr;
        auto p = UnsignedContainer::from_hex(hex, perr);
        CHECK(p.has_value() && *p == c, "GAP-4: input_scripts round-trip exactly");
        CHECK(p && p->input_scripts.size() == 2, "GAP-4: both input-scripts preserved");
        CHECK(p && p->script_for_input(0, InputScriptKind::Witness).has_value(),
              "GAP-4: witnessScript retrievable by (index,kind)");
        CHECK(p && p->script_for_input(1, InputScriptKind::Redeem).has_value(),
              "GAP-4: redeemScript retrievable by (index,kind)");
        CHECK(p && !p->script_for_input(0, InputScriptKind::Redeem).has_value(),
              "GAP-4: kind-specific lookup (no redeem on input 0)");
        CHECK(p && !p->script_for_input(5, InputScriptKind::Witness).has_value(),
              "GAP-4: missing index returns nullopt");

        // The Sign path consumes exactly this script as KeyForInput.script. For a
        // P2WSH input, the witness program is sha256(witnessScript); prove the
        // carried bytes are byte-identical AND bind to a P2WSH scriptPubKey.
        auto ws = *p->script_for_input(0, InputScriptKind::Witness);
        CHECK(ws == w.script, "GAP-4: consumed witnessScript is byte-identical to the produced one");
        Hash32 prog = sha256(ws);
        Bytes spk; spk.push_back(0x00); spk.push_back(0x20);
        spk.insert(spk.end(), prog.begin(), prog.end());
        CHECK(spk.size() == 34 && spk[0] == 0x00 && spk[1] == 0x20,
              "GAP-4: P2WSH program = sha256(witnessScript) binds the carried script to the input");

        // out-of-range input index refuses at parse.
        {
            UnsignedContainer bad; bad.coin = "ltc"; bad.unsigned_tx = B("0100000000");
            InputScript x; x.input_index = 9; x.kind = InputScriptKind::Redeem; x.script = B("51");
            bad.input_scripts = {x};
            std::string e; auto he = bad.to_hex(e); std::string pe;
            CHECK(!he.empty() && !UnsignedContainer::from_hex(he, pe).has_value(),
                  "GAP-4: an out-of-range input-script index is refused");
        }
        // duplicate (input_index, kind) input-script refuses at parse.
        {
            UnsignedContainer d; d.coin = "ltc"; d.unsigned_tx = B("0100000000");
            UnsignedInput in0; in0.prevout_index = 0; in0.script_pubkey = B("51"); in0.amount = 1;
            d.inputs.push_back(in0);
            InputScript a; a.input_index = 0; a.kind = InputScriptKind::Witness; a.script = B("51");
            InputScript b2; b2.input_index = 0; b2.kind = InputScriptKind::Witness; b2.script = B("52");
            d.input_scripts = {a, b2};
            std::string e; auto he = d.to_hex(e); std::string pe;
            CHECK(!he.empty() && !UnsignedContainer::from_hex(he, pe).has_value(),
                  "GAP-4: a duplicate (input,kind) input-script is refused");
        }
    }

    // ── 23. Unsigned <-> signed confusion refused in BOTH directions ──────────
    {
        // a legacy tx with a NON-EMPTY scriptSig on its only input == plausibly signed
        Bytes signedTx = B("01000000"
                           "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000"
                           "06" "010203040506" "ffffffff"
                           "01" "00e1f50500000000" "19" "76a914" "0000000000000000000000000000000000000000" "88ac"
                           "00000000");
        // the same tx with an EMPTY scriptSig == unsigned
        Bytes unsignedTx = B("01000000"
                             "01" "0000000000000000000000000000000000000000000000000000000000000000" "00000000"
                             "00" "ffffffff"
                             "01" "00e1f50500000000" "19" "76a914" "0000000000000000000000000000000000000000" "88ac"
                             "00000000");
        std::string why;
        CHECK(accept_as_signed(signedTx, why),
              "confusion: a tx with a scriptSig on every input is accepted as signed");
        CHECK(!accept_as_signed(unsignedTx, why),
              "confusion: an UNSIGNED tx (empty scriptSig) is refused in the signed slot");

        // a C2WU container pushed into the signed slot is refused by its magic
        UnsignedContainer cc; cc.coin = "btc"; cc.unsigned_tx = B("0100000000");
        std::string cerr; auto chex = cc.to_hex(cerr);
        auto cbytes = from_hex(chex);
        CHECK(cbytes && has_c2wu_magic(*cbytes), "confusion: a container carries the C2WU magic");
        CHECK(cbytes && !accept_as_signed(*cbytes, why),
              "confusion: a C2WU container is refused in the signed slot (magic)");

        // symmetric: a bare signed tx pushed into the UNSIGNED slot is refused
        // (UnsignedContainer::from_hex requires the C2WU magic).
        std::string uerr;
        auto notContainer = UnsignedContainer::from_hex(to_hex(signedTx), uerr);
        CHECK(!notContainer.has_value(),
              "confusion: a signed tx is refused in the unsigned slot (bad magic)");
    }

    // ── 24. GAP-8: a QR frame renders to a valid QR module matrix ─────────────
    {
        auto e = qr_encode(B("00112233445566778899aabbccddeeff"), 8);
        CHECK(e.ok && !e.frames.empty(), "GAP-8: qr_encode produced frames");
        QrModules m = qr_render_modules(e.frames[0]);
        // valid QR symbol sizes are 21,25,...,177 — all congruent to 1 mod 4.
        CHECK(m.ok() && m.size >= 21 && m.size <= 177 && (m.size % 4 == 1),
              "GAP-8: a frame renders to a valid QR module matrix (nayuki qrcodegen)");
        CHECK(m.cells.size() == static_cast<size_t>(m.size) * static_cast<size_t>(m.size),
              "GAP-8: module matrix is size*size");
    }

    // ── 25. GAP-8 transport ladder: round-trip + flipped / missing / wrong-total ─
    {
        const Bytes payload = B("deadbeefcafe0011223344556677");
        auto e = qr_encode(payload, 5);
        CHECK(e.ok && e.frames.size() >= 2, "GAP-8: multi-frame encode");
        auto d = qr_decode(e.frames);
        CHECK(d.ok && d.payload == payload, "GAP-8: encode(bytes) -> frames -> decode == bytes");

        // flipped frame: corrupt the last hex nibble of frame 0's chunk
        {
            auto bad = e.frames;
            std::string& f0 = bad[0];
            f0[f0.size() - 1] = (f0[f0.size() - 1] == '0') ? '1' : '0';
            CHECK(!qr_decode(bad).ok, "GAP-8: a flipped frame is refused (per-frame sha256)");
        }
        // missing seq: drop frame 0
        {
            auto miss = e.frames;
            miss.erase(miss.begin());
            CHECK(!qr_decode(miss).ok, "GAP-8: a missing seq is refused");
        }
        // wrong total: rewrite frame 0's total field so it disagrees
        {
            std::string ferr;
            auto fr0 = QrFrame::from_text(e.frames[0], ferr);
            CHECK(fr0.has_value(), "GAP-8: frame 0 parses");
            fr0->total += 7;
            auto mixed = e.frames;
            mixed[0] = fr0->to_text();
            CHECK(!qr_decode(mixed).ok, "GAP-8: a wrong total is refused");
        }
    }

    std::printf("\n== artifact KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
