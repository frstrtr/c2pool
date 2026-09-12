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

    std::printf("\n== artifact KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
