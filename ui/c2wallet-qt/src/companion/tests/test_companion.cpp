// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the c2wallet-qt COMPANION (online, key-free) — Family-A leg (design
// docs/design/c2wallet-qt.md §5.2 companion + §5.4 validate seam). The
// companion MARSHALS public artifacts and talks to the node; it holds NO keys.
// These tests prove:
//   * the legacy unsigned-tx serializer emits the documented byte format;
//   * produce_unsigned() builds the M5-A UnsignedContainer from funding data
//     and round-trips through to_hex/from_hex;
//   * FundingData::from_json parses the JSON/CLI intake (display->internal txid);
//   * the produce -> (offline sign) -> consume -> FILE-EMIT round-trip emits
//     EXACTLY the --pin-local-tx-hex / --embedded-tx-inject-hex bytes the
//     c2pool loader consumes (byte-format assert), and re-parses loader-exactly;
//   * the validate_inject dry-run request/response JSON round-trips and the
//     digest cross-check matches / mismatches correctly, with the online node
//     left as a named transport seam;
//   * QR reassembly of a signed artifact round-trips (incl. out-of-order +
//     duplicate frames) and detects a dropped frame.

#include "../FundingData.hpp"
#include "../Produce.hpp"
#include "../Submit.hpp"
#include "../ValidateClient.hpp"
#include "../QrReassembly.hpp"
#include "../MoneroSeam.hpp"

#include "Digest.hpp"
#include "QrTransport.hpp"
#include "TransferContainer.hpp"
#include "ValidateSeam.hpp"

#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace c2w::companion;
namespace art = c2w::artifact;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                                                 \
    do {                                                                                 \
        if (cond) { ++g_pass; }                                                          \
        else { ++g_fail; std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); }\
    } while (0)

static art::Bytes B(const std::string& hex) {
    auto v = art::from_hex(hex);
    return v ? *v : art::Bytes{};
}

// A small, fully-specified funding fixture (1 input, 1 P2PKH output).
static FundingData fixture_fd() {
    FundingData fd;
    fd.coin            = "btc";
    fd.network_version = 0;
    fd.algebra         = art::SighashAlgebra::Bip143;
    fd.tx_version      = 2;
    fd.locktime        = 0;
    fd.preflight_verdict = "ok";

    FundingInput in;
    in.prevout_txid.fill(0xaa);          // internal byte order
    in.prevout_index = 1;
    in.script_pubkey = B("76a914" "0000000000000000000000000000000000000000" "88ac");
    in.amount        = 200000;
    in.derivation_hint = "m/84'/0'/0'/0/0";
    in.sequence      = 0xffffffffu;
    fd.inputs.push_back(in);

    TargetOutput o;
    o.value        = 100000; // 0x186A0
    o.script_pubkey = B("76a914" "0000000000000000000000000000000000000000" "88ac");
    fd.outputs.push_back(o);
    return fd;
}

// A mock node transport returning a caller-chosen response (for the digest
// cross-check tests). Performs NO real I/O — it is a test double for the
// cross-lane node endpoint.
struct MockTransport : NodeTransport {
    art::SeamResponse canned;
    bool             ok_transport = true;
    bool send(const std::string& /*req*/, std::string& resp, std::string& err) override {
        if (!ok_transport) { err = "mock-down"; return false; }
        resp = canned.to_json();
        return true;
    }
    const char* name() const override { return "mock"; }
};

int main() {
    std::printf("== c2wallet-qt companion (online, key-free) KATs ==\n");

    // ── 1. Unsigned-tx serializer byte-format ─────────────────────────────────
    {
        FundingData fd = fixture_fd();
        std::string got = art::to_hex(serialize_unsigned_tx(fd));
        // Documented wire encoding, field by field:
        std::string exp;
        exp += "02000000";                                         // int32 version LE
        exp += "01";                                               // varint vin count
        exp += std::string(64, 'a');                               // 32-byte prevout txid (0xaa)
        exp += "01000000";                                         // vout u32 LE
        exp += "00";                                               // empty scriptSig varint
        exp += "ffffffff";                                         // sequence
        exp += "01";                                               // varint vout count
        exp += "a086010000000000";                                 // int64 value LE (100000)
        exp += "19";                                               // varint scriptlen (25)
        exp += "76a914" "0000000000000000000000000000000000000000" "88ac"; // P2PKH spk
        exp += "00000000";                                         // locktime
        CHECK(got == exp, "serialize_unsigned_tx matches documented byte format");
    }

    // ── 2. produce_unsigned builds the M5-A container + to_hex round-trip ─────
    {
        FundingData fd = fixture_fd();
        std::string err;
        auto c = produce_unsigned(fd, err);
        CHECK(c.has_value(), "produce_unsigned succeeds");
        if (c) {
            CHECK(c->coin == "btc", "container coin preserved");
            CHECK(c->algebra == art::SighashAlgebra::Bip143, "container algebra preserved");
            CHECK(c->preflight_verdict == "ok", "container preflight preserved");
            CHECK(c->inputs.size() == 1, "one input mapped");
            CHECK(c->inputs[0].prevout_index == 1, "input vout mapped");
            CHECK(c->inputs[0].amount == 200000, "input amount mapped");
            CHECK(c->inputs[0].derivation_hint == "m/84'/0'/0'/0/0", "input derivation mapped");
            CHECK(c->unsigned_tx == serialize_unsigned_tx(fd), "container carries the unsigned tx");

            std::string herr;
            std::string hex = c->to_hex(herr);
            CHECK(!hex.empty(), "to_hex produced artifact");
            auto rt = art::UnsignedContainer::from_hex(hex, herr);
            CHECK(rt.has_value() && *rt == *c, "UnsignedContainer to_hex/from_hex round-trip");
        }

        // empty-inputs / empty-outputs refusals
        FundingData bad = fixture_fd(); bad.inputs.clear();
        auto n1 = produce_unsigned(bad, err);
        CHECK(!n1.has_value(), "produce refuses empty inputs");
        bad = fixture_fd(); bad.outputs.clear();
        auto n2 = produce_unsigned(bad, err);
        CHECK(!n2.has_value(), "produce refuses empty outputs");
    }

    // ── 3. FundingData::from_json (JSON/CLI intake; display->internal txid) ───
    {
        // txid given in DISPLAY (byte-reversed) order = "00 01 02 ... 1f".
        std::string disp = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        std::string clean_spk = "76a914" "0000000000000000000000000000000000000000" "88ac";
        std::string json =
            std::string("{ \"coin\":\"dash\", \"network_version\":204, \"algebra\":\"legacy\",")
            + " \"tx_version\":2, \"locktime\":0, \"preflight_verdict\":\"ok\","
            + " \"inputs\":[ {\"txid\":\"" + disp + "\", \"vout\":3,"
            + "  \"script_pubkey\":\"" + clean_spk + "\", \"amount\":500000,"
            + "  \"derivation\":\"m/44'/5'/0'/0/2\", \"sequence\":4294967295 } ],"
            + " \"outputs\":[ {\"amount\":499000, \"script_pubkey\":\"6a04deadbeef\"} ] }";

        std::string err;
        auto fd = FundingData::from_json(json, err);
        CHECK(fd.has_value(), "from_json parses funding document");
        if (fd) {
            CHECK(fd->coin == "dash", "json coin");
            CHECK(fd->network_version == 204, "json network_version");
            CHECK(fd->algebra == art::SighashAlgebra::Legacy, "json algebra=legacy");
            CHECK(fd->inputs.size() == 1 && fd->outputs.size() == 1, "json input/output counts");
            // display "00 01 .. 1f" reversed -> internal "1f 1e .. 00"
            CHECK(fd->inputs[0].prevout_txid[0] == 0x1f &&
                  fd->inputs[0].prevout_txid[31] == 0x00, "json txid display->internal reversal");
            CHECK(fd->inputs[0].prevout_index == 3, "json vout");
            CHECK(fd->inputs[0].amount == 500000, "json input amount");
            CHECK(fd->inputs[0].derivation_hint == "m/44'/5'/0'/0/2", "json derivation");
            CHECK(fd->outputs[0].value == 499000, "json output amount");
            CHECK(fd->outputs[0].script_pubkey == B("6a04deadbeef"), "json output spk");

            std::string perr;
            auto c = produce_unsigned(*fd, perr);
            CHECK(c.has_value(), "produce from JSON-parsed funding data");
        }

        // malformed: missing inputs
        std::string e2;
        auto bad = FundingData::from_json("{\"coin\":\"btc\",\"outputs\":[]}", e2);
        CHECK(!bad.has_value(), "from_json refuses missing inputs");
    }

    // ── 4. Signed artifact: emit == the c2pool loader file bytes (byte-format) ─
    {
        // In a real flow these are the SIGNED tx hexes from the offline signer.
        // The loader (and SignedContainer::parse) do not parse structure here —
        // they enforce the FILE format: one raw hex per line, whitespace-strip,
        // skip-blank, odd-length whole-file refusal. Two even-length hexes:
        std::string hexA = art::to_hex(serialize_unsigned_tx(fixture_fd()));
        std::string hexB = "0100000001" "00" "0000"; // arbitrary even-length hex
        art::SignedContainer sc;
        sc.tx_hexes = { hexA, hexB };

        std::string emitted = sc.emit();
        CHECK(emitted == hexA + "\n" + hexB + "\n",
              "SignedContainer.emit() = one raw hex per line, '\\n'-terminated");

        // write the --pin-local-tx-hex file and read the exact bytes back
        std::string path = "/tmp/c2w_companion_pin_local.hex";
        std::string werr;
        bool wrote = write_pin_local_tx_file(path, sc, werr);
        CHECK(wrote, "write_pin_local_tx_file succeeds");

        std::ifstream f(path, std::ios::binary);
        std::stringstream ss; ss << f.rdbuf();
        std::string on_disk = ss.str();
        CHECK(on_disk == emitted, "on-disk file bytes == emit() (exact loader format)");

        // re-parse the file loader-exactly
        std::string perr;
        auto rp = parse_signed_artifact(on_disk, perr);
        CHECK(rp.has_value() && rp->tx_hexes == sc.tx_hexes,
              "file re-parses to the same tx list (loader-exact)");

        // loader rule: intra-line whitespace stripped, blank lines skipped
        std::string messy = "  " + hexA.substr(0, 6) + "  " + hexA.substr(6) + " \n\n" + hexB + "\n";
        auto rp2 = parse_signed_artifact(messy, perr);
        CHECK(rp2.has_value() && rp2->tx_hexes.size() == 2 &&
              rp2->tx_hexes[0] == hexA && rp2->tx_hexes[1] == hexB,
              "whitespace-strip + skip-blank matches the loader");

        // loader rule: odd hex length => whole-file refusal
        auto rp3 = parse_signed_artifact("abc\n", perr);
        CHECK(!rp3.has_value(), "odd-length line refused (all-or-nothing)");

        // txid cross-gap digest agrees with the seam's crossgap_txid
        auto tds = sc.txid_displays();
        CHECK(tds.size() == 2 && tds[0] == art::crossgap_txid(hexA),
              "txid_displays == crossgap_txid");
    }

    // ── 5. Full produce -> consume -> file round-trip (single tx) ─────────────
    {
        FundingData fd = fixture_fd();
        std::string err;
        std::string unsigned_hex = produce_unsigned_hex(fd, err);
        CHECK(!unsigned_hex.empty(), "produce_unsigned_hex (online -> offline)");

        // offline signer would sign; simulate the returned SIGNED artifact:
        std::string signed_hex = art::to_hex(serialize_unsigned_tx(fd));
        std::string signed_text = signed_hex + "\n"; // the artifact that crosses back

        auto sc = parse_signed_artifact(signed_text, err);
        CHECK(sc.has_value(), "consume signed artifact (offline -> online)");
        std::string path = "/tmp/c2w_companion_roundtrip.hex";
        bool wrote = sc && write_pin_local_tx_file(path, *sc, err);
        CHECK(wrote, "round-trip emits the node's --pin-local-tx-hex file");
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss; ss << f.rdbuf();
        CHECK(ss.str() == signed_hex + "\n", "round-trip file bytes exact");
    }

    // ── 6. validate_inject dry-run: JSON round-trip + digest cross-check ──────
    {
        std::string tx_hex = art::to_hex(serialize_unsigned_tx(fixture_fd()));

        // request round-trip
        auto req = art::SeamRequest::validate_inject("btc", tx_hex);
        CHECK(req.op == art::SeamOp::Validate && req.dry_run, "validate_inject shape");
        std::string rerr;
        auto req2 = art::SeamRequest::from_json(req.to_json(), rerr);
        CHECK(req2.has_value() && req2->coin == "btc" && req2->tx_hex == tx_hex &&
              req2->dry_run && req2->op == art::SeamOp::Validate,
              "SeamRequest to_json/from_json round-trip");

        // response round-trip
        art::SeamResponse resp;
        resp.ok = true; resp.cause = art::inject_cause::Ok; resp.txid = art::crossgap_txid(tx_hex);
        auto resp2 = art::SeamResponse::from_json(resp.to_json(), rerr);
        CHECK(resp2.has_value() && resp2->ok && resp2->cause == "ok" && resp2->txid == resp.txid,
              "SeamResponse to_json/from_json round-trip");

        // default unwired transport: no I/O, named cause, digest echoed => MATCH
        {
            ValidateInjectClient client(std::make_shared<UnwiredTransport>());
            auto r = client.validate_dry_run("btc", tx_hex);
            CHECK(r.transport_ok, "unwired transport returns a response doc");
            CHECK(r.response && r.response->cause == art::UnwiredOnlineSeam::kUnwiredCause,
                  "unwired cause = seam-unwired-cross-lane");
            CHECK(r.response && !r.response->ok, "unwired response not ok (no admit)");
            CHECK(r.local_txid == art::crossgap_txid(tx_hex), "local cross-gap digest computed");
            CHECK(r.digest_match, "unwired echoes cross-gap digest => MATCH");
        }

        // mock node accepts with matching digest => MATCH
        {
            auto mt = std::make_shared<MockTransport>();
            mt->canned.ok = true; mt->canned.cause = art::inject_cause::Ok;
            mt->canned.txid = art::crossgap_txid(tx_hex);
            ValidateInjectClient client(mt);
            auto r = client.validate_dry_run("btc", tx_hex);
            CHECK(r.transport_ok && r.digest_match && r.response->ok, "node accept + digest MATCH");
        }

        // mock node returns a WRONG digest => MISMATCH surfaced
        {
            auto mt = std::make_shared<MockTransport>();
            mt->canned.ok = true; mt->canned.cause = art::inject_cause::Ok;
            mt->canned.txid = std::string(64, '0');
            ValidateInjectClient client(mt);
            auto r = client.validate_dry_run("btc", tx_hex);
            CHECK(r.transport_ok && !r.digest_match, "wrong node digest => MISMATCH");
        }

        // loopback HTTP transport is DISARMED by default (money-path discipline)
        {
            ValidateInjectClient client(std::make_shared<LoopbackHttpTransport>());
            auto r = client.validate_dry_run("btc", tx_hex);
            CHECK(!r.transport_ok && r.error == "loopback-http-disarmed",
                  "loopback HTTP seam disarmed by default");
            CHECK(r.local_txid == art::crossgap_txid(tx_hex),
                  "local digest still computed when transport unwired");
        }
    }

    // ── 7. QR reassembly of a signed artifact (online side) ───────────────────
    {
        std::string hexA = art::to_hex(serialize_unsigned_tx(fixture_fd()));
        art::SignedContainer sc; sc.tx_hexes = { hexA };
        std::string signed_text = sc.emit();

        art::Bytes payload(signed_text.begin(), signed_text.end());
        auto enc = art::qr_encode(payload, 8); // small chunks => several frames
        CHECK(enc.ok && enc.frames.size() > 1, "signed artifact chunked into QR frames");

        std::string err;
        auto re = reassemble_signed_from_qr(enc.frames, err);
        CHECK(re.has_value() && re->tx_hexes == sc.tx_hexes, "QR reassembly round-trip");

        // out-of-order + duplicate frames still reassemble
        std::vector<std::string> shuffled(enc.frames.rbegin(), enc.frames.rend());
        shuffled.push_back(enc.frames.front()); // duplicate
        auto re2 = reassemble_signed_from_qr(shuffled, err);
        CHECK(re2.has_value() && re2->tx_hexes == sc.tx_hexes,
              "out-of-order + duplicate frames reassemble");

        // a dropped frame is detected
        std::vector<std::string> dropped(enc.frames.begin() + 1, enc.frames.end());
        auto re3 = reassemble_signed_from_qr(dropped, err);
        CHECK(!re3.has_value(), "dropped QR frame detected (no silent loss)");

        // produce-leg helper: unsigned hex -> frames -> decode round-trips
        std::string uerr;
        std::string unsigned_hex = produce_unsigned_hex(fixture_fd(), uerr);
        auto frames = frames_for_unsigned_hex(unsigned_hex, 16, uerr);
        CHECK(frames.has_value(), "frames_for_unsigned_hex produces frames");
        if (frames) {
            auto dec = art::qr_decode(*frames);
            std::string back(dec.payload.begin(), dec.payload.end());
            CHECK(dec.ok && back == unsigned_hex, "unsigned-hex QR round-trip");
        }
    }

    // ── 8. Monero online leg is a clearly-named cross-lane seam ───────────────
    {
        CHECK(std::string(monero::scan_feed_seam()) == "xmr-companion-v37-cross-lane",
              "Monero scan feed is a named cross-lane seam");
        CHECK(std::string(monero::relay_seam()) == monero::kSeamName,
              "Monero relay is a named cross-lane seam");
    }

    std::printf("\n== companion KATs: %d passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
