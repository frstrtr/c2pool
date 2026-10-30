// SPDX-License-Identifier: AGPL-3.0-or-later
#include "InjectManifest.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "InjectCaps.hpp"
#include "SweepTx.hpp"
#include "UtxoIntake.hpp"

#include "../hdkeys/HexUtil.hpp"

#include <crypto/sha256.h> // vendored btclibs CSHA256 (design §2.4 reuse)

#include <algorithm>
#include <utility>

namespace c2w::dash {

namespace {

// A tiny ordered JSON value, written out deterministically. Only what the
// manifest needs: null, bool, integers, strings, arrays, objects.
struct J {
    enum class K { Null, Bool, Int, Str, Arr, Obj } k = K::Null;
    bool b = false;
    int64_t i = 0;
    std::string s;
    std::vector<J> a;
    std::vector<std::pair<std::string, J>> o;

    static J null() { return J{}; }
    static J boolean(bool v) { J j; j.k = K::Bool; j.b = v; return j; }
    static J integer(int64_t v) { J j; j.k = K::Int; j.i = v; return j; }
    static J str(std::string v) { J j; j.k = K::Str; j.s = std::move(v); return j; }
    static J arr() { J j; j.k = K::Arr; return j; }
    static J obj() { J j; j.k = K::Obj; return j; }
    J& put(const std::string& key, J v) { o.emplace_back(key, std::move(v)); return *this; }
    J& push(J v) { a.push_back(std::move(v)); return *this; }
};

J str_or_null(const std::string& v) { return v.empty() ? J::null() : J::str(v); }
J int_or_null(int64_t v) { return v == 0 ? J::null() : J::integer(v); }

void write_str(std::string& out, const std::string& v)
{
    static const char* hex = "0123456789abcdef";
    out += '"';
    for (unsigned char c : v) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                out += "\\u00";
                out += hex[c >> 4];
                out += hex[c & 15];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    out += '"';
}

void write(std::string& out, const J& j, int depth)
{
    const std::string pad(static_cast<size_t>(depth + 1) * 2, ' ');
    const std::string end_pad(static_cast<size_t>(depth) * 2, ' ');
    switch (j.k) {
    case J::K::Null: out += "null"; return;
    case J::K::Bool: out += j.b ? "true" : "false"; return;
    case J::K::Int: out += std::to_string(j.i); return;
    case J::K::Str: write_str(out, j.s); return;
    case J::K::Arr:
        if (j.a.empty()) { out += "[]"; return; }
        out += "[\n";
        for (size_t n = 0; n < j.a.size(); ++n) {
            out += pad;
            write(out, j.a[n], depth + 1);
            out += n + 1 < j.a.size() ? ",\n" : "\n";
        }
        out += end_pad + "]";
        return;
    case J::K::Obj:
        if (j.o.empty()) { out += "{}"; return; }
        out += "{\n";
        for (size_t n = 0; n < j.o.size(); ++n) {
            out += pad;
            write_str(out, j.o[n].first);
            out += ": ";
            write(out, j.o[n].second, depth + 1);
            out += n + 1 < j.o.size() ? ",\n" : "\n";
        }
        out += end_pad + "}";
        return;
    }
}

// One input in the runtime-submit prevout-claim shape (RUNTIME-INJECT-DESIGN
// §5.2): {txid, vout, value, script_hex, height, coinbase}. An unknown coinbase
// flag is claimed `true`: the builder held the input to the coinbase rule.
J utxo_json(const Utxo& u)
{
    J j = J::obj();
    j.put("txid", J::str(u.txid));
    j.put("vout", J::integer(u.vout));
    j.put("value", J::integer(u.satoshis));
    j.put("script_hex", J::str(u.script_pubkey_hex));
    j.put("height", int_or_null(u.height));
    j.put("coinbase", J::boolean(u.coinbase.value_or(true)));
    return j;
}

std::string digest_hex(const uint8_t* h, bool reversed)
{
    std::vector<uint8_t> v(h, h + 32);
    if (reversed) std::reverse(v.begin(), v.end());
    return hdkeys::to_hex(v);
}

} // namespace

std::string sha256_hex(const std::string& bytes)
{
    uint8_t h[32];
    CSHA256().Write(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()).Finalize(h);
    return digest_hex(h, false);
}

std::string sha256d_display_hex(const std::string& bytes)
{
    uint8_t h1[32], h2[32];
    CSHA256().Write(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()).Finalize(h1);
    CSHA256().Write(h1, 32).Finalize(h2);
    return digest_hex(h2, true);
}

std::string build_inject_manifest(const ManifestData& d)
{
    if (d.txs.empty()) throw DashAbort("manifest: no signed transaction");
    if (d.hex_file.empty()) throw DashAbort("manifest: empty hex file");
    const bool relay = d.fee_mode == FeeMode::Relay;

    J root = J::obj();
    root.put("schema", J::str(kInjectManifestSchema));
    root.put("coin", J::str("dash"));
    root.put("network", J::str(d.testnet ? "testnet" : "mainnet"));
    root.put("mode", J::str(d.mode));
    root.put("fee_mode", J::str(relay ? "relay" : "inject-zero-fee"));
    root.put("fee_rate_duffs_per_byte", J::integer(relay ? d.fee_rate_per_byte : 0));
    root.put("funding_address", J::str(d.funding_address));
    {
        const std::array<uint8_t, 25> spk = p2pkh_script(addr_to_h160(d.funding_address, d.testnet));
        root.put("funding_script", J::str(hdkeys::to_hex(std::vector<uint8_t>(spk.begin(), spk.end()))));
    }
    root.put("destination", J::str(d.destination));
    root.put("gov_hash", str_or_null(d.gov_hash));
    root.put("hex_file_sha256", J::str(sha256_hex(d.hex_file)));
    root.put("hex_file_sha256d", J::str(sha256d_display_hex(d.hex_file)));
    root.put("tx_count", J::integer(static_cast<int64_t>(d.txs.size())));

    int64_t total_fee = 0, total_out = 0;
    J txs = J::arr();
    for (const ManifestTx& t : d.txs) {
        total_fee += t.fee;
        total_out += t.value_out;
        J tx = J::obj();
        tx.put("txid", J::str(t.txid));
        tx.put("size", J::integer(static_cast<int64_t>(t.size)));
        tx.put("est_signed_bytes", J::integer(static_cast<int64_t>(t.est_signed_bytes)));
        tx.put("vin", J::integer(static_cast<int64_t>(t.inputs.size())));
        tx.put("vout", J::integer(static_cast<int64_t>(t.outputs.size())));
        tx.put("value_out", J::integer(t.value_out));
        tx.put("fee", J::integer(t.fee));
        J outs = J::arr();
        for (const ManifestOutput& o : t.outputs) {
            J oj = J::obj();
            oj.put("value", J::integer(o.value));
            oj.put("kind", J::str(o.kind));
            oj.put("address", str_or_null(o.address));
            oj.put("script", J::str(o.script_hex));
            outs.push(std::move(oj));
        }
        tx.put("outputs", std::move(outs));
        J ins = J::arr();
        for (const Utxo& u : t.inputs) ins.push(utxo_json(u));
        tx.put("inputs", std::move(ins));
        txs.push(std::move(tx));
    }
    root.put("txs", std::move(txs));
    root.put("total_value_out", J::integer(total_out));
    root.put("total_fee", J::integer(total_fee));

    J mat = J::obj();
    mat.put("intake", J::str(d.intake_source));
    mat.put("coinbase_flags_known", J::boolean(d.coinbase_flags_known));
    mat.put("screen_tip_height", int_or_null(d.screen_tip_height));
    mat.put("screen_tip_hash", str_or_null(d.screen_tip_hash));
    mat.put("target_height", J::integer(d.target_height));
    mat.put("min_confirmations", J::integer(d.min_confirmations));
    mat.put("youngest_input_height", int_or_null(d.youngest_input_height));
    mat.put("safe_from_height", int_or_null(d.safe_from_height));
    root.put("maturity", std::move(mat));

    J skipped = J::obj();
    J imm = J::arr();
    for (const Utxo& u : d.immature) {
        J uj = utxo_json(u);
        uj.put("matures_in",
               J::integer(std::max<int64_t>(0, confirmations_needed(u, d.min_confirmations) -
                                                   u.confirmations)));
        imm.push(std::move(uj));
    }
    skipped.put("immature", std::move(imm));
    skipped.put("dust", J::integer(static_cast<int64_t>(d.dust_count)));
    skipped.put("dust_floor", J::integer(d.dust_floor));
    skipped.put("not_selected", J::integer(static_cast<int64_t>(d.not_selected)));
    root.put("skipped", std::move(skipped));

    J node = J::obj();
    if (relay) {
        node.put("lane", J::str("relay"));
        // Legacy sighash commits no input amounts: the export's amounts are the
        // trust root, and on this lane an understated one is paid as extra fee.
        node.put("submit", J::str("ONLY after the preflight below passes on the online host: "
                                  "dash-cli sendrawtransaction <each line of the .hex file>"));
        node.put("preflight",
                 J::str("for every input of every tx: dash-cli gettxout <txid> <vout> true must be "
                        "non-null, its scriptPubKey.hex must equal script_hex and round(value * 1e8) "
                        "must equal the input's value in duffs; and for every tx the inputs' values "
                        "must sum to value_out + fee. Legacy sighash commits no input amounts: an "
                        "understated amount would be paid as extra fee"));
        node.put("min_relay_fee_duffs_per_byte", J::integer(kMinRelayFeePerByte));
    } else {
        node.put("lane", J::str("pin|inject (zero fee: Dash Core peers will not relay it)"));
        node.put("pin_flags", J::str("--pin-local-tx-hex <file>"));
        node.put("inject_flags", J::str("--embedded-tx-inject --embedded-tx-inject-hex <file>"));
        node.put("inputs_must_resolve",
                 J::str("forward UTXO view OR --coin-rpc gettxout OR --embedded-fold-live"));
        node.put("inject_needs", J::str("--embedded-fold-live <db> --embedded-fold-checkscripts"));
    }
    node.put("max_tx_bytes", J::integer(static_cast<int64_t>(caps::kMaxInjectTxBytes)));
    node.put("sequence", J::str("0xffffffff"));
    node.put("earliest_block_height", int_or_null(d.safe_from_height));
    root.put("node_requirements", std::move(node));

    J key = J::obj();
    key.put("source", J::str(d.key_source));
    key.put("path", J::str(d.key_path));
    key.put("encoding", J::str(d.key_encoding));
    root.put("key", std::move(key));
    root.put("generated_by", J::str("c2wallet-qt-signer DashInjectModel (slice 2)"));

    std::string out;
    write(out, root, 0);
    out += '\n';
    return out;
}

} // namespace c2w::dash
