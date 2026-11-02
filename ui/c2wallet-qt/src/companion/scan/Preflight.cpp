// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Preflight.hpp"

#include "../Submit.hpp"            // parse_signed_artifact
#include "../sched/InjectQueue.hpp" // preflight_raw_tx, kProjectedTipHashPrefix
#include "../sched/Json.hpp"
#include "../sched/SubmitOutcome.hpp"
#include "../sched/TokenFile.hpp"   // build_token_body, wipe_string

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"
#include "../../family/bitcoin/dash/UtxoIntake.hpp"

#include "Digest.hpp"
#include "ValidateSeam.hpp" // crossgap_txid

#include <algorithm>
#include <array>
#include <map>
#include <set>

namespace c2w::companion::scan {

namespace {

using J = sched::json::J;
using c2w::dash::Utxo;

bool read_compact(const std::vector<uint8_t>& b, size_t& p, uint64_t& n)
{
    if (p >= b.size()) return false;
    const uint8_t c = b[p++];
    if (c < 0xfd) {
        n = c;
        return true;
    }
    const int width = c == 0xfd ? 2 : (c == 0xfe ? 4 : 8);
    if (p + static_cast<size_t>(width) > b.size()) return false;
    n = 0;
    for (int i = 0; i < width; ++i) n |= static_cast<uint64_t>(b[p + static_cast<size_t>(i)]) << (8 * i);
    p += static_cast<size_t>(width);
    return true;
}

std::string sha_hex(const std::string& s)
{
    return c2w::artifact::to_hex(c2w::artifact::sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

struct ManifestTx {
    std::string txid;
    int64_t fee = 0;
    std::vector<Utxo> inputs;
};

struct Manifest {
    std::string network, fee_mode, hex_file_sha256, screen_tip_hash;
    std::vector<ManifestTx> txs;
};

bool parse_manifest(const std::string& text, Manifest& m, std::string& why)
{
    J root;
    if (!sched::json::parse_bounded(text, root, why) || !root.is_object()) {
        why = "manifest: " + (why.empty() ? std::string("not a JSON object") : why);
        return false;
    }
    sched::json::Reader rd;
    if (rd.req_str(root, "schema", "manifest") != sched::kManifestSchema) {
        why = "manifest: schema is not " + std::string(sched::kManifestSchema);
        return false;
    }
    m.network = rd.str(root, "network", "manifest");
    m.fee_mode = rd.str(root, "fee_mode", "manifest");
    m.hex_file_sha256 = rd.req_str(root, "hex_file_sha256", "manifest");
    if (const J* mat = rd.obj(root, "maturity", "manifest"))
        m.screen_tip_hash = rd.str(*mat, "screen_tip_hash", "manifest.maturity");
    if (const J* txs = rd.arr(root, "txs", "manifest")) {
        for (size_t i = 0; i < txs->size(); ++i) {
            const J& t = (*txs)[i];
            const std::string p = "manifest.txs[" + std::to_string(i) + "]";
            ManifestTx mt;
            mt.txid = lower(rd.req_str(t, "txid", p));
            mt.fee = rd.i64(t, "fee", p);
            if (const J* ins = rd.arr(t, "inputs", p)) {
                for (size_t k = 0; k < ins->size(); ++k) {
                    const J& in = (*ins)[k];
                    const std::string q = p + ".inputs[" + std::to_string(k) + "]";
                    Utxo u;
                    u.txid = lower(rd.req_str(in, "txid", q));
                    const int64_t vout = rd.i64(in, "vout", q, -1);
                    if (vout < 0 || vout > 0xffffffffll) rd.fail(q + ".vout", "out of range");
                    u.vout = static_cast<uint32_t>(vout < 0 ? 0 : vout);
                    u.satoshis = rd.i64(in, "value", q);
                    u.script_pubkey_hex = lower(rd.req_str(in, "script_hex", q));
                    u.height = rd.i64(in, "height", q);
                    u.coinbase = rd.obool(in, "coinbase", q);
                    mt.inputs.push_back(std::move(u));
                }
            }
            m.txs.push_back(std::move(mt));
        }
    }
    if (!rd.ok()) {
        why = rd.err;
        return false;
    }
    if (m.txs.empty()) {
        why = "manifest lists no tx";
        return false;
    }
    return true;
}

} // namespace

bool parse_tx_io(const std::string& raw_hex, TxIO& out, std::string& why)
{
    out = TxIO{};
    const auto bytes = c2w::artifact::from_hex(raw_hex);
    if (!bytes || bytes->size() < 10) {
        why = "not a raw tx in hex";
        return false;
    }
    const std::vector<uint8_t>& b = *bytes;
    if (b[4] == 0x00 && b[5] == 0x01) {
        why = "a segwit serialization (DASH txs are legacy)";
        return false;
    }
    std::vector<uint8_t> blank(b.begin(), b.begin() + 4);
    size_t p = 4;
    uint64_t nin = 0;
    if (!read_compact(b, p, nin) || nin == 0 || nin > b.size()) {
        why = "bad input count";
        return false;
    }
    blank.insert(blank.end(), b.begin() + 4, b.begin() + static_cast<long>(p));
    for (uint64_t i = 0; i < nin; ++i) {
        if (p + 36 > b.size()) { why = "truncated input"; return false; }
        std::vector<uint8_t> txid(b.begin() + static_cast<long>(p), b.begin() + static_cast<long>(p) + 32);
        blank.insert(blank.end(), b.begin() + static_cast<long>(p), b.begin() + static_cast<long>(p) + 36);
        std::reverse(txid.begin(), txid.end());
        uint32_t vout = 0;
        for (int k = 0; k < 4; ++k) vout |= static_cast<uint32_t>(b[p + 32 + static_cast<size_t>(k)]) << (8 * k);
        p += 36;
        uint64_t slen = 0;
        if (!read_compact(b, p, slen) || p + slen + 4 > b.size()) { why = "truncated scriptSig"; return false; }
        p += slen;
        blank.push_back(0x00); // empty scriptSig
        blank.insert(blank.end(), b.begin() + static_cast<long>(p), b.begin() + static_cast<long>(p) + 4);
        p += 4;
        out.inputs.push_back({c2w::artifact::to_hex(txid), vout});
    }
    const size_t outs_at = p;
    uint64_t nout = 0;
    if (!read_compact(b, p, nout) || nout == 0 || nout > b.size()) { why = "bad output count"; return false; }
    for (uint64_t i = 0; i < nout; ++i) {
        if (p + 8 > b.size()) { why = "truncated output"; return false; }
        uint64_t v = 0;
        for (int k = 0; k < 8; ++k) v |= static_cast<uint64_t>(b[p + static_cast<size_t>(k)]) << (8 * k);
        p += 8;
        uint64_t slen = 0;
        if (!read_compact(b, p, slen) || p + slen > b.size()) { why = "truncated output script"; return false; }
        out.outputs.push_back({static_cast<int64_t>(v),
                               c2w::artifact::to_hex(b.data() + p, static_cast<size_t>(slen))});
        p += slen;
    }
    if (p + 4 != b.size()) { why = "bad locktime or trailing bytes"; return false; }
    blank.insert(blank.end(), b.begin() + static_cast<long>(outs_at), b.end());
    out.unsigned_sha256d = c2w::artifact::sha256d_display(blank);
    return true;
}

std::string PreflightReport::text() const
{
    std::string s;
    for (const auto& l : lines) s += l + "\n";
    for (const auto& n : notices) s += "notice: " + n + "\n";
    for (const auto& w : warnings) s += "warning: " + w + "\n";
    for (const auto& r : refusals) s += "REFUSED: " + r + "\n";
    std::string checks;
    for (const auto& c : ran) checks += (checks.empty() ? "" : ", ") + c;
    s += std::string(ok ? "preflight: PASS" : "preflight: FAILED") + (ok && forced ? " (forced)" : "") +
         " (checks run: " + (checks.empty() ? std::string("none") : checks) + ")\n";
    return s;
}

PreflightReport run_preflight(const PreflightInput& in, const PreflightOptions& opt, SourceDashd* dashd,
                              UtxoSource* c2pool, sched::NodeApi* node, const c2w::secure::SecureString* token)
{
    PreflightReport r;
    auto forceable = [&](const std::string& why) {
        if (opt.force_reason.empty()) {
            r.refusals.push_back(why + " (--force \"<reason>\" to queue it anyway)");
        } else {
            r.forced = true;
            r.warnings.push_back("FORCED (" + opt.force_reason + "): " + why);
        }
    };
    auto finish = [&]() -> PreflightReport& {
        r.ok = r.refusals.empty();
        return r;
    };

    // ── (a) structure ────────────────────────────────────────────────────────
    std::string why;
    const auto sc = parse_signed_artifact(in.hex_text, why);
    if (!sc || sc->tx_hexes.empty()) {
        r.refusals.push_back("hex file: " + (why.empty() ? std::string("no transaction") : why));
        return finish();
    }
    Manifest m;
    if (!parse_manifest(in.manifest_text, m, why)) {
        r.refusals.push_back(why);
        return finish();
    }
    const std::string want_net = opt.testnet ? "testnet" : "mainnet";
    if (m.network != want_net) r.refusals.push_back("the manifest is for " + m.network + ", the scan is " + want_net);
    if (m.hex_file_sha256 != sha_hex(in.hex_text))
        r.refusals.push_back("the hex file's sha256 is not the manifest's hex_file_sha256 (another hex file)");
    if (m.txs.size() != sc->tx_hexes.size())
        r.refusals.push_back("the manifest lists " + std::to_string(m.txs.size()) + " txs, the hex file carries " +
                             std::to_string(sc->tx_hexes.size()));
    if (!r.refusals.empty()) return finish();
    const bool projected = m.screen_tip_hash.rfind(sched::kProjectedTipHashPrefix, 0) == 0;
    std::vector<TxIO> io(m.txs.size());
    for (size_t i = 0; i < m.txs.size(); ++i) {
        const std::string ln = "tx " + std::to_string(i + 1);
        const std::string& hex = sc->tx_hexes[i];
        if (!sched::preflight_raw_tx(hex, m.txs[i].txid, why)) {
            r.refusals.push_back(ln + ": " + why);
            continue;
        }
        if (!parse_tx_io(hex, io[i], why)) {
            r.refusals.push_back(ln + ": " + why);
            continue;
        }
        std::vector<Outpoint> want;
        for (const Utxo& u : m.txs[i].inputs) want.push_back({u.txid, u.vout});
        if (io[i].inputs != want) r.refusals.push_back(ln + ": the signed tx's inputs are not the manifest's inputs");
    }
    if (!r.refusals.empty()) return finish();
    r.lines.push_back("(a) " + std::to_string(m.txs.size()) + " signed tx(s): sha256 bound to the manifest, txids "
                      "and inputs match, within the node caps");
    r.ran.push_back("a");
    if (projected)
        r.notices.push_back("stage-2 manifest: heights are projected (" + m.screen_tip_hash +
                            "); queue it with --after-parent for every parent");

    // ── (b) reconciliation ───────────────────────────────────────────────────
    if (in.utxos_text) {
        c2w::dash::UtxoImport ex;
        try {
            ex = c2w::dash::parse_utxo_export_v1(*in.utxos_text, opt.testnet);
        } catch (const c2w::dash::DashAbort& e) {
            r.refusals.push_back(std::string("the utxos file does not import: ") + e.what());
            return finish();
        }
        std::map<Outpoint, const Utxo*> rows;
        for (const Utxo& u : ex.utxos) rows[{u.txid, u.vout}] = &u;
        size_t n = 0;
        for (const ManifestTx& t : m.txs)
            for (const Utxo& u : t.inputs) {
                ++n;
                const auto it = rows.find({u.txid, u.vout});
                const std::string name = u.txid + ":" + std::to_string(u.vout);
                if (it == rows.end()) {
                    r.refusals.push_back("manifest input " + name + " is not a row of the utxos file the plan was made from");
                    continue;
                }
                const Utxo& e = *it->second;
                if (e.satoshis != u.satoshis || lower(e.script_pubkey_hex) != u.script_pubkey_hex || e.height != u.height ||
                    e.coinbase != u.coinbase)
                    r.refusals.push_back("manifest input " + name +
                                         " differs from its export row (value / script / height / coinbase)");
            }
        if (r.refusals.empty())
            r.lines.push_back("(b) every manifest input (" + std::to_string(n) + ") is an export row with equal value, "
                              "script, height and coinbase flag");
    }
    if (in.scanplan_text) {
        J sp;
        if (!sched::json::parse_bounded(*in.scanplan_text, sp, why) || !sp.is_object()) {
            r.refusals.push_back("scan-plan sidecar: " + (why.empty() ? std::string("not a JSON object") : why));
            return finish();
        }
        if (!in.utxos_text) {
            r.refusals.push_back("the scan-plan sidecar is bound to a utxos file; give it with --utxos");
        } else if (!sp.contains("utxos_file_sha256") || sp["utxos_file_sha256"] != sha_hex(*in.utxos_text)) {
            r.refusals.push_back("the scan-plan sidecar describes another utxos file (utxos_file_sha256)");
        } else {
            const J* batches = sp.contains("expected") && sp["expected"].contains("batches") ? &sp["expected"]["batches"] : nullptr;
            size_t compared = 0;
            for (size_t i = 0; i < io.size(); ++i) {
                const J* b = batches && batches->is_array() && i < batches->size() ? &(*batches)[i] : nullptr;
                if (!b || !b->contains("unsigned_sha256d") || !(*b)["unsigned_sha256d"].is_string()) continue;
                ++compared;
                if ((*b)["unsigned_sha256d"].get<std::string>() != io[i].unsigned_sha256d)
                    forceable("tx " + std::to_string(i + 1) + " is not the planned tx: unsigned sha256d " +
                              io[i].unsigned_sha256d + " != the sidecar's " + (*b)["unsigned_sha256d"].get<std::string>() +
                              " (the signer planned differently: key encoding, parameters?)");
            }
            if (batches && batches->is_array() && batches->size() != io.size() && !projected)
                forceable("the sidecar plans " + std::to_string(batches->size()) + " tx(s), the hex file carries " +
                          std::to_string(io.size()));
            r.lines.push_back("(b) sidecar bound to the utxos file; " + std::to_string(compared) +
                              " signed tx(s) compared with the planned unsigned digests");
        }
    }
    if (in.utxos_text || in.scanplan_text) r.ran.push_back("b");
    if (!r.refusals.empty()) return finish();

    // ── (c) still unspent ────────────────────────────────────────────────────
    std::vector<Utxo> inputs;
    std::set<Outpoint> seen;
    for (const ManifestTx& t : m.txs)
        for (const Utxo& u : t.inputs)
            if (seen.insert({u.txid, u.vout}).second) inputs.push_back(u);
    std::set<std::string> parents_unmined; // projected manifest: inputs the sources do not know yet
    try {
        if (dashd) {
            ScanOptions so = opt.scan;
            so.testnet = opt.testnet;
            for (const UnspentCheck& c : dashd->check_unspent(inputs, so)) {
                if (c.unspent) continue;
                if (projected && c.problem.rfind("spent", 0) == 0) {
                    parents_unmined.insert(c.outpoint.txid);
                    continue;
                }
                r.refusals.push_back("input " + outpoint_str(c.outpoint) + " on dashd: " + c.problem);
            }
            r.lines.push_back("(c) dashd: " + std::to_string(inputs.size()) + " input(s) checked with gettxout");
        }
        if (c2pool) {
            std::vector<std::string> addresses;
            for (const Utxo& u : inputs) {
                const auto spk = c2w::artifact::from_hex(u.script_pubkey_hex);
                if (!spk || spk->size() != 25 || (*spk)[0] != 0x76 || (*spk)[1] != 0xa9 || (*spk)[2] != 0x14) {
                    r.refusals.push_back("input " + u.txid + ":" + std::to_string(u.vout) + " is not a P2PKH output");
                    continue;
                }
                std::array<uint8_t, 20> h{};
                std::copy(spk->begin() + 3, spk->begin() + 23, h.begin());
                const std::string a = c2w::dash::h160_to_addr(h, opt.testnet);
                if (std::find(addresses.begin(), addresses.end(), a) == addresses.end()) addresses.push_back(a);
            }
            if (!r.refusals.empty()) return finish();
            ScanOptions so = opt.scan;
            so.testnet = opt.testnet;
            const ScanResult sr = c2pool->scan(addresses, so);
            std::map<Outpoint, const Utxo*> rows;
            for (const auto& imp : sr.imports)
                for (const Utxo& u : imp.utxos) rows[{u.txid, u.vout}] = &u;
            const std::set<Outpoint> spent(sr.mempool_spent.begin(), sr.mempool_spent.end());
            for (const Utxo& u : inputs) {
                const Outpoint o{u.txid, u.vout};
                const auto it = rows.find(o);
                if (it == rows.end()) {
                    if (projected && !spent.count(o)) {
                        parents_unmined.insert(u.txid);
                        continue;
                    }
                    r.refusals.push_back("input " + outpoint_str(o) + " on the node: " +
                                         (spent.count(o) ? "spent by a tx in the node's mempool"
                                                         : "not in the full UTXO set (spent, or never existed)"));
                    continue;
                }
                const Utxo& e = *it->second;
                if (e.satoshis != u.satoshis || e.script_pubkey_hex != u.script_pubkey_hex || e.height != u.height ||
                    e.coinbase != u.coinbase)
                    r.refusals.push_back("input " + outpoint_str(o) +
                                         " on the node differs from the manifest (value / script / height / coinbase)");
            }
            r.lines.push_back("(c) node: " + std::to_string(inputs.size()) + " input(s) checked against the full UTXO set at " +
                              std::to_string(sr.tip_height));
        }
        if (dashd || c2pool) r.ran.push_back("c");
    } catch (const ScanRefusal& e) {
        // The chosen source could not answer: the inputs are UNKNOWN, not
        // unspent.
        if (e.cause() == cause::kCancelled) {
            r.refusals.push_back(std::string("cancelled: ") + e.what());
            return finish();
        }
        forceable(std::string("UNKNOWN: (c) the still-unspent check could not run: ") + e.what());
    }
    if (!dashd && !c2pool) r.notices.push_back("(c) no source configured: inputs not re-checked");
    for (const std::string& t : parents_unmined)
        r.notices.push_back("(c) parent " + t + " is not mined yet: its outputs are checked when the scheduler fires");
    if (!r.refusals.empty()) return finish();

    // ── (d) dry run ──────────────────────────────────────────────────────────
    if (!opt.validate) {
        r.notices.push_back("(d) dry run skipped (--no-validate)");
    } else if (!node) {
        r.notices.push_back("(d) dry run skipped: no node");
    } else if (projected) {
        r.notices.push_back("(d) dry run skipped: a stage-2 tx's parents are not mined yet; the node's verdict comes "
                            "with the scheduler's submit");
    } else if (!token) {
        r.notices.push_back("(d) dry run skipped: it needs the node's control token (--token-file)");
    } else {
        for (size_t i = 0; i < m.txs.size(); ++i) {
            if (is_cancelled(opt.scan)) {
                r.refusals.push_back("cancelled during the dry run");
                break;
            }
            const std::string ln = "tx " + std::to_string(i + 1);
            const int64_t max_fee = m.fee_mode == "relay" ? m.txs[i].fee : 0;
            std::string body = sched::build_token_body(*token, "\"raw_tx\":\"" + sc->tx_hexes[i] +
                                                                   "\",\"max_fee\":" + std::to_string(max_fee));
            const sched::HttpReply rep = node->post_json(kValidateRoute, body);
            sched::wipe_string(body);
            if (!rep.transport_ok) {
                forceable("UNKNOWN: (d) " + ln + ": the node did not answer the dry run (" + rep.error + ")");
                break;
            }
            if (rep.status == 404 || rep.status == 503) {
                r.notices.push_back("(d) validate: the node has no dry-run route (HTTP " + std::to_string(rep.status) +
                                    ", older node or not wired); relying on (a)-(c)");
                break;
            }
            if (rep.status == 403) {
                forceable("UNKNOWN: (d) the node refused the dry run (HTTP 403: the token, or not a direct local "
                          "request); the queued item would block on it too");
                break;
            }
            J j;
            if (!sched::json::parse_bounded(rep.body, j, why) || !j.is_object() || !j.contains("dry_run") ||
                j["dry_run"] != true) {
                forceable("UNKNOWN: (d) the node answered POST " + std::string(kValidateRoute) +
                          " without a dry-run reply (HTTP " + std::to_string(rep.status) + ")");
                break;
            }
            const std::string echo = j.contains("txid") && j["txid"].is_string() ? lower(j["txid"].get<std::string>()) : "";
            if (echo != m.txs[i].txid) {
                r.refusals.push_back("(d) " + ln + ": the dry run analysed txid " + echo + ", not " + m.txs[i].txid);
                continue;
            }
            const std::string cause = j.contains("cause") && j["cause"].is_string() ? j["cause"].get<std::string>() : "";
            if (j.value("ok", false) && cause == sched::cause::Ok) {
                std::string fee = j.contains("fee") && j["fee"].is_number_integer()
                                      ? std::to_string(j["fee"].get<int64_t>()) + " duffs"
                                      : std::string("unpriced");
                r.lines.push_back("(d) " + ln + ": the node would admit it (dry run, fee " + fee + ")");
                if (std::find(r.ran.begin(), r.ran.end(), "d") == r.ran.end()) r.ran.push_back("d");
                continue;
            }
            std::string detail;
            if (j.contains("conflicts") && j["conflicts"].is_array())
                for (const J& c : j["conflicts"])
                    if (c.is_object())
                        detail += "; input " + c.value("txid", std::string()) + ":" + std::to_string(c.value("vout", 0)) +
                                  " already spent by pool tx " + c.value("spent_by", std::string());
            if (j.contains("inputs") && j["inputs"].is_array())
                for (const J& c : j["inputs"])
                    if (c.is_object() && c.contains("immature") && c["immature"] == true)
                        detail += "; immature input " + c.value("txid", std::string()) + ":" +
                                  std::to_string(c.value("vout", 0)) + " spendable from " +
                                  (c["spendable_from_height"].is_number() ? std::to_string(c["spendable_from_height"].get<int64_t>()) : "?");
            if (std::find(r.ran.begin(), r.ran.end(), "d") == r.ran.end()) r.ran.push_back("d");
            const sched::Outcome o = sched::classify_cause(cause, rep.status);
            const std::string text = "(d) " + ln + ": dry run " + cause + " — " + o.why + detail;
            if (cause == sched::cause::Disabled || cause == sched::cause::TipUnknown ||
                cause == sched::cause::RateLimitedCount || cause == sched::cause::RateLimitedBytes)
                r.warnings.push_back(text + " (transient: the scheduler waits for it)");
            else
                forceable(text);
        }
    }
    return finish();
}

} // namespace c2w::companion::scan
