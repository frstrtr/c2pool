// SPDX-License-Identifier: AGPL-3.0-or-later
#include "SignSession.hpp"

// The ONLY translation unit that bridges the two header trees: it includes the
// dashscript signer core (uint256/hash/script/primitives via Signer.hpp) and
// the std-only facade header above (which pulls the btclibs-free artifact +
// secure declarations). No btclibs header is included here.
#include "Signer.hpp"
#include "Scripts.hpp"
#include "Crypto.hpp"

#include <hash.h>            // CHash256 (dashscript)
#include <script/script.h>   // CScript
#include <uint256.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace c2w::sign {

namespace sgn = c2w::signer;

namespace {

// ── hex ─────────────────────────────────────────────────────────────────────
std::string hex_of(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0xf]; }
    return s;
}
std::string hex_of(const Bytes& v) { return hex_of(v.data(), v.size()); }

// Byte-reversed hex — the explorer/txid display order.
std::string reversed_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { uint8_t b = p[n - 1 - i]; s += d[b >> 4]; s += d[b & 0xf]; }
    return s;
}

Bytes script_bytes(const CScript& s) { return Bytes(s.begin(), s.end()); }
CScript cscript(const Bytes& b) { return CScript(b.data(), b.data() + b.size()); }

// ── raw (non-witness) tx parser — std-only, no dashscript deserializer ──────
struct RawIn  { Bytes txid; uint32_t index = 0; Bytes scriptsig; uint32_t seq = 0; };
struct RawOut { int64_t value = 0; Bytes spk; };
struct RawTx  { int32_t version = 0; uint32_t locktime = 0; std::vector<RawIn> vin; std::vector<RawOut> vout; };

struct Reader {
    const Bytes& b; size_t pos = 0; bool bad = false;
    explicit Reader(const Bytes& v) : b(v) {}
    uint8_t u8() { if (pos + 1 > b.size()) { bad = true; return 0; } return b[pos++]; }
    uint32_t u32() { uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= uint32_t(u8()) << (8 * i); return v; }
    uint64_t u64() { uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(u8()) << (8 * i); return v; }
    uint64_t compact() {
        uint8_t c = u8();
        if (c < 0xfd) return c;
        if (c == 0xfd) { uint64_t v = u8(); v |= uint64_t(u8()) << 8; return v; }
        if (c == 0xfe) return u32();
        return u64();
    }
    Bytes take(uint64_t n) {
        if (bad || n > b.size() - pos) { bad = true; return {}; }
        Bytes out(b.begin() + pos, b.begin() + pos + n); pos += n; return out;
    }
};

bool parse_raw_tx(const Bytes& raw, RawTx& tx, std::string& err) {
    Reader r(raw);
    tx.version = int32_t(r.u32());
    uint64_t nin = r.compact();
    // A segwit-serialized blob has a 0x00 marker here; an unsigned tx must be
    // the plain (non-witness) form. A 0-input read collides with the marker and
    // is refused by the count cross-check downstream, but reject it plainly too.
    if (nin == 0) { err = "unsigned tx declares zero inputs (or is segwit-serialized)"; return false; }
    if (nin > 100000) { err = "input count implausible"; return false; }
    tx.vin.resize(nin);
    for (auto& in : tx.vin) {
        in.txid = r.take(32);
        in.index = r.u32();
        uint64_t sslen = r.compact();
        in.scriptsig = r.take(sslen);
        in.seq = r.u32();
    }
    uint64_t nout = r.compact();
    if (nout > 100000) { err = "output count implausible"; return false; }
    tx.vout.resize(nout);
    for (auto& o : tx.vout) {
        o.value = int64_t(r.u64());
        uint64_t spklen = r.compact();
        o.spk = r.take(spklen);
    }
    tx.locktime = r.u32();
    if (r.bad) { err = "truncated tx bytes"; return false; }
    if (r.pos != raw.size()) { err = "trailing bytes after tx"; return false; }
    return true;
}

// Validate the parsed tx against the container metadata (GAP-2 cross-checks).
bool cross_check(const RawTx& tx, const c2w::artifact::UnsignedContainer& c, std::string& err) {
    if (tx.vin.size() != c.inputs.size()) { err = "vin count != container input count"; return false; }
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (!tx.vin[i].scriptsig.empty()) { err = "input " + std::to_string(i) + " scriptSig is not empty (already signed?)"; return false; }
        if (tx.vin[i].txid.size() != 32) { err = "input " + std::to_string(i) + " prevout txid truncated"; return false; }
        if (std::memcmp(tx.vin[i].txid.data(), c.inputs[i].prevout_txid.data(), 32) != 0) {
            err = "input " + std::to_string(i) + " prevout txid does not match container"; return false;
        }
        if (tx.vin[i].index != c.inputs[i].prevout_index) {
            err = "input " + std::to_string(i) + " prevout index does not match container"; return false;
        }
    }
    return true;
}

// Build a Signer from the parsed tx + container, and assert the non-witness
// re-serialization is byte-exact against the container's unsigned_tx.
bool build_signer(const RawTx& tx, const c2w::artifact::UnsignedContainer& c,
                  sgn::Signer& sg, std::string& err) {
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        uint256 h; std::memcpy(h.begin(), tx.vin[i].txid.data(), 32);
        sg.add_input(h, tx.vin[i].index, c.inputs[i].amount,
                     cscript(c.inputs[i].script_pubkey), tx.vin[i].seq);
    }
    for (const auto& o : tx.vout) sg.add_output(o.value, cscript(o.spk));

    Bytes reser = sg.serialize(false);
    if (reser != c.unsigned_tx) { err = "re-serialized unsigned tx is not byte-exact (GAP-2)"; return false; }
    return true;
}

// Read a small integer (0..20) encoded either as an OP_N opcode (0x51..0x60)
// or as a 1-byte minimal data push (0x01 0xNN — the form CScript's operator<<
// (CScriptNum) emits). Advances `pos`; returns -1 on any other shape.
int read_small_int(const Bytes& s, size_t& pos) {
    if (pos >= s.size()) return -1;
    const uint8_t op = s[pos];
    if (op == 0x00) { ++pos; return 0; }                    // OP_0
    if (op >= 0x51 && op <= 0x60) { ++pos; return op - 0x50; } // OP_1..OP_16
    if (op == 0x01 && pos + 1 < s.size()) { int v = s[pos + 1]; pos += 2; return v; } // push <v>
    return -1;
}

// Extract the pubkey list (in script order) from a bare-multisig script
// <m> <pk..> <n> OP_CHECKMULTISIG, tolerating BOTH the OP_N and the
// CScriptNum-pushdata encodings of m/n. Returns {} on any non-multisig shape.
std::vector<Bytes> multisig_pubkeys(const Bytes& s) {
    std::vector<Bytes> pks;
    if (s.size() < 4 || s.back() != 0xae) return {};        // OP_CHECKMULTISIG
    size_t pos = 0;
    const int m = read_small_int(s, pos);
    if (m < 1) return {};
    while (pos < s.size() && (s[pos] == 0x21 || s[pos] == 0x41)) {
        size_t len = s[pos];
        if (pos + 1 + len > s.size()) return {};
        pks.emplace_back(s.begin() + pos + 1, s.begin() + pos + 1 + len);
        pos += 1 + len;
    }
    const int n = read_small_int(s, pos);
    if (n < 1 || static_cast<size_t>(n) != pks.size() || m > n) return {};
    if (pos + 1 != s.size() || s[pos] != 0xae) return {};   // OP_CHECKMULTISIG is the tail
    return pks;
}

bool is_multisig(const Bytes& s) { return !multisig_pubkeys(s).empty(); }
bool is_witness_v0_prog(const Bytes& s) {
    return (s.size() == 22 && s[0] == 0x00 && s[1] == 0x14) ||
           (s.size() == 34 && s[0] == 0x00 && s[1] == 0x20);
}

bool bytes_eq(const uint8_t* a, const uint8_t* b, size_t n) { return std::memcmp(a, b, n) == 0; }

} // namespace

const char* spk_type_str(SpkType t) {
    switch (t) {
        case SpkType::P2PK:   return "P2PK";
        case SpkType::P2PKH:  return "P2PKH";
        case SpkType::P2WPKH: return "P2WPKH";
        case SpkType::P2SH:   return "P2SH";
        case SpkType::P2WSH:  return "P2WSH";
        case SpkType::P2TR:   return "P2TR";
        default:              return "Unknown";
    }
}

SpkType classify_spk(const Bytes& s) {
    const size_t n = s.size();
    if (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xac) return SpkType::P2PKH;
    if (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) return SpkType::P2SH;
    if (n == 22 && s[0] == 0x00 && s[1] == 0x14) return SpkType::P2WPKH;
    if (n == 34 && s[0] == 0x00 && s[1] == 0x20) return SpkType::P2WSH;
    if (n == 34 && s[0] == 0x51 && s[1] == 0x20) return SpkType::P2TR;
    if (n == 35 && s[0] == 0x21 && s[34] == 0xac) return SpkType::P2PK;
    if (n == 67 && s[0] == 0x41 && s[66] == 0xac) return SpkType::P2PK;
    return SpkType::Unknown;
}

TxView parse_unsigned(const c2w::artifact::UnsignedContainer& c) {
    TxView v;
    RawTx tx;
    if (!parse_raw_tx(c.unsigned_tx, tx, v.error)) return v;
    if (!cross_check(tx, c, v.error)) return v;

    sgn::Signer sg(tx.version, tx.locktime);
    if (!build_signer(tx, c, sg, v.error)) return v;

    v.version = tx.version;
    v.locktime = tx.locktime;
    v.serialized_size = c.unsigned_tx.size();
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        InputView iv;
        iv.script_pubkey = c.inputs[i].script_pubkey;
        iv.type = classify_spk(iv.script_pubkey);
        iv.amount = c.inputs[i].amount;
        iv.prevout_txid_display = reversed_hex(tx.vin[i].txid.data(), 32);
        iv.prevout_index = tx.vin[i].index;
        iv.derivation_hint = c.inputs[i].derivation_hint;
        iv.spk_hex = hex_of(iv.script_pubkey);
        v.sum_in += iv.amount;
        v.inputs.push_back(std::move(iv));
    }
    for (const auto& o : tx.vout) {
        OutputView ov;
        ov.value = o.value;
        ov.script_pubkey = o.spk;
        ov.spk_hex = hex_of(o.spk);
        v.sum_out += ov.value;
        v.outputs.push_back(std::move(ov));
    }
    v.fee = v.sum_in - v.sum_out;
    v.ok = true;
    return v;
}

SignOutcome sign_and_verify(const c2w::artifact::UnsignedContainer& c,
                            std::vector<KeyForInput>&& keys,
                            const SignOptions& opt) {
    SignOutcome out;

    RawTx tx;
    if (!parse_raw_tx(c.unsigned_tx, tx, out.error)) return out;
    if (!cross_check(tx, c, out.error)) return out;

    sgn::Signer sg(tx.version, tx.locktime);
    if (!build_signer(tx, c, sg, out.error)) return out;

    // ── balance / absurd-fee / oversize gates (T-4) ─────────────────────────
    int64_t sum_in = 0, sum_out = 0;
    for (const auto& in : c.inputs) sum_in += in.amount;
    for (const auto& o : tx.vout) sum_out += o.value;
    const int64_t fee = sum_in - sum_out;
    if (fee < 0) { out.error = "refuse: unbalanced (sum_in - sum_out < 0)"; return out; }
    if (fee > kAbsurdFeeSats && !opt.absurd_fee_confirmed) {
        out.error = "refuse: absurd fee " + std::to_string(fee) +
                    " sat exceeds " + std::to_string(kAbsurdFeeSats) +
                    " sat; set absurd_fee_confirmed to override";
        return out;
    }

    // ── group keys by input index ───────────────────────────────────────────
    std::map<size_t, std::vector<size_t>> by_input;
    for (size_t k = 0; k < keys.size(); ++k) by_input[keys[k].index].push_back(k);

    for (size_t i = 0; i < tx.vin.size(); ++i) {
        const Bytes& spk = c.inputs[i].script_pubkey;
        const SpkType t = classify_spk(spk);
        auto it = by_input.find(i);
        if (it == by_input.end() || it->second.empty()) {
            out.error = "refuse: input " + std::to_string(i) + " has no signing key"; return out;
        }
        const std::vector<size_t>& kidx = it->second;
        const KeyForInput& k0 = keys[kidx[0]];
        const int64_t amount = c.inputs[i].amount;

        switch (t) {
            case SpkType::P2PK: {
                // Binding: the pubkey embedded in the SPK must equal ours (T-6).
                const size_t plen = spk[0];
                if (spk.size() != plen + 2 || !bytes_eq(spk.data() + 1, k0.pub.data(),
                        std::min<size_t>(plen, k0.pub.size())) || k0.pub.size() != plen) {
                    out.error = "refuse: derived key does not fund input " + std::to_string(i) + " (P2PK pubkey mismatch)"; return out;
                }
                Bytes sig = sg.make_legacy_sig(i, cscript(spk), k0.sk, opt.sighash);
                sg.set_scriptsig(i, sgn::push_data(sig));
                break;
            }
            case SpkType::P2PKH: {
                Bytes h = sgn::hash160(k0.pub);
                if (h.size() != 20 || !bytes_eq(h.data(), spk.data() + 3, 20)) {
                    out.error = "refuse: derived key does not fund input " + std::to_string(i) + " (P2PKH hash160 mismatch)"; return out;
                }
                Bytes sig = sg.make_legacy_sig(i, cscript(spk), k0.sk, opt.sighash);
                CScript ss; ss << sig << k0.pub;
                sg.set_scriptsig(i, ss);
                break;
            }
            case SpkType::P2WPKH: {
                Bytes h = sgn::hash160(k0.pub);
                if (h.size() != 20 || !bytes_eq(h.data(), spk.data() + 2, 20)) {
                    out.error = "refuse: derived key does not fund input " + std::to_string(i) + " (P2WPKH hash160 mismatch)"; return out;
                }
                Bytes sig = sg.make_bip143_sig(i, sgn::p2wpkh_scriptcode(k0.pub), amount, k0.sk, opt.sighash);
                sg.set_witness(i, sgn::Witness{sig, k0.pub});
                break;
            }
            case SpkType::P2SH: {
                // redeemScript: supplied for multisig/arbitrary; derived as the
                // P2SH-P2WPKH program when absent.
                Bytes redeem = k0.script;
                if (redeem.empty()) redeem = script_bytes(sgn::p2wpkh(k0.pub));
                Bytes rh = sgn::hash160(redeem);
                if (rh.size() != 20 || !bytes_eq(rh.data(), spk.data() + 2, 20)) {
                    out.error = "refuse: derived key does not fund input " + std::to_string(i) + " (P2SH redeem hash160 mismatch)"; return out;
                }
                if (is_witness_v0_prog(redeem)) {
                    if (redeem.size() == 22) { // P2SH-P2WPKH
                        Bytes sig = sg.make_bip143_sig(i, sgn::p2wpkh_scriptcode(k0.pub), amount, k0.sk, opt.sighash);
                        sg.set_scriptsig(i, sgn::push_data(redeem));
                        sg.set_witness(i, sgn::Witness{sig, k0.pub});
                    } else {
                        out.error = "refuse: P2SH-P2WSH is not in slice-2a"; return out;
                    }
                } else if (is_multisig(redeem)) {
                    std::vector<Bytes> pks = multisig_pubkeys(redeem);
                    std::vector<std::pair<Bytes, Bytes>> partials;
                    for (size_t ki : kidx) {
                        Bytes sig = sg.make_legacy_sig(i, cscript(redeem), keys[ki].sk, opt.sighash);
                        partials.emplace_back(keys[ki].pub, sig);
                    }
                    std::vector<Bytes> ordered = sgn::Signer::order_multisig_sigs(pks, partials);
                    CScript redeem_cs = cscript(redeem);
                    sg.set_scriptsig(i, sgn::Signer::multisig_scriptsig(ordered, &redeem_cs));
                } else {
                    // single-key legacy P2SH (e.g. P2SH-P2PK / P2SH-P2PKH)
                    Bytes sig = sg.make_legacy_sig(i, cscript(redeem), k0.sk, opt.sighash);
                    CScript ss; ss << sig;
                    if (classify_spk(redeem) == SpkType::P2PKH) ss << k0.pub;
                    ss << redeem;
                    sg.set_scriptsig(i, ss);
                }
                break;
            }
            case SpkType::P2WSH: {
                Bytes ws = k0.script;
                if (ws.empty()) { out.error = "refuse: input " + std::to_string(i) + " P2WSH needs a witnessScript"; return out; }
                Bytes sh = sgn::sha256(ws);
                if (sh.size() != 32 || !bytes_eq(sh.data(), spk.data() + 2, 32)) {
                    out.error = "refuse: derived key does not fund input " + std::to_string(i) + " (P2WSH sha256 mismatch)"; return out;
                }
                if (is_multisig(ws)) {
                    std::vector<Bytes> pks = multisig_pubkeys(ws);
                    std::vector<std::pair<Bytes, Bytes>> partials;
                    for (size_t ki : kidx) {
                        Bytes sig = sg.make_bip143_sig(i, cscript(ws), amount, keys[ki].sk, opt.sighash);
                        partials.emplace_back(keys[ki].pub, sig);
                    }
                    std::vector<Bytes> ordered = sgn::Signer::order_multisig_sigs(pks, partials);
                    sg.set_witness(i, sgn::Signer::multisig_witness(ordered, cscript(ws)));
                } else {
                    Bytes sig = sg.make_bip143_sig(i, cscript(ws), amount, k0.sk, opt.sighash);
                    sg.set_witness(i, sgn::Witness{sig, ws});
                }
                break;
            }
            case SpkType::P2TR: {
                // Key-path only in slice-2a (no script tree). Binding is enforced
                // by finalize()'s taproot verifier: a wrong key yields a different
                // output key and the Schnorr check fails.
                const int th = (opt.sighash == 0x01) ? 0x00 /*SIGHASH_DEFAULT*/ : opt.sighash;
                Bytes sig = sg.make_taproot_keypath_sig(i, k0.sk, /*merkle_root*/ nullptr, th);
                if (sig.empty()) { out.error = "refuse: taproot key-path sign failed for input " + std::to_string(i); return out; }
                sg.set_witness(i, sgn::Witness{sig});
                break;
            }
            default:
                out.error = "refuse: input " + std::to_string(i) + " has an unsupported scriptPubKey type"; return out;
        }
    }

    // ── MANDATORY finalize self-verify (T-5) + oversize refusal ─────────────
    Bytes signed_tx;
    std::string ferr;
    if (!sg.finalize(signed_tx, ferr)) {
        out.error = "refuse: self-verify/oversize failed: " + ferr;
        return out;
    }

    // ── re-assert the txid (non-witness) is self-consistent ─────────────────
    uint256 tid = sg.txid();
    // Independent recompute of sha256d over the non-witness serialization.
    Bytes nonwit = sg.serialize(false);
    uint256 tid2 = Hash(nonwit);
    if (tid != tid2) { out.error = "refuse: txid cross-check mismatch"; return out; }

    out.ok = true;
    out.signed_tx = hex_of(signed_tx);
    out.txid_display = reversed_hex(tid.begin(), 32);
    // wtxid: sha256d of the full (witness) bytes — equals txid for legacy txs.
    uint256 wtid = Hash(signed_tx);
    out.wtxid_display = reversed_hex(wtid.begin(), 32);
    out.warnings = sg.warnings();
    return out;
}

} // namespace c2w::sign
