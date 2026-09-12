// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Taproot.hpp"

#include "Crypto.hpp"

#include <crypto/sha256.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace c2w::signer {

namespace {

inline Bytes sha256_bytes(const std::vector<uint8_t>& x)
{
    Bytes out(32);
    CSHA256().Write(x.data(), x.size()).Finalize(out.data());
    return out;
}

void put_u32_le(std::vector<uint8_t>& v, uint32_t x)
{
    v.push_back((uint8_t)(x & 0xff));
    v.push_back((uint8_t)((x >> 8) & 0xff));
    v.push_back((uint8_t)((x >> 16) & 0xff));
    v.push_back((uint8_t)((x >> 24) & 0xff));
}
void put_i64_le(std::vector<uint8_t>& v, int64_t x)
{
    uint64_t u = (uint64_t)x;
    for (int i = 0; i < 8; ++i) v.push_back((uint8_t)((u >> (8 * i)) & 0xff));
}
void put_compactsize(std::vector<uint8_t>& v, uint64_t n)
{
    if (n < 253) { v.push_back((uint8_t)n); }
    else if (n <= 0xffff) { v.push_back(253); v.push_back((uint8_t)(n & 0xff)); v.push_back((uint8_t)(n >> 8)); }
    else if (n <= 0xffffffff) { v.push_back(254); put_u32_le(v, (uint32_t)n); }
    else { v.push_back(255); put_i64_le(v, (int64_t)n); }
}
// compactsize(len) ‖ bytes — a script serialized as a length-prefixed field.
void put_var_script(std::vector<uint8_t>& v, const CScript& s)
{
    put_compactsize(v, s.size());
    v.insert(v.end(), s.begin(), s.end());
}
void put_outpoint(std::vector<uint8_t>& v, const COutPoint& o)
{
    v.insert(v.end(), o.hash.begin(), o.hash.end()); // 32 bytes, internal order
    put_u32_le(v, o.n);
}
void put_output(std::vector<uint8_t>& v, const CTxOut& o)
{
    put_i64_le(v, o.nValue);
    put_var_script(v, o.scriptPubKey);
}

// A CScriptNum-free minimal number reader/writer for the tapscript subset.
int64_t read_scriptnum(const std::vector<uint8_t>& vch)
{
    if (vch.empty()) return 0;
    int64_t result = 0;
    for (size_t i = 0; i < vch.size(); ++i) result |= (int64_t)vch[i] << (8 * i);
    if (vch.back() & 0x80) return -((int64_t)(result & ~((int64_t)0x80 << (8 * (vch.size() - 1)))));
    return result;
}

} // namespace

// ── tagged hashes ───────────────────────────────────────────────────────────
uint256 tagged_hash(const std::string& tag, const std::vector<uint8_t>& msg)
{
    uint8_t th[32];
    CSHA256().Write(reinterpret_cast<const uint8_t*>(tag.data()), tag.size()).Finalize(th);
    CSHA256 h;
    h.Write(th, 32).Write(th, 32).Write(msg.data(), msg.size());
    uint256 out;
    h.Finalize(out.begin());
    return out;
}

uint256 tapleaf_hash(uint8_t leaf_version, const CScript& script)
{
    std::vector<uint8_t> m;
    m.push_back(leaf_version);
    put_var_script(m, script);
    return tagged_hash("TapLeaf", m);
}

uint256 tapbranch_hash(const uint256& a, const uint256& b)
{
    std::vector<uint8_t> m(64);
    const bool a_first = std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
    const uint256& lo = a_first ? a : b;
    const uint256& hi = a_first ? b : a;
    std::memcpy(m.data(), lo.begin(), 32);
    std::memcpy(m.data() + 32, hi.begin(), 32);
    return tagged_hash("TapBranch", m);
}

// ── tap tree ──────────────────────────────────────────────────────────────
TapTree TapTree::Leaf(const CScript& s, uint8_t ver)
{
    TapTree t;
    t.leaf = true;
    t.leaf_version = ver;
    t.script = s;
    return t;
}
TapTree TapTree::Branch(const TapTree& a, const TapTree& b)
{
    TapTree t;
    t.leaf = false;
    t.l = std::make_shared<TapTree>(a);
    t.r = std::make_shared<TapTree>(b);
    return t;
}
uint256 TapTree::merkle_root() const
{
    if (leaf) return tapleaf_hash(leaf_version, script);
    return tapbranch_hash(l->merkle_root(), r->merkle_root());
}
bool TapTree::merkle_path(const uint256& target, std::vector<uint256>& out) const
{
    if (leaf) return tapleaf_hash(leaf_version, script) == target;
    std::vector<uint256> sub;
    if (l->merkle_path(target, sub)) {
        out = std::move(sub);
        out.push_back(r->merkle_root());
        return true;
    }
    sub.clear();
    if (r->merkle_path(target, sub)) {
        out = std::move(sub);
        out.push_back(l->merkle_root());
        return true;
    }
    return false;
}

// ── taptweak / output key / address ───────────────────────────────────────
uint256 taptweak(const Bytes& internal_xonly, const uint256* merkle_root)
{
    std::vector<uint8_t> m(internal_xonly.begin(), internal_xonly.end());
    if (merkle_root) m.insert(m.end(), merkle_root->begin(), merkle_root->end());
    return tagged_hash("TapTweak", m);
}

bool tweak_output_key(const Bytes& internal_xonly, const uint256* merkle_root,
                      Bytes& out_q, int& q_parity)
{
    if (internal_xonly.size() != 32) return false;
    uint256 t = taptweak(internal_xonly, merkle_root);
    out_q.assign(32, 0);
    return Secp::instance().xonly_tweak_add(internal_xonly.data(), t.begin(),
                                            out_q.data(), &q_parity);
}

CScript p2tr_spk(const Bytes& q_xonly)
{
    if (q_xonly.size() != 32) throw std::runtime_error("p2tr_spk: Q must be 32-byte x-only");
    CScript s;
    s << OP_1 << q_xonly;
    return s;
}

P2TROutput build_p2tr(const Bytes& internal_xonly, const uint256* merkle_root,
                      const std::string& hrp)
{
    P2TROutput o;
    if (!tweak_output_key(internal_xonly, merkle_root, o.q_xonly, o.q_parity))
        throw std::runtime_error("build_p2tr: invalid internal key");
    o.spk = p2tr_spk(o.q_xonly);
    o.address = bech32m_address(hrp, 1, o.q_xonly);
    return o;
}

// bech32/bech32m per BIP173/BIP350 (self-contained; no vendored bech32 exists).
namespace {
const char* B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
uint32_t bech32_polymod(const std::vector<uint8_t>& values)
{
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}
std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp)
{
    std::vector<uint8_t> r;
    for (char c : hrp) r.push_back((uint8_t)c >> 5);
    r.push_back(0);
    for (char c : hrp) r.push_back((uint8_t)c & 31);
    return r;
}
// 8-bit -> 5-bit regrouping (pad).
bool convertbits_8to5(const Bytes& in, std::vector<uint8_t>& out)
{
    int acc = 0, bits = 0;
    for (uint8_t v : in) {
        acc = (acc << 8) | v;
        bits += 8;
        while (bits >= 5) { bits -= 5; out.push_back((acc >> bits) & 31); }
    }
    if (bits) out.push_back((acc << (5 - bits)) & 31);
    return true;
}
} // namespace

std::string bech32m_address(const std::string& hrp, int witver, const Bytes& program)
{
    std::vector<uint8_t> data;
    data.push_back((uint8_t)witver);
    convertbits_8to5(program, data);
    // checksum with bech32m constant 0x2bc830a3.
    std::vector<uint8_t> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (int i = 0; i < 6; ++i) values.push_back(0);
    uint32_t polymod = bech32_polymod(values) ^ 0x2bc830a3;
    for (int i = 0; i < 6; ++i) data.push_back((polymod >> (5 * (5 - i))) & 31);
    std::string out = hrp + "1";
    for (uint8_t d : data) out += B32[d];
    return out;
}

Bytes control_block(const Bytes& internal_xonly, int q_parity, uint8_t leaf_version,
                    const std::vector<uint256>& merkle_path)
{
    Bytes cb;
    cb.push_back((uint8_t)(leaf_version | (q_parity & 1)));
    cb.insert(cb.end(), internal_xonly.begin(), internal_xonly.end());
    for (const auto& h : merkle_path) cb.insert(cb.end(), h.begin(), h.end());
    return cb;
}

// ── tapscript multisig (OP_CHECKSIGADD) ─────────────────────────────────────
CScript checksigadd_multisig(int k, const std::vector<Bytes>& xonly_pubkeys)
{
    const int n = (int)xonly_pubkeys.size();
    if (k < 1 || k > n || n < 1) throw std::runtime_error("checksigadd: bad k/n");
    for (const auto& pk : xonly_pubkeys)
        if (pk.size() != 32) throw std::runtime_error("checksigadd: x-only keys are 32 bytes");
    CScript s;
    s << xonly_pubkeys[0] << OP_CHECKSIG;
    for (int i = 1; i < n; ++i) s << xonly_pubkeys[i] << (opcodetype)OP_CHECKSIGADD_BYTE;
    s << CScriptNum(k) << OP_NUMEQUAL;
    return s;
}

Witness checksigadd_witness(const std::vector<Bytes>& sigs_in_pubkey_order,
                            const CScript& leaf, const Bytes& control_block_bytes)
{
    Witness w;
    // pk1 is checked first, so its slot must sit on top of the stack — reverse.
    for (auto it = sigs_in_pubkey_order.rbegin(); it != sigs_in_pubkey_order.rend(); ++it)
        w.push_back(*it);
    w.push_back(Bytes(leaf.begin(), leaf.end()));
    w.push_back(control_block_bytes);
    return w;
}

std::vector<Bytes> combine_checksigadd(
    const std::vector<Bytes>& pubkeys,
    const std::vector<std::pair<Bytes, Bytes>>& partials)
{
    std::vector<Bytes> out;
    out.reserve(pubkeys.size());
    for (const auto& pk : pubkeys) {
        Bytes sig; // empty vector = unused-signer placeholder (§4.1)
        for (const auto& pr : partials)
            if (pr.first == pk) { sig = pr.second; break; }
        out.push_back(sig);
    }
    return out;
}

// ── BIP341/342 sighash ──────────────────────────────────────────────────────
uint256 taproot_sighash(const CMutableTransaction& tx,
                        const std::vector<SpentOutput>& prevouts,
                        unsigned int nIn, int hash_type, int ext_flag,
                        const uint256* tapleaf_h)
{
    const bool anyonecanpay = (hash_type & 0x80) != 0;
    const int out_type = hash_type & 0x03; // 0 DEFAULT ~ ALL, 1 ALL, 2 NONE, 3 SINGLE

    std::vector<uint8_t> ss;
    ss.push_back(0x00);                       // sighash epoch
    ss.push_back((uint8_t)hash_type);
    put_u32_le(ss, (uint32_t)(int32_t)tx.nVersion);
    put_u32_le(ss, (uint32_t)tx.nLockTime);

    if (!anyonecanpay) {
        std::vector<uint8_t> b;
        for (const auto& in : tx.vin) put_outpoint(b, in.prevout);
        Bytes h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());

        b.clear();
        for (const auto& po : prevouts) put_i64_le(b, po.amount);
        h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());

        b.clear();
        for (const auto& po : prevouts) put_var_script(b, po.spk);
        h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());

        b.clear();
        for (const auto& in : tx.vin) put_u32_le(b, in.nSequence);
        h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());
    }

    if (out_type != 0x02 && out_type != 0x03) { // ALL or DEFAULT
        std::vector<uint8_t> b;
        for (const auto& o : tx.vout) put_output(b, o);
        Bytes h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());
    }

    const uint8_t spend_type = (uint8_t)(ext_flag * 2); // annex bit 0 (unsupported here)
    ss.push_back(spend_type);

    if (anyonecanpay) {
        put_outpoint(ss, tx.vin[nIn].prevout);
        put_i64_le(ss, prevouts[nIn].amount);
        put_var_script(ss, prevouts[nIn].spk);
        put_u32_le(ss, tx.vin[nIn].nSequence);
    } else {
        put_u32_le(ss, nIn);
    }

    if (out_type == 0x03) { // SIGHASH_SINGLE: commit only the paired output
        std::vector<uint8_t> b;
        if (nIn < tx.vout.size()) put_output(b, tx.vout[nIn]);
        Bytes h = sha256_bytes(b); ss.insert(ss.end(), h.begin(), h.end());
    }

    if (ext_flag == 1) { // BIP342 tapscript extension
        if (!tapleaf_h) throw std::runtime_error("taproot_sighash: script path needs tapleaf hash");
        ss.insert(ss.end(), tapleaf_h->begin(), tapleaf_h->end());
        ss.push_back(0x00);          // key_version
        put_u32_le(ss, 0xffffffff);  // codesep_pos (none)
    }

    return tagged_hash("TapSighash", ss);
}

bool is_p2tr(const CScript& spk)
{
    return spk.size() == 34 && spk[0] == OP_1 && spk[1] == 0x20;
}

// ── minimal BIP341/342 verifier (self-verify-before-emit) ───────────────────
namespace {

// Verify one Schnorr sig (64 or 65 bytes; the 65th byte is the sighash type)
// under x-only `pk`, recomputing the script-path sighash for its declared type.
// Returns +1 valid, 0 empty sig (a legitimate CHECKSIGADD placeholder), -1 bad.
int check_tapscript_sig(const Bytes& sig, const Bytes& pk,
                        const CMutableTransaction& tx,
                        const std::vector<SpentOutput>& prevouts,
                        unsigned int nIn, const uint256& tapleaf_h)
{
    if (sig.empty()) return 0;
    if (pk.size() != 32) return -1; // we only build/verify 32-byte x-only keys
    int hash_type = 0x00; // SIGHASH_DEFAULT
    Bytes sig64;
    if (sig.size() == 64) {
        sig64 = sig;
    } else if (sig.size() == 65) {
        hash_type = sig.back();
        if (hash_type == 0x00) return -1; // explicit 0x00 is forbidden (use 64B)
        sig64.assign(sig.begin(), sig.begin() + 64);
    } else {
        return -1;
    }
    uint256 sh = taproot_sighash(tx, prevouts, nIn, hash_type, /*ext*/1, &tapleaf_h);
    return Secp::instance().schnorr_verify(pk.data(), sh.begin(), sig64) ? 1 : -1;
}

// A deliberately small tapscript evaluator covering exactly the leaf shapes this
// wallet builds: data pushes, OP_0/OP_1..OP_16, OP_CHECKSIG, OP_CHECKSIGADD,
// OP_NUMEQUAL/OP_NUMEQUALVERIFY, OP_CHECKSIGVERIFY. Anything else is refused
// (self-verify is conservative — an unrecognised leaf is not asserted valid).
std::string eval_tapscript(const CScript& leaf, std::vector<Bytes> stack,
                           const CMutableTransaction& tx,
                           const std::vector<SpentOutput>& prevouts,
                           unsigned int nIn, const uint256& tapleaf_h)
{
    CScript::const_iterator pc = leaf.begin();
    opcodetype op;
    std::vector<uint8_t> push;
    auto pop = [&](Bytes& out) -> bool {
        if (stack.empty()) return false;
        out = std::move(stack.back());
        stack.pop_back();
        return true;
    };
    while (pc != leaf.end()) {
        if (!leaf.GetOp(pc, op, push)) return "tapscript: malformed script";
        if (op <= OP_PUSHDATA4) {
            stack.push_back(push);
            continue;
        }
        if (op == OP_1NEGATE) { stack.push_back(Bytes{0x81}); continue; }
        if (op >= OP_1 && op <= OP_16) { stack.push_back(Bytes{(uint8_t)(op - OP_1 + 1)}); continue; }
        if (op == OP_0) { stack.push_back(Bytes{}); continue; }

        if (op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY) {
            Bytes pk, sig;
            if (!pop(pk) || !pop(sig)) return "tapscript: CHECKSIG stack underflow";
            int r = check_tapscript_sig(sig, pk, tx, prevouts, nIn, tapleaf_h);
            if (r < 0) return "tapscript: CHECKSIG signature invalid";
            if (op == OP_CHECKSIGVERIFY) {
                if (r != 1) return "tapscript: CHECKSIGVERIFY failed";
            } else {
                stack.push_back(r == 1 ? Bytes{0x01} : Bytes{});
            }
            continue;
        }
        if ((uint8_t)op == OP_CHECKSIGADD_BYTE) {
            Bytes pk, num, sig;
            if (!pop(pk) || !pop(num) || !pop(sig)) return "tapscript: CHECKSIGADD stack underflow";
            int64_t n = read_scriptnum(num);
            int r = check_tapscript_sig(sig, pk, tx, prevouts, nIn, tapleaf_h);
            if (r < 0) return "tapscript: CHECKSIGADD signature invalid";
            int64_t res = n + (r == 1 ? 1 : 0);
            Bytes enc;
            if (res != 0) { enc.push_back((uint8_t)(res & 0xff)); } // small non-negative counts
            stack.push_back(enc);
            continue;
        }
        if (op == OP_NUMEQUAL || op == OP_NUMEQUALVERIFY) {
            Bytes a, b;
            if (!pop(a) || !pop(b)) return "tapscript: NUMEQUAL stack underflow";
            bool eq = read_scriptnum(a) == read_scriptnum(b);
            if (op == OP_NUMEQUALVERIFY) {
                if (!eq) return "tapscript: NUMEQUALVERIFY failed";
            } else {
                stack.push_back(eq ? Bytes{0x01} : Bytes{});
            }
            continue;
        }
        return "tapscript: unsupported opcode in self-verify subset";
    }
    if (stack.empty()) return "tapscript: empty stack at end";
    // truthiness of the top element
    const Bytes& top = stack.back();
    for (size_t i = 0; i < top.size(); ++i) {
        if (top[i] != 0) {
            if (i == top.size() - 1 && top[i] == 0x80) return "tapscript: script left false (negative zero)";
            return {};
        }
    }
    return "tapscript: script left a false value";
}

} // namespace

std::string taproot_verify_input(const SpentOutput& prevout, const Witness& witness,
                                 const CMutableTransaction& tx,
                                 const std::vector<SpentOutput>& prevouts,
                                 unsigned int nIn)
{
    if (!is_p2tr(prevout.spk)) return "taproot verify: scriptPubKey is not a P2TR (OP_1 <32>)";
    Bytes Q(prevout.spk.begin() + 2, prevout.spk.end()); // 32-byte output key

    // Strip an optional annex (last element with prefix 0x50 when >1 element).
    Witness stack = witness;
    if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == 0x50)
        stack.pop_back();

    if (stack.empty()) return "taproot verify: empty witness";

    if (stack.size() == 1) {
        // key-path spend
        const Bytes& sig = stack[0];
        int hash_type = 0x00;
        Bytes sig64;
        if (sig.size() == 64) {
            sig64 = sig;
        } else if (sig.size() == 65) {
            hash_type = sig.back();
            if (hash_type == 0x00) return "taproot verify: 65-byte sig with explicit 0x00 type is invalid";
            sig64.assign(sig.begin(), sig.begin() + 64);
        } else {
            return "taproot verify: key-path sig must be 64 or 65 bytes";
        }
        uint256 sh = taproot_sighash(tx, prevouts, nIn, hash_type, /*ext*/0, nullptr);
        if (!Secp::instance().schnorr_verify(Q.data(), sh.begin(), sig64))
            return "taproot verify: key-path Schnorr signature does not verify under Q";
        return {};
    }

    // script-path spend: <inputs...> <leaf script> <control block>
    const Bytes& cb = stack.back();
    if (cb.size() < 33 || ((cb.size() - 33) % 32) != 0)
        return "taproot verify: control block length invalid";
    const uint8_t leaf_version = cb[0] & 0xfe;
    const int declared_parity = cb[0] & 0x01;
    Bytes P(cb.begin() + 1, cb.begin() + 33);
    std::vector<uint256> path;
    for (size_t off = 33; off < cb.size(); off += 32) {
        uint256 h; std::memcpy(h.begin(), cb.data() + off, 32); path.push_back(h);
    }
    CScript leaf(stack[stack.size() - 2].begin(), stack[stack.size() - 2].end());

    // Fold the merkle root from the leaf hash up the provided path.
    uint256 acc = tapleaf_hash(leaf_version, leaf);
    for (const auto& sib : path) acc = tapbranch_hash(acc, sib);

    // Recompute Q' from P + taptweak(P ‖ merkle_root); it must equal the output
    // key AND the parity bit in the control block must match.
    Bytes Qp; int q_parity = 0;
    if (!tweak_output_key(P, &acc, Qp, q_parity))
        return "taproot verify: internal key tweak failed";
    if (Qp != Q) return "taproot verify: control block does not commit to the output key (bad merkle path / internal key)";
    if (q_parity != declared_parity) return "taproot verify: control block parity bit mismatch";

    uint256 leaf_h = tapleaf_hash(leaf_version, leaf);
    std::vector<Bytes> inputs(stack.begin(), stack.end() - 2);
    return eval_tapscript(leaf, inputs, tx, prevouts, nIn, leaf_h);
}

} // namespace c2w::signer
