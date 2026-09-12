// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Signer.hpp"

#include "Bip143.hpp"
#include "Crypto.hpp"
#include "Taproot.hpp"

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <script/script_error.h>

#include <cstring>
#include <stdexcept>

namespace c2w::signer {

// ── a minimal write-only stream backed by a byte vector (the vendored
//    serialize.h Serialize()/WriteCompactSize() write through this) ──────────
namespace {
struct VecWriter {
    Bytes& v;
    void write(Span<const std::byte> s) {
        const auto* p = reinterpret_cast<const unsigned char*>(s.data());
        v.insert(v.end(), p, p + s.size());
    }
    template <typename T> VecWriter& operator<<(const T& obj) { ::Serialize(*this, obj); return *this; }
    int GetType() const { return 0; }
    int GetVersion() const { return 0; }
};

// BIP340 deterministic-nonce auxiliary value. A FIXED input (not an RNG) so the
// signature is reproducible; §5.3 forbids a custom RNG in the signing path, and
// the BIP341 published vectors were generated with an all-zero aux.
static const uint8_t TAPROOT_AUX[32] = {0};

bool CastToBool(const std::vector<unsigned char>& vch) {
    for (size_t i = 0; i < vch.size(); ++i) {
        if (vch[i] != 0) {
            if (i == vch.size() - 1 && vch[i] == 0x80) return false; // negative zero
            return true;
        }
    }
    return false;
}

bool is_p2wpkh_program(const CScript& spk) {
    return spk.size() == 22 && spk[0] == 0x00 && spk[1] == 0x14;
}
bool is_p2wsh_program(const CScript& spk) {
    return spk.size() == 34 && spk[0] == 0x00 && spk[1] == 0x20;
}
bool is_p2sh(const CScript& spk) {
    return spk.size() == 23 && spk[0] == OP_HASH160 && spk[1] == 0x14 && spk[22] == OP_EQUAL;
}

// Segwit-v0 self-verify: drive the vendored EvalScript with the BIP143 checker.
std::string eval_witness_v0(const CScript& program, const Witness& witness,
                            const CMutableTransaction& tx, unsigned int nIn, int64_t amount) {
    const unsigned int flags = SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S |
                               SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_STRICTENC;
    Bip143SignatureChecker checker(tx, nIn, amount);

    if (is_p2wpkh_program(program)) {
        if (witness.size() != 2) return "P2WPKH witness must be <sig> <pubkey>";
        const Bytes& pubkey = witness[1];
        if (pubkey.size() != 33) return "P2WPKH requires a compressed pubkey (WITNESS_PUBKEYTYPE)";
        if (hash160(pubkey) != Bytes(program.begin() + 2, program.end()))
            return "P2WPKH pubkey does not match the program hash160";
        CScript scriptCode = p2wpkh_scriptcode(pubkey);
        std::vector<std::vector<unsigned char>> stack{witness[0], witness[1]};
        ScriptError err;
        if (!EvalScript(stack, scriptCode, flags, checker, SigVersion::BASE, &err))
            return std::string("P2WPKH eval failed: ") + ScriptErrorString(err);
        if (stack.empty() || !CastToBool(stack.back())) return "P2WPKH eval left a false stack";
        return {};
    }
    if (is_p2wsh_program(program)) {
        if (witness.empty()) return "P2WSH witness is empty";
        CScript witnessScript(witness.back().begin(), witness.back().end());
        Bytes ws(witnessScript.begin(), witnessScript.end());
        if (sha256(ws) != Bytes(program.begin() + 2, program.end()))
            return "P2WSH witnessScript does not match the program sha256";
        std::vector<std::vector<unsigned char>> stack(witness.begin(), witness.end() - 1);
        ScriptError err;
        if (!EvalScript(stack, witnessScript, flags, checker, SigVersion::BASE, &err))
            return std::string("P2WSH eval failed: ") + ScriptErrorString(err);
        if (stack.empty() || !CastToBool(stack.back())) return "P2WSH eval left a false stack";
        return {};
    }
    return "unrecognised witness v0 program";
}
} // namespace

Signer::Signer(int32_t version, uint32_t locktime)
{
    tx_.nVersion = (int16_t)version;
    tx_.nType = 0; // TRANSACTION_NORMAL — a plain Bitcoin-family tx, no Dash payload
    tx_.nLockTime = locktime;
}

size_t Signer::add_input(const uint256& prevhash, uint32_t n, int64_t amount,
                         const CScript& scriptPubKey, uint32_t sequence)
{
    CTxIn in;
    in.prevout = COutPoint(prevhash, n);
    in.nSequence = sequence;
    tx_.vin.push_back(in);
    prevouts_.push_back({scriptPubKey, amount});
    witnesses_.push_back({});
    return tx_.vin.size() - 1;
}

void Signer::add_output(int64_t value, const CScript& scriptPubKey)
{
    CTxOut out;
    out.nValue = value;
    out.scriptPubKey = scriptPubKey;
    tx_.vout.push_back(out);
}

std::vector<SpentOutput> Signer::spent_outputs() const
{
    std::vector<SpentOutput> v;
    v.reserve(prevouts_.size());
    for (const auto& po : prevouts_) v.push_back({po.spk, po.amount});
    return v;
}

uint256 Signer::legacy_sighash(size_t nIn, const CScript& scriptCode, int nHashType)
{
    if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn >= tx_.vout.size()) {
        warnings_.push_back(
            "SIGHASH_SINGLE bug: input index >= number of outputs; the legacy "
            "digest is the constant 0x0000..0001 (reproduced for parity).");
    }
    return SignatureHash(scriptCode, tx_, (unsigned int)nIn, nHashType, /*amount*/(int64_t)0,
                         SigVersion::BASE);
}

uint256 Signer::bip143_sighash_for(size_t nIn, const CScript& scriptCode,
                                   int64_t amount, int nHashType)
{
    return bip143_sighash(tx_, (unsigned int)nIn, scriptCode, amount, nHashType);
}

uint256 Signer::taproot_sighash_keypath(size_t nIn, int nHashType)
{
    return taproot_sighash(tx_, spent_outputs(), (unsigned int)nIn, nHashType, /*ext*/0, nullptr);
}

uint256 Signer::taproot_sighash_scriptpath(size_t nIn, int nHashType, const uint256& tapleaf_h)
{
    return taproot_sighash(tx_, spent_outputs(), (unsigned int)nIn, nHashType, /*ext*/1, &tapleaf_h);
}

Bytes Signer::make_legacy_sig(size_t nIn, const CScript& scriptCode,
                              const secure::SecureBytes& sk, int nHashType)
{
    if (sk.size() != 32) throw std::runtime_error("private key must be 32 bytes");
    uint256 h = legacy_sighash(nIn, scriptCode, nHashType);
    Bytes der = Secp::instance().sign_ecdsa_der(sk.data(), h.begin());
    if (der.empty()) throw std::runtime_error("ECDSA sign failed");
    der.push_back((uint8_t)nHashType);
    return der;
}

Bytes Signer::make_bip143_sig(size_t nIn, const CScript& scriptCode, int64_t amount,
                              const secure::SecureBytes& sk, int nHashType)
{
    if (sk.size() != 32) throw std::runtime_error("private key must be 32 bytes");
    uint256 h = bip143_sighash_for(nIn, scriptCode, amount, nHashType);
    Bytes der = Secp::instance().sign_ecdsa_der(sk.data(), h.begin());
    if (der.empty()) throw std::runtime_error("ECDSA sign failed");
    der.push_back((uint8_t)nHashType);
    return der;
}

Bytes Signer::make_taproot_keypath_sig(size_t nIn, const secure::SecureBytes& d,
                                       const uint256* merkle_root, int nHashType)
{
    if (d.size() != 32) throw std::runtime_error("private key must be 32 bytes");
    // taptweak commits to the x-only INTERNAL key P (derived from d).
    uint8_t p_xonly[32]; int parity = 0;
    if (!Secp::instance().xonly_pubkey(d.data(), p_xonly, &parity))
        throw std::runtime_error("taproot: invalid internal key");
    Bytes p(p_xonly, p_xonly + 32);
    uint256 tweak = taptweak(p, merkle_root);
    uint256 h = taproot_sighash_keypath(nIn, nHashType);
    Bytes sig = Secp::instance().schnorr_sign_tweaked(d.data(), tweak.begin(), h.begin(), TAPROOT_AUX);
    if (sig.empty()) throw std::runtime_error("taproot key-path Schnorr sign failed");
    if (nHashType != SIGHASH_DEFAULT) sig.push_back((uint8_t)nHashType);
    return sig;
}

Bytes Signer::make_taproot_scriptpath_sig(size_t nIn, const CScript& leaf, uint8_t leafver,
                                          const secure::SecureBytes& leaf_key, int nHashType)
{
    if (leaf_key.size() != 32) throw std::runtime_error("private key must be 32 bytes");
    uint256 lh = tapleaf_hash(leafver, leaf);
    uint256 h = taproot_sighash_scriptpath(nIn, nHashType, lh);
    Bytes sig = Secp::instance().schnorr_sign(leaf_key.data(), h.begin(), TAPROOT_AUX);
    if (sig.empty()) throw std::runtime_error("taproot script-path Schnorr sign failed");
    if (nHashType != SIGHASH_DEFAULT) sig.push_back((uint8_t)nHashType);
    return sig;
}

void Signer::set_scriptsig(size_t nIn, const CScript& s) { tx_.vin[nIn].scriptSig = s; }
void Signer::set_witness(size_t nIn, const Witness& w) { witnesses_[nIn] = w; }

bool Signer::has_witness() const
{
    for (const auto& w : witnesses_) if (!w.empty()) return true;
    return false;
}

SelfVerifyResult Signer::verify_input(size_t nIn) const
{
    const Prevout& po = prevouts_[nIn];
    const Witness& wit = witnesses_[nIn];

    if (wit.empty()) {
        // Legacy: full VerifyScript (independent re-derivation of the sighash).
        const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG |
                                   SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLDUMMY |
                                   SCRIPT_VERIFY_STRICTENC;
        MutableTransactionSignatureChecker checker(&tx_, (unsigned int)nIn, po.amount,
                                                   MissingDataBehavior::FAIL);
        ScriptError err;
        if (!VerifyScript(tx_.vin[nIn].scriptSig, po.spk, flags, checker, &err))
            return {false, std::string("legacy VerifyScript failed: ") + ScriptErrorString(err)};
        return {true, {}};
    }

    // Taproot (BIP341/342): the vendored interpreter is BASE-only, so verify via
    // the minimal in-module verifier (re-derive sighash + libsecp Schnorr).
    if (is_p2tr(po.spk)) {
        std::string e = taproot_verify_input({po.spk, po.amount}, wit, tx_, spent_outputs(),
                                             (unsigned int)nIn);
        if (!e.empty()) return {false, e};
        return {true, {}};
    }

    // Segwit v0: resolve the witness program (native or P2SH-nested).
    CScript program;
    if (is_p2wpkh_program(po.spk) || is_p2wsh_program(po.spk)) {
        program = po.spk;
    } else if (is_p2sh(po.spk)) {
        // scriptSig must be a single push of the witness program.
        CScript::const_iterator it = tx_.vin[nIn].scriptSig.begin();
        opcodetype op;
        std::vector<unsigned char> pushed;
        if (!tx_.vin[nIn].scriptSig.GetOp(it, op, pushed) || pushed.empty())
            return {false, "P2SH-wrapped segwit: scriptSig must push the witness program"};
        if (it != tx_.vin[nIn].scriptSig.end())
            return {false, "P2SH-wrapped segwit: scriptSig must be exactly one push"};
        if (hash160(pushed) != Bytes(po.spk.begin() + 2, po.spk.begin() + 22))
            return {false, "P2SH-wrapped segwit: program hash160 mismatch"};
        program = CScript(pushed.begin(), pushed.end());
    } else {
        return {false, "input has a witness but the scriptPubKey is not a segwit/P2SH/taproot program"};
    }

    std::string e = eval_witness_v0(program, wit, tx_, (unsigned int)nIn, po.amount);
    if (!e.empty()) return {false, e};
    return {true, {}};
}

Bytes Signer::serialize(bool with_witness) const
{
    Bytes out;
    VecWriter w{out};
    const int32_t version = (int32_t)((uint16_t)tx_.nVersion | ((uint32_t)tx_.nType << 16));
    w << version;
    if (with_witness) {
        uint8_t marker = 0x00, flag = 0x01; // BIP144
        w << marker << flag;
    }
    w << tx_.vin;
    w << tx_.vout;
    if (with_witness) {
        for (size_t i = 0; i < tx_.vin.size(); ++i) {
            WriteCompactSize(w, witnesses_[i].size());
            for (const auto& item : witnesses_[i]) w << item;
        }
    }
    w << (uint32_t)tx_.nLockTime;
    return out;
}

uint256 Signer::txid() const
{
    Bytes b = serialize(/*with_witness*/false);
    uint256 h;
    CHash256().Write(MakeUCharSpan(b)).Finalize(Span<unsigned char>{h.begin(), 32});
    return h;
}

bool Signer::finalize(Bytes& out, std::string& err) const
{
    for (size_t i = 0; i < tx_.vin.size(); ++i) {
        SelfVerifyResult r = verify_input(i);
        if (!r.ok) {
            err = "self-verify-before-emit REFUSED input " + std::to_string(i) + ": " + r.error;
            return false;
        }
    }
    Bytes b = serialize(has_witness());
    if (b.size() > MAX_TX_SIZE) {
        err = "oversize refusal: serialized tx is " + std::to_string(b.size()) +
              " bytes > " + std::to_string(MAX_TX_SIZE);
        return false;
    }
    out = std::move(b);
    return true;
}

std::vector<Bytes> Signer::order_multisig_sigs(
    const std::vector<Bytes>& pubkeys,
    const std::vector<std::pair<Bytes, Bytes>>& partials)
{
    std::vector<Bytes> ordered;
    for (const auto& pk : pubkeys) {
        for (const auto& pr : partials) {
            if (pr.first == pk) { ordered.push_back(pr.second); break; }
        }
    }
    return ordered;
}

CScript Signer::multisig_scriptsig(const std::vector<Bytes>& ordered_sigs, const CScript* redeem)
{
    CScript s;
    s << OP_0; // NULLDUMMY: an EMPTY push, never OP_1 (§4.1)
    for (const auto& sig : ordered_sigs) s << sig;
    if (redeem) s << Bytes(redeem->begin(), redeem->end());
    return s;
}

Witness Signer::multisig_witness(const std::vector<Bytes>& ordered_sigs, const CScript& witnessScript)
{
    Witness w;
    w.push_back(Bytes{}); // leading empty element = the NULLDUMMY dummy
    for (const auto& sig : ordered_sigs) w.push_back(sig);
    w.push_back(Bytes(witnessScript.begin(), witnessScript.end()));
    return w;
}

} // namespace c2w::signer
