// SPDX-License-Identifier: AGPL-3.0-or-later
// Signing half of the zero-fee sweep builder (SweepTx.hpp): sign a planned
// sweep, sign operator-supplied unsigned hex (c2wallet.py sign / sign-batch
// parity), and re-verify a signed funding-address spend. Lives in
// c2wallet-dash-tx on the dashscript closure, like CollateralTx.cpp; the
// key-free half (plan / emit / serialize) is SweepTx.cpp in c2wallet-dash-common.
#include "SweepTx.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

#include "../hdkeys/HexUtil.hpp" // std-only decl; from_hex/to_hex live in the hdkeys .a

// The M3-A signing core (vendored dashscript closure) and its std-only raw-tx
// parser. No btclibs header here.
#include "../signer/Scripts.hpp"
#include "../signer/SignSession.hpp"
#include "../signer/Signer.hpp"

#include <cstring>
#include <exception>

namespace c2w::dash {

namespace {

using signer::Bytes;

Bytes h160_bytes(const std::array<uint8_t, 20>& h) { return Bytes(h.begin(), h.end()); }

std::string trim(const std::string& s)
{
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string hex32(uint32_t v)
{
    static const char* d = "0123456789abcdef";
    std::string s = "0x";
    for (int i = 7; i >= 0; --i) s += d[(v >> (4 * i)) & 0xF];
    return s;
}

// The key must be the funding key: the address it was found for AND the
// hash160 of the pubkey it will push must both be the funding address's.
void bind_key(const FoundKey& key, const std::string& funding_address,
              const std::array<uint8_t, 20>& funding_h160)
{
    if (key.address != funding_address)
        throw DashAbort("the supplied key is for " + key.address + ", not the funding address " +
                        funding_address + " — refusing to sign");
    if (signer::hash160(key.pub) != h160_bytes(funding_h160))
        throw DashAbort("the supplied key's pubkey does not hash to the funding address — "
                        "refusing to sign");
}

// Sign every input (each spends the funding P2PKH) with the one key, then the
// mandatory finalize: self-verify every input through the vendored interpreter
// and refuse on oversize. The signed size is re-checked against the node cap.
SignedTx sign_all_inputs(signer::Signer& s, const CScript& funding_spk, const FoundKey& key,
                         const std::string& label)
{
    try {
        for (size_t i = 0; i < s.tx().vin.size(); ++i) {
            Bytes sig = s.make_legacy_sig(i, funding_spk, key.priv, SIGHASH_ALL);
            CScript scriptsig;
            scriptsig << sig << key.pub; // <sig‖hashtype> <pubkey>
            s.set_scriptsig(i, scriptsig);
        }
    } catch (const DashAbort&) {
        throw;
    } catch (const std::exception& e) {
        throw DashAbort(label + ": signing failed: " + e.what());
    }

    Bytes out;
    std::string err;
    if (!s.finalize(out, err))
        throw DashAbort(label + ": self-verify / oversize gate FAILED before emit: " + err);
    if (out.size() > caps::kMaxInjectTxBytes)
        throw DashAbort(label + ": signed size " + std::to_string(out.size()) +
                        " B exceeds the node's " + std::to_string(caps::kMaxInjectTxBytes) +
                        " B inject cap");

    SignedTx tx;
    tx.hex = hdkeys::to_hex(out);
    tx.txid = s.txid().GetHex();
    tx.size = out.size();
    return tx;
}

uint256 internal_txid(const Bytes& txid)
{
    uint256 h;
    std::memcpy(h.begin(), txid.data(), 32);
    return h;
}

} // namespace

std::vector<SignedTx> sign_sweep(const SweepBatchPlan& plan, const FoundKey& key,
                                 bool confirm_spend)
{
    // The typed-SPEND gate in library form: never auto-sign.
    if (!confirm_spend)
        throw DashAbort("not confirmed (confirm_spend=false); nothing was signed");
    if (plan.txs.empty())
        throw DashAbort("the sweep plan holds no tx; nothing was signed");

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(plan.funding_address, plan.testnet);
    bind_key(key, plan.funding_address, funding_h160);
    const CScript funding_spk = signer::p2pkh_from_h160(h160_bytes(funding_h160));
    const std::string dest =
        plan.destination_address.empty() ? plan.funding_address : plan.destination_address;
    const std::array<uint8_t, 25> dest_script = p2pkh_script(addr_to_h160(dest, plan.testnet));
    const Bytes dest_spk(dest_script.begin(), dest_script.end());

    const bool relay = plan.fee_mode == FeeMode::Relay;
    const PubkeyEncoding key_enc =
        key.compressed ? PubkeyEncoding::Compressed : PubkeyEncoding::Uncompressed;

    // Check every planned tx before signing any of them.
    for (size_t t = 0; t < plan.txs.size(); ++t) {
        const SweepTxPlan& tx = plan.txs[t];
        const std::string label = "sweep tx " + std::to_string(t + 1);
        if (tx.inputs.empty() || tx.inputs.size() > caps::kMaxInjectInputs)
            throw DashAbort(label + " has " + std::to_string(tx.inputs.size()) +
                            " inputs; it must have 1.." + std::to_string(caps::kMaxInjectInputs));
        if (tx.dest_spk != dest_spk)
            throw DashAbort(label + " does not pay the destination " + dest);
        int64_t sum = 0;
        for (const Utxo& u : tx.inputs)
            if (u.satoshis < 0 || __builtin_add_overflow(sum, u.satoshis, &sum) || sum > kMaxMoney)
                throw DashAbort(label + " input amounts are malformed");
        if (!relay) {
            if (tx.fee != 0 || sum != tx.value_out)
                throw DashAbort(label + " is not zero-fee (inputs " + std::to_string(sum) +
                                " != output " + std::to_string(tx.value_out) +
                                " duffs) — refusing to sign");
        } else {
            // Money range first, then the balance identity, then the fee ceiling
            // for THIS key's worst-case size (never the plan's own estimate).
            int64_t out_plus_fee = 0;
            if (tx.fee <= 0 || tx.fee > kMaxMoney || tx.value_out < kP2pkhDustDuffs ||
                tx.value_out > kMaxMoney ||
                __builtin_add_overflow(tx.value_out, tx.fee, &out_plus_fee) || out_plus_fee != sum)
                throw DashAbort(label + " does not balance as a relay tx (inputs " +
                                std::to_string(sum) + ", output " + std::to_string(tx.value_out) +
                                ", fee " + std::to_string(tx.fee) + " duffs) — refusing to sign");
            const size_t worst = est_signed_size(tx.unsigned_tx.size(), tx.inputs.size(), key_enc);
            if (tx.fee > kMaxRelayFeePerByte * static_cast<int64_t>(worst))
                throw DashAbort(label + " fee " + std::to_string(tx.fee) + " duffs is above " +
                                std::to_string(kMaxRelayFeePerByte) + " duffs/B x " +
                                std::to_string(worst) + " B — refusing to sign");
        }
    }

    std::vector<SignedTx> out;
    out.reserve(plan.txs.size());
    for (size_t t = 0; t < plan.txs.size(); ++t) {
        const SweepTxPlan& tx = plan.txs[t];
        const std::string label = "sweep tx " + std::to_string(t + 1);
        signer::Signer s(2, 0); // Dash classic (type-0) tx, version 2
        for (const Utxo& u : tx.inputs) {
            uint256 prev;
            prev.SetHex(u.txid.c_str());
            s.add_input(prev, u.vout, u.satoshis, funding_spk, caps::kSequenceFinal);
        }
        s.add_output(tx.value_out, CScript(tx.dest_spk.begin(), tx.dest_spk.end()));
        if (s.serialize(false) != tx.unsigned_tx)
            throw DashAbort(label + ": the tx about to be signed is not the planned one — "
                            "refusing to sign");
        SignedTx signed_tx = sign_all_inputs(s, funding_spk, key, label);
        if (relay && tx.fee < kMinRelayFeePerByte * static_cast<int64_t>(signed_tx.size))
            throw DashAbort(label + ": fee " + std::to_string(tx.fee) + " duffs is below dashd's " +
                            std::to_string(kMinRelayFeePerByte) + " duff/B minimum relay fee for " +
                            std::to_string(signed_tx.size) + " signed bytes");
        out.push_back(std::move(signed_tx));
    }
    return out;
}

std::vector<SignedTx> sign_external_unsigned(const std::vector<std::string>& raw_hexes,
                                             const std::string& funding_address,
                                             bool testnet,
                                             const FoundKey& key,
                                             bool confirm_spend)
{
    if (!confirm_spend)
        throw DashAbort("not confirmed (confirm_spend=false); nothing was signed");
    if (raw_hexes.empty())
        throw DashAbort("no unsigned tx given; nothing was signed");

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(funding_address, testnet);

    // Parse and validate EVERY blob before the key is used: a malformed file
    // found after the seed is typed wastes the one moment the operator holds it.
    struct Parsed {
        Bytes raw;
        sign::RawTxView view;
    };
    std::vector<Parsed> parsed;
    for (size_t i = 0; i < raw_hexes.size(); ++i) {
        const std::string label = "unsigned tx " + std::to_string(i + 1);
        auto raw = hdkeys::from_hex(trim(raw_hexes[i]));
        if (!raw || raw->empty())
            throw DashAbort(label + " is not hex");
        Parsed p;
        p.raw = std::move(*raw);
        std::string err;
        if (!sign::parse_raw_legacy_tx(p.raw, p.view, err))
            throw DashAbort(label + ": " + err);
        const sign::RawTxView& v = p.view;
        const uint32_t version = static_cast<uint32_t>(v.version);
        if ((version >> 16) != 0)
            throw DashAbort(label + " is a special tx (type " + std::to_string(version >> 16) +
                            "); only classic type-0 txs are signed here");
        if (version != 2)
            throw DashAbort(label + " has version " + std::to_string(version) +
                            "; only version 2 is signed here");
        if (v.vout.empty())
            throw DashAbort(label + " has no outputs");
        if (v.vin.size() > caps::kMaxInjectInputs || v.vout.size() > caps::kMaxInjectOutputs)
            throw DashAbort(label + " has " + std::to_string(v.vin.size()) + " inputs / " +
                            std::to_string(v.vout.size()) + " outputs, over the node's inject "
                            "caps of " + std::to_string(caps::kMaxInjectInputs) + " / " +
                            std::to_string(caps::kMaxInjectOutputs));
        for (size_t k = 0; k < v.vin.size(); ++k) {
            if (!v.vin[k].scriptsig.empty())
                throw DashAbort(label + " input " + std::to_string(k) +
                                " already carries a scriptSig — expected a fully unsigned tx");
            if ((v.vin[k].seq & caps::kSequenceLocktimeDisableFlag) == 0)
                throw DashAbort(label + " input " + std::to_string(k) + " sequence " +
                                hex32(v.vin[k].seq) +
                                " has bit 31 clear (a BIP68 relative lock): the node's inject "
                                "gate refuses it");
        }
        parsed.push_back(std::move(p));
    }

    bind_key(key, funding_address, funding_h160);
    const CScript funding_spk = signer::p2pkh_from_h160(h160_bytes(funding_h160));

    std::vector<SignedTx> out;
    out.reserve(parsed.size());
    for (size_t i = 0; i < parsed.size(); ++i) {
        const std::string label = "unsigned tx " + std::to_string(i + 1);
        const sign::RawTxView& v = parsed[i].view;
        signer::Signer s(v.version, v.locktime);
        // Legacy sighash commits no input amounts, so 0 stands in for each.
        for (const auto& in : v.vin)
            s.add_input(internal_txid(in.txid), in.index, 0, funding_spk, in.seq);
        for (const auto& o : v.vout) s.add_output(o.value, CScript(o.spk.begin(), o.spk.end()));
        if (s.serialize(false) != parsed[i].raw)
            throw DashAbort(label + " does not re-serialize byte-exact — refusing to sign");
        out.push_back(sign_all_inputs(s, funding_spk, key, label));
    }
    return out;
}

void verify_signed_funding_tx(const std::string& signed_hex,
                              const std::string& funding_address,
                              bool testnet)
{
    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(funding_address, testnet);
    const CScript funding_spk = signer::p2pkh_from_h160(h160_bytes(funding_h160));

    auto raw = hdkeys::from_hex(trim(signed_hex));
    if (!raw || raw->empty())
        throw DashAbort("signed tx is not hex");
    sign::RawTxView v;
    std::string err;
    if (!sign::parse_raw_legacy_tx(*raw, v, err))
        throw DashAbort("signed tx: " + err);

    signer::Signer s(v.version, v.locktime);
    for (const auto& in : v.vin)
        s.add_input(internal_txid(in.txid), in.index, 0, funding_spk, in.seq);
    for (const auto& o : v.vout) s.add_output(o.value, CScript(o.spk.begin(), o.spk.end()));
    for (size_t i = 0; i < v.vin.size(); ++i) {
        if (v.vin[i].scriptsig.empty())
            throw DashAbort("signed tx input " + std::to_string(i) + " is not signed");
        s.set_scriptsig(i, CScript(v.vin[i].scriptsig.begin(), v.vin[i].scriptsig.end()));
    }
    if (s.serialize(false) != *raw)
        throw DashAbort("signed tx does not re-serialize byte-exact");
    for (size_t i = 0; i < v.vin.size(); ++i) {
        const signer::SelfVerifyResult r = s.verify_input(i);
        if (!r.ok)
            throw DashAbort("signed tx input " + std::to_string(i) + " fails verification: " +
                            r.error);
    }
}

} // namespace c2w::dash
