// SPDX-License-Identifier: AGPL-3.0-or-later
// Key-free half of the zero-fee sweep builder (planning, serialization and the
// loader-file emit). Lives in c2wallet-dash-common on the btclibs closure and
// touches no signing code; the signing half is SweepSign.cpp in c2wallet-dash-tx.
#include "SweepTx.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "UtxoIntake.hpp"

#include "../hdkeys/HexUtil.hpp"

#include <algorithm>

namespace c2w::dash {

namespace {

size_t compact_size_len(uint64_t n)
{
    if (n < 0xFD) return 1;
    if (n <= 0xFFFF) return 3;
    if (n <= 0xFFFFFFFFull) return 5;
    return 9;
}

void put_compact_size(std::vector<uint8_t>& v, uint64_t n)
{
    if (n < 0xFD) {
        v.push_back(static_cast<uint8_t>(n));
        return;
    }
    const int width = n <= 0xFFFF ? 2 : (n <= 0xFFFFFFFFull ? 4 : 8);
    v.push_back(width == 2 ? 0xFD : (width == 4 ? 0xFE : 0xFF));
    for (int i = 0; i < width; ++i) v.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
}

void put_le(std::vector<uint8_t>& v, uint64_t value, int nbytes)
{
    for (int i = 0; i < nbytes; ++i) v.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
}

// Estimated signed size of a sweep tx: n P2PKH inputs and one P2PKH output.
size_t est_sweep_bytes(size_t n, size_t per_input)
{
    return 4 + compact_size_len(n) + n * per_input + compact_size_len(1) + (8 + 1 + 25) + 4;
}

} // namespace

std::vector<uint8_t> serialize_unsigned_legacy_tx(
    const std::vector<Utxo>& inputs,
    const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outputs)
{
    std::vector<uint8_t> tx;
    tx.reserve(4 + 9 + inputs.size() * caps::kUnsignedInputBytes + 9 + outputs.size() * 43 + 4);
    put_le(tx, 2, 4); // version 2, type 0 (classic Dash tx)
    put_compact_size(tx, inputs.size());
    for (const Utxo& u : inputs) {
        auto txid = u.txid.size() == 64 ? hdkeys::from_hex(u.txid) : std::nullopt;
        if (!txid || txid->size() != 32)
            throw DashAbort("malformed UTXO entry: bad txid");
        tx.insert(tx.end(), txid->rbegin(), txid->rend()); // display -> internal order
        put_le(tx, u.vout, 4);
        tx.push_back(0x00); // empty scriptSig
        put_le(tx, caps::kSequenceFinal, 4);
    }
    put_compact_size(tx, outputs.size());
    for (const auto& [value, spk] : outputs) {
        put_le(tx, static_cast<uint64_t>(value), 8);
        put_compact_size(tx, spk.size());
        tx.insert(tx.end(), spk.begin(), spk.end());
    }
    put_le(tx, 0, 4); // locktime 0
    return tx;
}

size_t est_signed_size(size_t unsigned_bytes, size_t n_inputs, PubkeyEncoding encoding)
{
    return unsigned_bytes + n_inputs * (signed_input_bytes(encoding) - caps::kUnsignedInputBytes);
}

SweepBatchPlan plan_sweep(const SweepRequest& req)
{
    if (req.max_inputs_per_tx == 0 || req.max_inputs_per_tx > caps::kMaxInjectInputs)
        throw DashAbort("max_inputs_per_tx must be in [1, " +
                        std::to_string(caps::kMaxInjectInputs) +
                        "] (the node's inject input cap)");
    if (req.max_tx_bytes == 0 || req.max_tx_bytes > caps::kMaxInjectTxBytes)
        throw DashAbort("max_tx_bytes must be in [1, " + std::to_string(caps::kMaxInjectTxBytes) +
                        "] (the node's inject size cap)");
    if (req.dust_floor < 0)
        throw DashAbort("dust_floor must be >= 0");
    const bool relay = req.fee_mode == FeeMode::Relay;
    if (relay) {
        if (req.fee_rate_per_byte < kMinRelayFeePerByte || req.fee_rate_per_byte > kMaxRelayFeePerByte)
            throw DashAbort("RELAY sweep fee rate " + std::to_string(req.fee_rate_per_byte) +
                            " duffs/B is outside [" + std::to_string(kMinRelayFeePerByte) + ", " +
                            std::to_string(kMaxRelayFeePerByte) + "] (1 = dashd's minimum relay fee)");
    } else if (req.fee_rate_per_byte != 0) {
        throw DashAbort("a zero-fee (inject/pin) sweep needs fee rate 0 (got " +
                        std::to_string(req.fee_rate_per_byte) +
                        " duffs/B); a fee-paying sweep is FeeMode::Relay");
    }

    const std::array<uint8_t, 20> funding_h160 = addr_to_h160(req.funding_address, req.testnet);
    const std::string dest =
        req.destination_address.empty() ? req.funding_address : req.destination_address;
    const std::array<uint8_t, 25> dest_script = p2pkh_script(addr_to_h160(dest, req.testnet));
    const std::vector<uint8_t> dest_spk(dest_script.begin(), dest_script.end());

    UtxoScreen screen =
        screen_utxos(req.utxos, funding_h160, req.min_confirmations, req.dust_floor, true);
    if (screen.spendable.empty())
        throw DashAbort("nothing to sweep: every UTXO is immature (" +
                        std::to_string(screen.immature.size()) + ") or dust (" +
                        std::to_string(screen.dust.size()) + "). Nothing was built.");

    std::vector<Utxo> inputs = screen.spendable;
    if (!req.preserve_input_order) sort_by_outpoint(inputs);

    const size_t per_input = signed_input_bytes(req.key_encoding);
    if (est_sweep_bytes(1, per_input) > req.max_tx_bytes)
        throw DashAbort("max_tx_bytes " + std::to_string(req.max_tx_bytes) +
                        " cannot hold even one signed input");

    SweepBatchPlan plan;
    plan.funding_address = req.funding_address;
    plan.destination_address = dest;
    plan.testnet = req.testnet;
    plan.skipped_immature = screen.immature.size();
    plan.skipped_dust = screen.dust.size();
    plan.fee_mode = req.fee_mode;
    plan.fee_rate_per_byte = relay ? req.fee_rate_per_byte : 0;

    auto close_batch = [&](std::vector<Utxo>& batch) {
        SweepTxPlan tx;
        int64_t value_in = 0;
        for (const Utxo& u : batch) {
            if (__builtin_add_overflow(value_in, u.satoshis, &value_in) || value_in > kMaxMoney)
                throw DashAbort("sweep value exceeds MAX_MONEY — the UTXO amounts are not real");
        }
        const std::string label = "sweep tx " + std::to_string(plan.txs.size() + 1);
        // The signed size does not depend on the output value, so the fee is
        // known before the bytes are laid out.
        const size_t est = est_sweep_bytes(batch.size(), per_input);
        tx.fee = relay ? req.fee_rate_per_byte * static_cast<int64_t>(est) : 0;
        tx.value_out = value_in - tx.fee;
        if (relay && tx.fee > tx.value_out)
            throw DashAbort(label + ": the fee " + format_dash(tx.fee) + " DASH would exceed the " +
                            format_dash(tx.value_out) + " DASH it moves — raise dust_floor or "
                            "lower the fee rate. Nothing was built.");
        if (tx.value_out < kP2pkhDustDuffs)
            throw DashAbort(label + ": output " + std::to_string(tx.value_out) +
                            " duffs is below the P2PKH dust threshold (" +
                            std::to_string(kP2pkhDustDuffs) + "). Nothing was built.");
        tx.inputs = std::move(batch);
        tx.dest_spk = dest_spk;
        tx.unsigned_tx = serialize_unsigned_legacy_tx(tx.inputs, {{tx.value_out, dest_spk}});
        tx.est_signed_bytes =
            est_signed_size(tx.unsigned_tx.size(), tx.inputs.size(), req.key_encoding);
        if (tx.est_signed_bytes != est)
            throw DashAbort(label + ": internal size estimate disagrees with the serializer");
        plan.total_in += value_in;
        plan.total_fee += tx.fee;
        plan.txs.push_back(std::move(tx));
        batch.clear();
    };

    // Greedy split: a batch closes when one more input would cross either cap.
    std::vector<Utxo> batch;
    for (const Utxo& u : inputs) {
        if (!batch.empty() && (batch.size() + 1 > req.max_inputs_per_tx ||
                               est_sweep_bytes(batch.size() + 1, per_input) > req.max_tx_bytes))
            close_batch(batch);
        batch.push_back(u);
    }
    close_batch(batch);
    if (plan.total_in > kMaxMoney)
        throw DashAbort("sweep value exceeds MAX_MONEY — the UTXO amounts are not real");

    size_t est_total = 0;
    for (const SweepTxPlan& tx : plan.txs) est_total += tx.est_signed_bytes;

    std::string s;
    s += "======================================================================\n";
    s += std::string(relay ? "DASH FEE-PAYING SWEEP (RELAY)" : "DASH ZERO-FEE SWEEP (INJECT-ONLY)") +
         " -- DRY-RUN SUMMARY (" + (req.testnet ? "TESTNET" : "MAINNET") + ")\n";
    s += "======================================================================\n";
    s += "funding address:   " + req.funding_address + "\n";
    s += "destination:       " + dest + "\n";
    s += "inputs:            " + std::to_string(inputs.size()) + " mature UTXOs, " +
         format_dash(plan.total_in) + " DASH\n";
    for (size_t i = 0; i < plan.txs.size(); ++i) {
        const SweepTxPlan& tx = plan.txs[i];
        s += "tx " + std::to_string(i + 1) + "/" + std::to_string(plan.txs.size()) + ": " +
             std::to_string(tx.inputs.size()) + " inputs -> " + format_dash(tx.value_out) +
             " DASH, est signed " + std::to_string(tx.est_signed_bytes) + "/" +
             std::to_string(caps::kMaxInjectTxBytes) + " B" +
             (relay ? ", fee " + format_dash(tx.fee) + " DASH" : std::string()) + "\n";
    }
    if (relay) {
        s += "fee " + format_dash(plan.total_fee) + " DASH total (" + std::to_string(plan.total_fee) +
             " duffs = " + std::to_string(req.fee_rate_per_byte) +
             " duffs/B x est signed bytes; RELAY: submit with dash-cli sendrawtransaction)\n";
        s += "you receive:       " + format_dash(plan.total_in - plan.total_fee) + " DASH at " + dest +
             "\n";
        size_t uneconomic = 0;
        for (const Utxo& u : inputs)
            if (u.satoshis < req.fee_rate_per_byte * static_cast<int64_t>(per_input)) ++uneconomic;
        if (uneconomic)
            s += "WARNING: " + std::to_string(uneconomic) +
                 " input(s) carry less than the fee their own bytes cost; raise dust_floor to "
                 "leave them out.\n";
    } else {
        s += "fee 0.00000000 (INJECT-ONLY: Dash Core peers will not relay; rides only a c2pool "
             "block)\n";
    }
    s += describe_skipped(screen, req.min_confirmations, req.dust_floor);
    if (relay)
        s += "NOTE: legacy sighash commits no input amounts. If a UTXO amount above is\n"
             "      understated the difference is paid as extra fee; if it is overstated\n"
             "      dashd refuses the tx.\n";
    else
        s += "NOTE: legacy sighash commits no input amounts. If a UTXO amount above is\n"
             "      understated, the inject lane takes the difference as block fee and the\n"
             "      pin lane EXCLUDES the tx (fee-not-zero); if it is overstated the node\n"
             "      refuses the tx.\n";
    if (!relay && (plan.txs.size() > caps::kFullBatchesPerPool || est_total > caps::kMaxInjectTotalBytes))
        s += "WARNING: " + std::to_string(plan.txs.size()) + " txs / ~" +
             std::to_string(est_total) + " B exceed one node's inject pool (" +
             std::to_string(caps::kMaxInjectTotalBytes) + " B, " +
             std::to_string(caps::kMaxInjectPoolEntries) +
             " entries): submit them in rounds, or to several nodes.\n";
    s += "----------------------------------------------------------------------\n";
    s += relay ? "WARNING: this SPENDS REAL FUNDS and pays the fee above.\n"
               : "WARNING: this SPENDS REAL FUNDS. Only a c2pool block will confirm it.\n";
    s += "======================================================================\n";
    plan.summary = std::move(s);
    return plan;
}

std::string emit_inject_file(const std::vector<SignedTx>& txs)
{
    if (txs.empty())
        throw DashAbort("nothing to emit: no signed transaction");
    std::string out;
    for (size_t i = 0; i < txs.size(); ++i) {
        const std::string& h = txs[i].hex;
        const bool lower_hex = std::all_of(h.begin(), h.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
        if (h.empty() || h.size() % 2 != 0 || !lower_hex)
            throw DashAbort("signed tx " + std::to_string(i) +
                            " is not lowercase even-length hex — the c2pool loader would refuse "
                            "the whole file");
        out += h;
        out += '\n';
    }
    return out;
}

} // namespace c2w::dash
