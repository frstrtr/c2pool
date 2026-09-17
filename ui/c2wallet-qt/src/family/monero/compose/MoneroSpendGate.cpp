// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/compose/MoneroSpendGate.cpp
// ---------------------------------------------------------------------------
#include "family/monero/compose/MoneroSpendGate.hpp"

#include <cstdio>

#include "secure/SecureString.hpp"   // c2w::secure::secure_wipe

namespace c2wallet::monero::compose {

std::string format_xmr(std::uint64_t pico)
{
    const std::uint64_t whole = pico / PICO_PER_XMR;
    const std::uint64_t frac  = pico % PICO_PER_XMR;   // 0 .. 999999999999
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%012llu", static_cast<unsigned long long>(frac));
    return std::to_string(whole) + "." + buf;
}

std::string both_units(std::uint64_t pico)
{
    return format_xmr(pico) + " XMR (" + std::to_string(pico) + " pico)";
}

bool parse_xmr(const std::string& s_in, std::uint64_t& pico, std::string& err)
{
    // trim surrounding whitespace
    std::size_t a = s_in.find_first_not_of(" \t\r\n");
    std::size_t b = s_in.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) { err = "empty amount"; return false; }
    const std::string s = s_in.substr(a, b - a + 1);

    std::string whole = s, frac;
    const std::size_t dot = s.find('.');
    if (dot != std::string::npos) {
        whole = s.substr(0, dot);
        frac  = s.substr(dot + 1);
        if (frac.find('.') != std::string::npos) { err = "more than one decimal point"; return false; }
    }
    if (whole.empty() && frac.empty()) { err = "no digits"; return false; }
    if (frac.size() > 12) { err = "more than 12 decimal places (sub-piconero)"; return false; }

    auto digits_ok = [](const std::string& t) {
        for (char c : t) if (c < '0' || c > '9') return false;
        return true;
    };
    if (!digits_ok(whole) || !digits_ok(frac)) { err = "amount has a non-numeric character"; return false; }

    // pad the fractional part to exactly 12 digits (piconero).
    frac.append(12 - frac.size(), '0');

    // integer-only: pico = whole * 1e12 + frac, with overflow checks.
    std::uint64_t w = 0;
    for (char c : whole) {
        if (w > (UINT64_MAX - 9) / 10) { err = "amount too large"; return false; }
        w = w * 10 + std::uint64_t(c - '0');
    }
    std::uint64_t f = 0;
    for (char c : frac) f = f * 10 + std::uint64_t(c - '0');   // <= 999999999999, no overflow

    if (w > UINT64_MAX / PICO_PER_XMR) { err = "amount too large"; return false; }
    const std::uint64_t hi = w * PICO_PER_XMR;
    if (hi > UINT64_MAX - f) { err = "amount too large"; return false; }
    pico = hi + f;
    return true;
}

bool decode_dest(const std::string& addr, Network expected_net,
                 DecodedDest& out, std::string& err)
{
    MoneroAddress a;
    if (!address_decode(addr, a, err)) return false;   // err set by the codec
    if (a.net != expected_net) {
        const char* want = expected_net == Network::Mainnet ? "mainnet"
                         : expected_net == Network::Testnet ? "testnet" : "stagenet";
        const char* got  = a.net == Network::Mainnet ? "mainnet"
                         : a.net == Network::Testnet ? "testnet" : "stagenet";
        err = std::string("address network mismatch: this is a ") + got
            + " address but the transaction is being built for " + want;
        return false;
    }
    out.type                = a.type;
    out.has_payment_id      = a.has_payment_id;
    out.payment_id          = a.payment_id;
    out.dest.spend_pub      = a.spend_pub;
    out.dest.view_pub       = a.view_pub;
    out.dest.is_subaddress  = (a.type == AddressType::Subaddress);
    out.dest.amount         = 0;   // caller fills
    return true;
}

bool balance_ok(const std::vector<artifact::UnsignedTxSource>& sources,
                const std::vector<prover::TxDestination>& dests,
                std::uint64_t fee,
                std::uint64_t& sum_in, std::uint64_t& sum_out)
{
    sum_in = 0; sum_out = 0;
    for (const auto& s : sources) {
        if (s.amount > UINT64_MAX - sum_in) return false;   // overflow => not balanced
        sum_in += s.amount;
    }
    for (const auto& d : dests) {
        if (d.amount > UINT64_MAX - sum_out) return false;
        sum_out += d.amount;
    }
    if (fee > UINT64_MAX - sum_out) return false;
    return sum_in == sum_out + fee;
}

Ownership classify_dest(const prover::TxDestination& d, const MoneroKeys& keys,
                        const SubaddressTable& subs)
{
    // Primary / standard account (0,0): K_v = k_v * G == keys.view_pub. Both
    // keys bound.
    if (d.spend_pub == keys.spend_pub && d.view_pub == keys.view_pub)
        return Ownership::Own;
    // A subaddress (i,j) we derived: the spend-pub is in our table AND its view
    // key satisfies K_v^(i,j) == k_v * K_s^(i,j) (the same relation
    // derive_subaddress uses). BINDING SPEND-PUB ALONE burns a swapped-view-key
    // change output; require the view relation too.
    SubaddressTable::Entry e;
    if (subs.lookup(d.spend_pub, e)) {
        Bytes32 expect_view{};
        if (mcrypto::point_scalarmult(keys.view_priv, d.spend_pub, expect_view)
            && expect_view == d.view_pub)
            return Ownership::Own;
    }
    return Ownership::External;
}

bool dest_supported(bool is_subaddress, bool has_payment_id, std::string& reason)
{
    if (is_subaddress) {
        reason = "subaddress outputs need per-output tx keys — not supported by this signer yet";
        return false;
    }
    if (has_payment_id) {
        reason = "integrated / payment-id outputs need the pid encrypted under the tx key — "
                 "not supported by this signer yet";
        return false;
    }
    return true;
}

void wipe_spend_inputs(std::vector<prover::SpendInput>& v)
{
    for (auto& si : v) {
        c2w::secure::secure_wipe(si.one_time_sec.data(), si.one_time_sec.size());
        c2w::secure::secure_wipe(si.amount_mask.data(), si.amount_mask.size());
    }
}

} // namespace c2wallet::monero::compose
