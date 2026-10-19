// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// Shared DASH v36 share test fixture: the canonical fully-populated
// DashV36Share and hex helpers. Used by test_dash_v36_share.cpp (wire-format
// KATs) and test_dash_v36_ref_stream_verify.cpp (ref-stream / verifier KATs),
// so both pin the SAME share. Test-only; anonymous namespace per TU.

#include <impl/dash/share.hpp>         // dash::DashV36Share
#include <impl/dash/share_types.hpp>   // dash::PackedPayment, dash::v36::*

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <span>
#include <string>
#include <vector>

namespace {

inline std::string to_hex(const std::span<const unsigned char> bytes)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) { out.push_back(h[b >> 4]); out.push_back(h[b & 0xf]); }
    return out;
}

inline std::string pack_hex(const PackStream& ps)
{
    auto& m = const_cast<PackStream&>(ps);
    return to_hex(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(m.data()), m.size()));
}

// A canonical, fully-populated DASH v36 share. Distinctive scalar values so a
// misordered/misencoded field is visible; merged fields left EMPTY (DASH is
// standalone X11 — no AuxPoW child), DASH suffix populated.
inline dash::DashV36Share make_canonical_v36()
{
    dash::DashV36Share s;
    s.m_min_header.m_version = 2;
    s.m_min_header.m_previous_block.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000aa");
    s.m_min_header.m_timestamp = 0x11223344;
    s.m_min_header.m_bits = 0x1e0ffff0;
    s.m_min_header.m_nonce = 0x55667788;

    s.m_prev_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    s.m_coinbase = BaseScript(std::vector<unsigned char>{0xab, 0xcd});
    s.m_nonce = 0x0a0b0c0d;
    s.m_pubkey_hash.SetHex("00000000000000000000000000000000deadbeef");
    s.m_pubkey_type = 0;                 // DASH always P2PKH
    s.m_subsidy = 5000000000ULL;         // > 2^32 => 9-byte VarInt
    s.m_donation = 0x1234;
    s.m_stale_info = dash::StaleInfo::none;
    s.m_desired_version = 36;            // the version-vote

    // merged_addresses: EMPTY (inert)
    s.m_far_share_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000002");
    s.m_max_bits = 0x1e0fffff;
    s.m_bits = 0x1d00ffff;
    s.m_timestamp = 0x99aabbcc;
    s.m_absheight = 0x00010203;
    s.m_abswork = uint128(0x0102030405060708ULL);

    // merged_coinbase_info: EMPTY (inert); merged_payout_hash: zero (inert)
    s.m_last_txout_nonce = 0xdeadbeefcafef00dULL;
    s.m_hash_link.m_state.m_data.assign(32, 0x00);
    for (int i = 0; i < 32; ++i) s.m_hash_link.m_state.m_data[i] = static_cast<unsigned char>(i);
    s.m_hash_link.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
    s.m_hash_link.m_length = 128;
    // ref_merkle_link / merkle_link: empty branches
    // message_data: EMPTY (Phase A — messaging is Phase B)

    // ── DASH suffix ──
    s.m_coinbase_payload = BaseScript(std::vector<unsigned char>{0x01, 0x02});
    s.m_payment_amount = 0x00000000abcdef01ULL;
    s.m_packed_payments.push_back(dash::PackedPayment{"!6a0401020304", 12345});
    s.m_coinbase_payload_outer = BaseScript(std::vector<unsigned char>{0x02, 0x01, 0x02});
    return s;
}

} // namespace
