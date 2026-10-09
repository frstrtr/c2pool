// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_epee_budget_kat.cpp
//
// The epee portable-storage decoder's MESSAGE-WIDE array-element budget. The
// per-array cap bounds one array, but several arrays each just under it can sum
// to an allocation far larger than the body; the decoder must also bound the
// total element count across the whole message and refuse before allocating.
//   EB1  array_elements_over_total : two arrays each under the per-array cap,
//        summing over it, are refused with ArrayTooLarge.
//   EB2  array_elements_under_total : a single array under the cap decodes.
// STL-only. No test framework, matching the neighbouring C1a KATs.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/epee_storage.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace epee = c2pool::xmr::native::epee;
namespace kat  = c2pool::xmr::native::kat;

namespace {

// The default per-array / per-message element ceiling.
constexpr std::size_t kCap = 262144;

epee::Value u8_array(std::size_t n) {
    std::vector<epee::Value> elems;
    elems.reserve(n);
    for (std::size_t i = 0; i < n; ++i) elems.push_back(epee::v_u8(static_cast<std::uint8_t>(i & 0xff)));
    return epee::v_array(epee::Type::Uint8, std::move(elems));
}

std::vector<std::uint8_t> encode_root(std::vector<epee::Entry> entries) {
    epee::Value root = epee::v_object(std::move(entries));
    std::vector<std::uint8_t> out;
    epee::StorageError err = epee::StorageError::None;
    epee::write_storage(root, out, err);   // encoder has no element cap: builds the adversarial body
    return out;
}

} // namespace

int main() {
    // EB1: two uint8 arrays, each < kCap, summing > kCap.
    {
        const std::size_t n = (kCap / 2) + 1000;   // 2n > kCap, n < kCap
        std::vector<epee::Entry> ents;
        ents.push_back(epee::Entry{"a", u8_array(n)});
        ents.push_back(epee::Entry{"b", u8_array(n)});
        const std::vector<std::uint8_t> blob = encode_root(std::move(ents));
        kat::check(!blob.empty(), "EB1: the adversarial body encodes");

        epee::Value parsed;
        epee::StorageError err = epee::StorageError::None;
        const bool ok = epee::read_storage(blob, parsed, err);
        kat::check(!ok, "EB1: a body over the message-wide element budget is refused");
        kat::checkf(err == epee::StorageError::ArrayTooLarge,
                    "EB1: refused as ArrayTooLarge (got %s)", epee::to_string(err));
    }

    // EB2: a single array under the cap still decodes.
    {
        const std::size_t n = kCap / 4;
        std::vector<epee::Entry> ents;
        ents.push_back(epee::Entry{"a", u8_array(n)});
        const std::vector<std::uint8_t> blob = encode_root(std::move(ents));

        epee::Value parsed;
        epee::StorageError err = epee::StorageError::None;
        const bool ok = epee::read_storage(blob, parsed, err);
        kat::checkf(ok, "EB2: a body under the budget decodes (err=%s)", epee::to_string(err));
        if (ok) {
            const epee::Value* a = epee::get_array(parsed, "a", epee::Type::Uint8);
            kat::checkf(a != nullptr && a->arr.size() == n,
                        "EB2: the array round-trips (%zu elements)", a ? a->arr.size() : 0);
        }
    }

    return kat::report("xmr_native_epee_budget_kat");
}
