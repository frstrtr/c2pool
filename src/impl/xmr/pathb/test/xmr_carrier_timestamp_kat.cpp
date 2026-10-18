// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/xmr_carrier_timestamp_kat.cpp
// Consensus time of the carrier chain (C33; pathb_fork_choice.hpp,
// pathb_receipt_admission.hpp, pathb_header_rules.hpp):
//   (a) h(c) < H(parent) -> not a carrier;
//   (b) a same-height Monero race: two carriers of one tip at one height on
//       different Monero parents are both valid;
//   (c) a carried receipt with h(r) > h(c) does NOT raise H: the record is
//       over carriers only, so the next carrier at h(c) + 1 is placed;
//   (d) no clock source in the Path B headers (the C08 patterns, code only);
//   (e) S1.3 #7 on the carrier's own body: major != hf(h) STRIKE, timestamp
//       below median60 of its P_r branch STRIKE, a timestamp 3 h ahead of the
//       newest block admitted (no clock input).
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_branch.hpp"
#include "impl/xmr/pathb/pathb_fork_choice.hpp"
#include "impl/xmr/pathb/pathb_header_rules.hpp"
#include "impl/xmr/pathb/pathb_receipt_admission.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

#ifndef PATHB_SRC_DIR
#error "PATHB_SRC_DIR must name src/impl/xmr/pathb"
#endif

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

const pb::LaneParams P = pb::kRuledLaneParams;
const pb::Hash32 kGenesis = seq32(0x01);
constexpr std::uint64_t kGenesisHeight = 1000;
constexpr std::uint64_t kBase = 1700000000;

pb::Hash32 cid(std::uint8_t branch, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = 0x80;
    h[1] = branch;
    for (int i = 0; i < 8; ++i) h[2 + i] = static_cast<std::uint8_t>(n >> (56 - 8 * i));
    return h;
}

// A carrier on a held tip, carrying nothing, with the receipts_root it commits there.
pb::CarrierAnnounce on_tip(const pb::CarrierTree& t, const pb::Hash32& id, const pb::Hash32& tip, std::uint64_t h) {
    return pb::CarrierAnnounce{id, tip, h, t.next_receipts_root(tip, {}).value_or(pb::Hash32{}), 0};
}

bool place_complete(pb::CarrierTree& t, const pb::CarrierAnnounce& c,
                    std::span<const pb::CarriedPlacement> carried = {}) {
    return t.place(c, carried).verdict == pb::PlaceVerdict::Placed && t.mark_verified(c.id) && t.mark_bodies(c.id);
}

class MapView final : public pb::IBranchView {
public:
    std::map<pb::Hash32, pb::BranchBlock> blocks;
    std::optional<pb::BranchBlock> block(const pb::Hash32& id) const override {
        const auto it = blocks.find(id);
        if (it == blocks.end()) return std::nullopt;
        return it->second;
    }
    std::optional<pb::WeightInputs> weights_at(const pb::Hash32&) const override { return std::nullopt; }
};

pb::Hash32 mid(std::uint64_t h) {
    pb::Hash32 id{};
    id[0] = 0x4d;
    for (int i = 0; i < 8; ++i) id[1 + i] = static_cast<std::uint8_t>(h >> (8 * i));
    return id;
}

// Code text of a header with // comments removed (block comments are not used in these headers).
std::string code_of(const std::filesystem::path& p) {
    std::ifstream in(p);
    std::string line, out;
    while (std::getline(in, line)) {
        const std::size_t c = line.find("//");
        out += (c == std::string::npos ? line : line.substr(0, c));
        out += '\n';
    }
    return out;
}

}  // namespace

int main() {
    std::printf("xmr_carrier_timestamp_kat\n");

    pb::CarrierTree t(P, kGenesis, kGenesisHeight, pb::EpochTable{});
    const pb::CarrierAnnounce c1 = on_tip(t, cid(1, 1), kGenesis, 1001);
    check(place_complete(t, c1), "carrier at 1001 placed");

    // (a) h(c) < H(parent): not a carrier
    {
        check(!pb::carrier_height_admissible(1001, 1000), "h 1000 below the parent's record 1001: not admissible");
        check(t.place(on_tip(t, cid(1, 2), c1.id, 1000), {}).verdict == pb::PlaceVerdict::NotCarrier,
              "(a) h(c) < H(parent) -> not a carrier");
    }

    // (b) a same-height Monero race: both carriers of one tip at one height valid
    {
        const pb::CarrierAnnounce ra = on_tip(t, cid(2, 1), c1.id, 1002);
        const pb::CarrierAnnounce rb = on_tip(t, cid(3, 1), c1.id, 1002);
        check(place_complete(t, ra) && place_complete(t, rb), "(b) a same-height race: both sides placed");
        check(t.find(ra.id)->H == 1002 && t.find(rb.id)->H == 1002, "(b) both records at 1002");
    }

    // (c) a carried receipt with h(r) > h(c) does not raise H
    {
        // c, a carrier at h 1001 on c1, carries a receipt of origin bin 1003 (h(r) > h(c)); its bin is open on
        // c's chain.
        const pb::ReceiptBodyV3 own = make_body(2, false, 0x10);
        std::vector<pb::CarriedReceipt> carried{{make_body(2, false, 0x20), 1003}};
        pb::ReceiptBodyV3 cbody = own;
        const std::vector<pb::Hash32> ids{pb::receipt_id(*carried[0].body)};
        cbody.side.receipts_root = pb::carrier_receipts_root_over(ids, t.find(c1.id)->rs);
        pb::PlacedSet placed;
        const pb::CarriedListResult r =
                pb::check_carried_list(cbody, t.find(c1.id)->H, carried, placed, t.find(c1.id)->rs, P);
        check(!r.verdict.has_value(), "(c) the carried receipt at h 1003 is admitted on c");
        const pb::CarrierAnnounce c{cid(4, 1), c1.id, 1001, cbody.side.receipts_root, 0};
        check(c.receipts_root == *t.next_receipts_root(c1.id, ids), "(c) c's receipts_root is the tree's fold over its carried id");
        const std::vector<pb::CarriedPlacement> cp{{ids[0], P.d_min, 0, true}};
        check(place_complete(t, c, cp) && t.find(c.id)->H == 1001, "(c) H(c) = h(c) = 1001, not the carried 1003");
        check(t.place(on_tip(t, cid(4, 2), c.id, 1002), {}).verdict == pb::PlaceVerdict::Placed,
              "(c) the next carrier at 1002 is a carrier (H was not raised)");
        check(pb::record_height(1001, 1001) == 1001, "(c) the record reads carrier heights only");
    }

    // (d) no clock source in the consensus core
    {
        const std::vector<std::string> forbidden = {"::now(",          "gettimeofday(", "clock_gettime(", "localtime(",
                                                    "localtime_r(",    "gmtime(",       "gmtime_r(",      "timespec_get(",
                                                    "std::time(",      "time(nullptr)", "time(NULL)",     "time(0)",
                                                    "<chrono>",        "<ctime>",       "<sys/time.h>"};
        std::size_t files = 0;
        bool saw_admission = false, saw_header_rules = false;
        std::vector<std::string> hits;
        for (const auto& e : std::filesystem::directory_iterator(PATHB_SRC_DIR)) {
            if (e.path().extension() != ".hpp") continue;
            ++files;
            saw_admission = saw_admission || e.path().filename() == "pathb_receipt_admission.hpp";
            saw_header_rules = saw_header_rules || e.path().filename() == "pathb_header_rules.hpp";
            const std::string code = code_of(e.path());
            for (const std::string& f : forbidden)
                if (code.find(f) != std::string::npos) hits.push_back(e.path().filename().string() + ": " + f);
        }
        for (const std::string& h : hits) std::printf("  clock read: %s\n", h.c_str());
        check(files >= 19 && saw_admission && saw_header_rules,
              "(d) the Path B headers were scanned (" + std::to_string(files) + ")");
        check(hits.empty(), "(d) no clock source in the Path B headers");
    }

    // (e) S1.3 #7 on the carrier's own body
    {
        MapView v;
        for (std::uint64_t h = 0; h <= 100; ++h) {
            pb::BranchBlock b;
            b.id = mid(h);
            b.prev_id = h ? mid(h - 1) : pb::Hash32{};
            b.height = h;
            b.timestamp = kBase + 120 * h;
            v.blocks[b.id] = b;
        }
        std::optional<std::uint64_t> m;
        check(pb::timestamp_median_for_child(v, mid(100), m).selected() && m == std::optional<std::uint64_t>(kBase + 120 * 70 + 60),
              "(e) median60 for a carrier on P_r = 100: mid(ts(70), ts(71))");
        const std::uint64_t med = m.value_or(0);
        pb::ReceiptBodyV3 own = make_body(2, false, 0x30);
        own.blob.major = 16;
        own.blob.tx_count = 6;
        own.blob.timestamp = med;
        const pb::HeaderInputs in{16, m, 300000, 300000};
        const auto verdict = [&](const pb::ReceiptBodyV3& b) {
            return pb::header_fields_verdict(pb::header_fields(b, enc(b).size(), in));
        };
        check(!verdict(own).has_value(), "(e) a carrier with major 16 and timestamp == median60 passes #7");
        pb::ReceiptBodyV3 bad = own;
        bad.blob.major = 15;
        check(verdict(bad) == pb::AdmitVerdict::Strike, "(e) carrier major != hf(h) STRIKE");
        bad = own;
        bad.blob.timestamp = med - 1;
        check(verdict(bad) == pb::AdmitVerdict::Strike, "(e) carrier timestamp below median60 STRIKE");
        bad = own;
        bad.blob.timestamp = kBase + 120 * 100 + 3 * 3600;
        check(!verdict(bad).has_value(), "(e) a carrier 3 h ahead of the newest block admitted (no clock)");
    }

    return finish("xmr_carrier_timestamp_kat");
}
