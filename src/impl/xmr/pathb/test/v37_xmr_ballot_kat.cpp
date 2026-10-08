// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ballot_kat (C23; ballot_to_write, side_data_v3 offset 35):
//   the ballot is under the receipt's own PoW (a changed ballot changes the
//   mm_root the tree root binds); a ballot for e' is yes for every e <= e'; a
//   ballot <= epoch_cur is no; any u16 decodes (no range check); default yes
//   on an upgraded build (source default); --vote no writes epoch_cur
//   (opt-out); a stated vote=n sets the own flag (own), vote=0 is own no; the
//   login reply's vote object; a stated vote expires with its deployment;
//   a --vote change applies to the next ballot written.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_ratchet_activation.hpp"
#include "impl/xmr/pathb/pathb_wire_v3.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_ratchet_sim.hpp"

using namespace pathb_kat;
using namespace ratchet_sim;

int main() {
    const pb::RatchetParams P = pb::kRuledRatchetParams;
    const std::uint64_t L = P.window;

    // under the receipt's own PoW: the ballot is a side_data_v3 byte pair at offset 35
    pb::SideDataV3 sd;
    sd.ballot = pb::make_ballot(1, false);
    std::vector<std::uint8_t> bytes;
    check(pb::encode_side_data_v3(sd, bytes) == pb::WireError::None && pb::side_v3::kBallotOff == 35
              && bytes[35] == 0x01 && bytes[36] == 0x00,
          "ballot u16 at side_data_v3 offset 35, little-endian");
    pb::SideDataV3 sd2 = sd;
    sd2.ballot = pb::make_ballot(2, false);
    check(pb::mm_root_of(sd) != pb::mm_root_of(sd2), "a changed ballot changes mm_root (fails the tree root before RandomX)");
    // any u16 decodes: no range check against a table
    bool all = true;
    for (std::uint32_t b = 0; b <= 0xffff; b += 251) {
        pb::SideDataV3 s = sd;
        s.ballot = static_cast<std::uint16_t>(b);
        std::vector<std::uint8_t> v;
        pb::SideDataV3 back;
        all = all && pb::encode_side_data_v3(s, v) == pb::WireError::None
              && pb::decode_side_data_v3(v.data(), v.size(), back) == pb::WireError::None && back.ballot == s.ballot;
    }
    {
        pb::SideDataV3 s = sd;
        s.ballot = 0xffff;
        std::vector<std::uint8_t> v;
        pb::SideDataV3 back;
        all = all && pb::encode_side_data_v3(s, v) == pb::WireError::None
              && pb::decode_side_data_v3(v.data(), v.size(), back) == pb::WireError::None && back.ballot == 0xffff;
    }
    check(all, "any u16 ballot is admitted by the codec");

    // yes(r, e) = epoch_no(r) >= e: a ballot for e' is yes for every e <= e'; <= epoch_cur is no
    pb::RatchetState s = pb::genesis_ratchet_state(kG);
    s.epoch_cur = 3;
    const pb::RatchetPlacement for5{10, pb::make_ballot(5, true)};
    const pb::RatchetState t = pb::rs_step(P, s, 7, std::span<const pb::RatchetPlacement>(&for5, 1));
    check(t.y1 == pb::RsWork(10) && t.y2 == pb::RsWork(10), "a ballot for e' = 5 counts yes for e = 4 and e = 5 at epoch_cur 3");
    const pb::RatchetPlacement for3{10, pb::make_ballot(3, false)};
    const pb::RatchetState u = pb::rs_step(P, s, 7, std::span<const pb::RatchetPlacement>(&for3, 1));
    check(u.y1.is_zero() && u.y2.is_zero() && u.all == pb::RsWork(10), "a ballot <= epoch_cur is no");
    check(pb::ballot_epoch(pb::make_ballot(5, true)) == 5 && pb::ballot_own(pb::make_ballot(5, true)), "own flag bit 15, epoch bits 0..14");

    // the writer
    const pb::EpochTable T = release({vote(P, 1, kR1, 0)});
    const pb::RatchetState g = pb::genesis_ratchet_state(kG);
    const pb::BallotChoice def = pb::ballot_to_write(P, g, 10, T, std::nullopt, false);
    check(def.ballot == pb::make_ballot(1, false) && def.source == pb::BallotSource::Default, "default yes on an upgraded build (source default)");
    const pb::BallotChoice opt = pb::ballot_to_write(P, g, 10, T, std::nullopt, true);
    check(opt.ballot == pb::make_ballot(0, false) && opt.source == pb::BallotSource::OptOut, "--vote no writes epoch_cur (source opt-out)");
    const pb::BallotChoice own1 = pb::ballot_to_write(P, g, 10, T, 1u, true);
    check(own1.ballot == pb::make_ballot(1, true) && own1.source == pb::BallotSource::Own, "a stated vote=1 sets the own flag (source own)");
    const pb::BallotChoice own0 = pb::ballot_to_write(P, g, 10, T, 0u, false);
    check(own0.ballot == pb::make_ballot(0, true) && own0.source == pb::BallotSource::Own, "vote=0 is own no");
    check(pb::vote_json(def) == "\"vote\": {\"ballot\": \"0x0001\", \"source\": \"default\"}"
              && pb::vote_json(own0) == "\"vote\": {\"ballot\": \"0x8000\", \"source\": \"own\"}"
              && pb::vote_json(opt) == "\"vote\": {\"ballot\": \"0x0000\", \"source\": \"opt-out\"}",
          "the login reply echoes the ballot and its source: " + pb::vote_json(def));
    // a stated vote for an epoch that is not the open one is written as the default
    const pb::BallotChoice v7 = pb::ballot_to_write(P, g, 10, T, 7u, false);
    check(v7 == def, "a stated vote=7 (not open) is written as the default");
    // the stated vote expires with its deployment: past timeout_D the default is written
    const std::uint64_t after = pb::own_attempt(T, 1)->timeout;
    const pb::BallotChoice exp = pb::ballot_to_write(P, g, after, T, 1u, false);
    check(exp.ballot == pb::make_ballot(0, false) && exp.source == pb::BallotSource::Default,
          "a stated vote=1 past timeout_D is written as the default (epoch_cur)");
    // LOCKED_IN before timeout_D is open: the default yes continues
    pb::RatchetState locked = g;
    locked.levels = {0, 0, 0, 1};
    const std::uint64_t x_lock = 4 * L + 3;  // window 3 is kept with level 1
    check(pb::locked(P, locked, x_lock, T) && pb::open(P, locked, x_lock, T)
              && pb::ballot_to_write(P, locked, x_lock, T, std::nullopt, false).ballot == pb::make_ballot(1, false),
          "LOCKED_IN before timeout_D: open, default yes");
    // a --vote change applies to the next ballot written (the writer is a function of the setting)
    check(pb::ballot_to_write(P, g, 11, T, std::nullopt, false) != pb::ballot_to_write(P, g, 11, T, std::nullopt, true),
          "a --vote change applies to new jobs");
    // nothing open: the default is epoch_cur
    check(pb::ballot_to_write(P, g, 10, release({}), std::nullopt, false).ballot == pb::make_ballot(0, false),
          "no deployment open: the default is epoch_cur");
    return finish("v37_xmr_ballot_kat");
}
