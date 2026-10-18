// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// Test-only translation unit of v37_xmr_pathb_miner_tx_kat (C26, C37):
//   the author key references the Path B KATs pass (kAuthorRefsOfRecord) equal
//   the K16 author references per network (pathb_lane_rules.hpp author_ref);
//   the coin-level derivation (generate_key_derivation, derive_public_key,
//   derive_view_tag) gives the same (P_i, vt_i) as pathb's derive_out_key.
// ---------------------------------------------------------------------------
#include <cstring>
#include <string>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int author_refs_of_record_kat() {
    const int fails_before = g_fail;
    for (std::size_t i = 0; i < 4; ++i) {
        const pb::LaneNet n = pb::kLaneNets[i];
        check(author_ref_of_record(i) == pb::author_ref(n),
              std::string("author reference of record (") + std::string(pb::lane_net_name(n)) + ") == K16 author_ref");
        check(pb::key_ref_points_valid(author_ref_of_record(i)),
              std::string("author reference (") + std::string(pb::lane_net_name(n)) + ") decompresses");
    }

    // the coin-level derivation == pathb derive_out_key (r of the self-golden)
    const pb::Hash32 r = pb::derive_r_v3(seq32(0x01), seq32(0x21), seq32(0x41), 3800000);
    ::xmr::coin::SecretKey rs;
    std::memcpy(rs.data(), r.data(), 32);
    for (const pb::XmrKeyRef& ref : {ref_from_secrets(11, 13), ref_from_secrets(17, 19), author_ref_of_record(0)}) {
        ::xmr::coin::PublicKey A, B;
        std::memcpy(A.data(), ref.view.data(), 32);
        std::memcpy(B.data(), ref.spend.data(), 32);
        ::xmr::coin::KeyDerivation D;
        bool same = ::xmr::coin::generate_key_derivation(A, rs, D);
        for (std::size_t i : {std::size_t{0}, std::size_t{1}, std::size_t{127}, std::size_t{128}, std::size_t{300}}) {
            ::xmr::coin::PublicKey p;
            ::xmr::coin::ViewTag vt;
            const bool ok = ::xmr::coin::derive_public_key(D, i, B, p);
            ::xmr::coin::derive_view_tag(D, i, vt);
            const std::optional<pb::OutKey> o = pb::derive_out_key(r, ref, i);
            same = same && ok && o && std::memcmp(p.data(), o->key.data(), 32) == 0 && vt.tag == o->view_tag;
        }
        check(same, "coin-level derivation == pathb derive_out_key at i in {0, 1, 127, 128, 300}");
    }
    return g_fail - fails_before;
}
