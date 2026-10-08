// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// Test-only translation unit of v37_xmr_pathb_miner_tx_kat (C26, C37):
//   the author key references the Path B KATs pass (kAuthorRefsOfRecord) equal
//   the per-network donation keys of record (xmr_fee_model.hpp donation_info);
//   the settle derivation (settle::derive_output) gives the same (P_i, vt_i) as
//   pathb's derive_out_key (an equivalence check only).
// ---------------------------------------------------------------------------
#include <cstring>
#include <string>

#include "c2pool/v37/xmr/xmr_fee_model.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

int author_refs_of_record_kat() {
    namespace fee = ::c2pool::v37n::xmr::fee;
    const int fails_before = g_fail;
    const fee::DonationNet nets[4] = {fee::DonationNet::Mainnet, fee::DonationNet::Testnet, fee::DonationNet::Stagenet,
                                      fee::DonationNet::Regtest};
    for (std::size_t i = 0; i < 4; ++i) {
        const fee::DonationIdentity di = fee::donation_info(nets[i]);
        check(std::string(di.spend_hex) == kAuthorRefsOfRecord[i].spend
                      && std::string(di.view_hex) == kAuthorRefsOfRecord[i].view,
              std::string("author reference of record (") + fee::to_string(nets[i]) + ") == donation_info");
        check(pb::key_ref_points_valid(author_ref_of_record(i)),
              std::string("author reference (") + fee::to_string(nets[i]) + ") decompresses");
    }

    // settle::derive_output == pathb derive_out_key (r of the self-golden).
    const pb::Hash32 r = pb::derive_r_v3(seq32(0x01), seq32(0x21), seq32(0x41), 3800000);
    ::xmr::coin::SecretKey rs;
    std::memcpy(rs.data(), r.data(), 32);
    for (const pb::XmrKeyRef& ref : {ref_from_secrets(11, 13), ref_from_secrets(17, 19), author_ref_of_record(0)}) {
        ::v37::ScriptRef pay;
        pay.kind = ::v37::xmr::XMR_STD;
        pay.payload.assign(ref.spend.begin(), ref.spend.end());
        pay.payload.insert(pay.payload.end(), ref.view.begin(), ref.view.end());
        bool same = true;
        for (std::size_t i : {std::size_t{0}, std::size_t{1}, std::size_t{127}, std::size_t{128}, std::size_t{300}}) {
            ::xmr::coin::PublicKey p;
            ::xmr::coin::ViewTag vt;
            const bool ok = ::v37::xmr::settle::derive_output(rs, pay, i, p, vt);
            const std::optional<pb::OutKey> o = pb::derive_out_key(r, ref, i);
            same = same && ok && o && std::memcmp(p.data(), o->key.data(), 32) == 0 && vt.tag == o->view_tag;
        }
        check(same, "settle::derive_output == pathb derive_out_key at i in {0, 1, 127, 128, 300}");
    }
    return g_fail - fails_before;
}
