// SPDX-License-Identifier: (see repository LICENSE)
// ---------------------------------------------------------------------------
// xmr_recon_verify.hpp — RECON Phase-1: VERIFY the reconstructed payout against
// the winner's ACTUAL ON-CHAIN coinbase.
//
// The reconstructor (xmr_recon.hpp) produces the owed map it BELIEVES the winner
// deducted. This module proves it: it rebuilds the canonical W5-XMR coinbase
// from the reconstructed settlement source at the WINNER's parent context and
// byte-compares it against the coinbase the winner actually published — exactly
// p2pool's SideChain::verify discipline ("pays out to a wrong wallet at index
// i") applied to the OWED list. This is the same call the node already runs on
// its OWN template pre-publish (xmr_settlement_coinbase_shape.hpp); RECON runs
// it on the PEER's block. NOT a sha256d stand-in.
//
// The winner's block bytes reach the receiver via `bid`:
//   * native arm  : XmrChainIndex::get_block_entry(id).block_blob
//   * daemon arm  : MoneroRpc::get_block(height, hash_hex)
// then parse_and_identify -> parse_coinbase_prefix -> ReceivedCoinbase. That
// parse is the daemon's WinnerCoinbaseFetcher; a KAT supplies the winner's own
// BuiltCoinbase directly. When the bytes are not yet held the fetcher returns
// false and the reconstructor PARKs (bounded), never refuses.
//
// The r-derivation is FENCED and deterministic in (domain, major, chain_id,
// lane_commitment, prev_id, height): the height/prev_id/major_version therefore
// MUST be overridden to the winner's before the compare, because the receiver's
// own template parent is a strictly later instant.
//
// Consumer-tree module: no consensus body edit.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "xmr_s1_fold.hpp"                 // XmrPeerWin, o2 namespace
#include "xmr_o2_settlement_source.hpp"    // XmrOwedSettlementSource, x6 = ::v37::xmr::settle

namespace c2pool::v37n::xmr::o2 {

// The winner's coinbase, as reached via `bid` and parsed off its on-chain block.
struct WinnerCoinbase {
    x6::ReceivedCoinbase       got;             // R / amounts / keys / view_tags / tx_extra
    ::xmr::coin::Hash256       prev_id{};        // block header prev_id (bin origin)
    std::uint8_t               major_version = 0;// block header major version (FENCE key)
    std::vector<unsigned char> extra_nonce;      // the 0x02 tag payload the winner used
};

// bid -> the winner's coinbase. false + why when the block bytes are not yet
// held (PARK) or cannot be parsed (refuse, surfaced by the caller).
using WinnerCoinbaseFetcher =
    std::function<bool(const std::string& bid, WinnerCoinbase& out, std::string& why)>;

struct ReconVerifyResult {
    bool        ok = false;
    int         first_bad_index = 0;   // x6::MatchResult codes (IDX_R/EXTRA/COUNT/BUILD or vout)
    std::string reason;
};

// Rebuild the canonical coinbase from the reconstructed source at the winner's
// parent context and byte-compare against the winner's on-chain coinbase.
inline ReconVerifyResult recon_verify_coinbase(const XmrOwedSettlementSource& src,
                                               const XmrPeerWin& w,
                                               const WinnerCoinbase& wc) {
    x6::CoinbaseInputs in = src.inputs_at(w.reward, wc.extra_nonce);
    // Override to the WINNER's parent context — the fields the deterministic r
    // and every one-time key are bound to. lane_commitment is already the
    // scratch ledger's owed_digest (== w.owed_digest_at_win by the pick rule).
    in.height               = w.h_b;
    in.prev_id              = wc.prev_id;
    in.monero_major_version = wc.major_version;

    const x6::MatchResult m = x6::canonical_coinbase_matches(in, wc.got);
    ReconVerifyResult r;
    r.ok              = m.matches;
    r.first_bad_index = m.first_bad_index;
    r.reason          = m.reason;
    return r;
}

}  // namespace c2pool::v37n::xmr::o2
