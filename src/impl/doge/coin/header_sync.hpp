// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: when the header chain asks peers for headers (main_ltc's
/// DOGE header handlers), as Dogecoin/Bitcoin Core does it
/// (net_processing.cpp ProcessHeadersMessage):
///   - after a headers batch, more are asked only of the peer that sent new
///     ones, with the chain's locator; a batch with nothing new asks nothing.
///     Before, a full batch with nothing accepted asked every peer again, and
///     an accepted one asked every peer with a bare last-hash locator (a
///     peer without that hash answers from genesis): ~80 getheaders a minute
///     and ~190 MB a minute of AuxPoW headers, which delayed every other
///     answer on those connections (the hash schedule's among them);
///   - the periodic getheaders asks one peer per tick while the chain is
///     catching up (round robin), and every peer once it is synced: the
///     tip's headers path is unchanged.

namespace doge {
namespace coin {

/// What to do after a headers batch.
enum class HeadersFollowUp {
    None,       // nothing new in it: ask nothing
    AskSender,  // new headers: ask the same peer for more, from the chain's locator
};

inline HeadersFollowUp headers_follow_up(int accepted)
{
    return accepted > 0 ? HeadersFollowUp::AskSender : HeadersFollowUp::None;
}

/// Who the periodic getheaders goes to.
enum class HeadersPoll {
    OnePeer,    // catching up: one peer per tick
    EveryPeer,  // synced: every peer (the tip's headers)
};

inline HeadersPoll headers_poll(bool chain_synced)
{
    return chain_synced ? HeadersPoll::EveryPeer : HeadersPoll::OnePeer;
}

} // namespace coin
} // namespace doge
