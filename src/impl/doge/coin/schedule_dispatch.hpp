// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Embedded DOGE: who takes a `headers` message (main_ltc's DOGE headers
/// handler, on the header pool's thread), in order:
///   1. the anchored ranges (RangeSync): an answer that starts at an
///      anchor's child below the checkpoint;
///   2. the sequential hash schedule (HashScheduleSync), only while it runs
///      (no anchors, refused anchors, or the tail past them);
///   3. the header chain: only then is the peer's header-chain getheaders
///      answered (HeaderAsks) — a range or schedule answer never counts as
///      one, so a peer with both in flight keeps its header-chain ask.

#include <impl/doge/coin/hash_schedule.hpp>
#include <impl/doge/coin/header_sync.hpp>
#include <impl/doge/coin/range_sync.hpp>

#include <optional>
#include <string>
#include <vector>

namespace doge {
namespace coin {

struct HeadersRoute {
    enum class Taken { Range, Schedule, HeaderChain };
    Taken                                 taken{Taken::HeaderChain};
    RangeSync::Answer                     range{RangeSync::Answer::NotOurs};
    HashSchedule::Feed                    feed{HashSchedule::Feed::NotNext};
    std::optional<HashScheduleSync::Ask>  next;  // the sequential sync's next ask
};

inline HeadersRoute route_headers(RangeSync* ranges, HashScheduleSync* sequential, HashSchedule* schedule,
                                  HeaderAsks& asks, const std::string& peer,
                                  const std::vector<ltc::coin::BlockHeaderType>& headers,
                                  std::chrono::steady_clock::time_point now)
{
    HeadersRoute r;
    if (ranges) {
        r.range = ranges->on_headers(peer, headers, now);
        if (r.range != RangeSync::Answer::NotOurs) {
            r.taken = HeadersRoute::Taken::Range;
            return r;
        }
    }
    if (sequential && schedule && !schedule->complete() && (!ranges || ranges->sequential())) {
        r.feed = sequential->on_headers(peer, headers, now, r.next);
        if (r.feed != HashSchedule::Feed::NotNext && r.feed != HashSchedule::Feed::Done) {
            r.taken = HeadersRoute::Taken::Schedule;
            return r;
        }
    }
    asks.answered(peer);
    r.taken = HeadersRoute::Taken::HeaderChain;
    return r;
}

} // namespace coin
} // namespace doge
