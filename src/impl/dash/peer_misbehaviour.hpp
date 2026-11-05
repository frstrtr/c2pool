// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Graded misbehaviour score for DASH sharechain peers (#1829).
//
// A peer that sends a share failing share_init_verify, a structurally invalid
// share, an over-cap 'shares' / 'sharereply' message or an unparseable payload
// is charged a weighted offence against its source IP. The score decays with a
// half-life; once the decayed score reaches BAN_THRESHOLD the node disconnects
// every connection from that IP and bans the IP (NodeImpl::m_ip_ban_list, for
// m_ban_duration), so an inbound reconnect from any source port is refused at
// NodeImpl::connected() and outbound dialing skips it.
//
// Port of the LTC scorer (src/impl/ltc/misbehavior.hpp, #1601), generalised
// from one offence to a weighted set. Same constants, same decay rule, same
// keying (IP, not IP:port), same whitelist exemption.
//
// Which offences count depends on the network (ShareProfile
// full_misbehaviour_grading, config_pool.hpp):
//
//   * Public network (no --network-id, p2pool-dash compatible): only what the
//     p2pool-dash oracle itself treats as a peer error. The oracle raises
//     PeerMisbehavingError for 'share PoW invalid' / 'share target invalid'
//     (p2pool/data.py:356-362), which packetReceived turns into disconnect +
//     1 h host ban (p2pool/p2p.py:89-102); it disconnects (no ban) on the
//     Share.__init__ field checks: coinbase size, merkle branch > 16,
//     transaction_hash_refs (data.py:317-340, ValueError / AssertionError ->
//     "Error handling message" -> disconnect, util/p2protocol.py:57-60). Those
//     two classes are scored here. Everything the oracle tolerates is not:
//     unknown commands (skipped, p2protocol.py:49-53), shares of an older type
//     (skipped, p2p.py:334), oversize frames (skipped, p2protocol.py:38-40),
//     stale / duplicate / orphan / losing shares (never throw in the receive
//     verify at all). Payload parse failures are not scored on the public
//     network either: a codec difference between c2pool and p2pool-dash must
//     never cost an honest peer its connection. The oracle is harsher than this
//     scorer: it bans on the first invalid-PoW share, we act only past the
//     threshold.
//   * DASH v36 network (custom --network-id): every offence below.
//
// Never scored anywhere: a share timestamp too far in the future (clock skew is
// not misbehaviour, and scoring it would let a skewed local clock cut the node
// off from its peers), handshake refusals (a build below the protocol floor is
// refused at handle_version and never reaches this scorer; the oracle bans
// "peer too old", p2p.py:150-151, c2pool deliberately does not), unknown
// message types, and every share drop that happens after the receive verify.
//
// Whitelisted peers (--addnode / --connect seeds, NodeImpl::is_whitelisted) are
// never scored. Localhost is not exempt (the oracle exempts it from the ban,
// p2p.py:101): a co-located node is whitelisted with --addnode instead.
// Scores and IP bans live in memory only (as in the oracle and LTC).

#include "share_precheck.hpp"   // SharePoWTargetMiss / ShareStructureReject / ShareClockReject

#include <cmath>
#include <cstddef>
#include <exception>
#include <map>
#include <optional>

namespace dash::misbehaviour
{

enum class Offence : std::size_t
{
    invalid_pow,        // PoW hash above the share target, or the target is zero / easier than MAX_TARGET
    structural,         // coinbase size, merkle branch > 16, tx refs, v36 field checks
    bad_verify,         // any other share_init_verify failure (hash_link, message_data, ...)
    wrong_share_type,   // a share of a type this sharechain does not admit
    precheck_drop,      // a 'shares' / 'sharereply' message over a per-message or per-share cap
    parse_failure,      // a known message whose payload, or a share whose contents, does not parse
    COUNT
};

inline constexpr std::size_t OFFENCE_COUNT = static_cast<std::size_t>(Offence::COUNT);

// Score added per offence. BAN_THRESHOLD / weight = offences needed inside one
// half-life to be banned: 5 invalid-PoW shares, 10 structural / bad-verify
// shares or over-cap messages, 20 wrong-type shares or unparseable payloads.
inline constexpr double weight(Offence o)
{
    switch (o)
    {
    case Offence::invalid_pow:      return 20.0;
    case Offence::structural:       return 10.0;
    case Offence::bad_verify:       return 10.0;
    case Offence::wrong_share_type: return 5.0;
    case Offence::precheck_drop:    return 10.0;
    case Offence::parse_failure:    return 5.0;
    case Offence::COUNT:            break;
    }
    return 0.0;
}

inline constexpr const char* name(Offence o)
{
    switch (o)
    {
    case Offence::invalid_pow:      return "invalid_pow";
    case Offence::structural:       return "structural";
    case Offence::bad_verify:       return "bad_verify";
    case Offence::wrong_share_type: return "wrong_share_type";
    case Offence::precheck_drop:    return "precheck_drop";
    case Offence::parse_failure:    return "parse_failure";
    case Offence::COUNT:            break;
    }
    return "?";
}

// True for the offences the p2pool-dash oracle itself answers with a
// disconnect (and, for invalid_pow, a ban). Only these are scored on the
// public network.
inline constexpr bool oracle_penalised(Offence o)
{
    return o == Offence::invalid_pow || o == Offence::structural;
}

// Whether offence `o` is scored on a network whose profile has
// full_misbehaviour_grading == `full_grading`.
inline constexpr bool applies(Offence o, bool full_grading)
{
    return o != Offence::COUNT && (full_grading || oracle_penalised(o));
}

/// Decaying per-peer score. Keyed on any comparable identity (NodeImpl uses
/// the source IP string). Not thread-safe: NodeImpl touches it on the IO
/// thread only (the verify-pool worker posts the charge there), the same
/// discipline as m_ban_list.
template <class Key>
class PeerMisbehaviourScorer
{
public:
    // The peer is banned once its decayed score reaches this.
    static constexpr double BAN_THRESHOLD = 100.0;
    // The score halves every this many seconds, so only a sustained stream of
    // offences reaches the threshold; a slow trickle settles below it.
    static constexpr double HALFLIFE_SECONDS = 600.0;

    /// Charge `w` against `peer` at monotonic time `now_s`. Returns true when
    /// the decayed score reaches BAN_THRESHOLD; the caller then bans and calls
    /// clear(peer).
    bool note(const Key& peer, double w, double now_s)
    {
        auto& e = m_scores[peer];
        e.score = decayed(e, now_s) + w;
        e.last_s = now_s;
        return e.score >= BAN_THRESHOLD;
    }

    /// Decayed score of `peer` at `now_s` (0 if untracked). Read-only.
    double score(const Key& peer, double now_s) const
    {
        auto it = m_scores.find(peer);
        if (it == m_scores.end()) return 0.0;
        return decayed(it->second, now_s);
    }

    void clear(const Key& peer) { m_scores.erase(peer); }

    /// Drop entries that decayed below `floor`, so the map stays bounded as
    /// offenders age out.
    void prune(double now_s, double floor = 0.01)
    {
        for (auto it = m_scores.begin(); it != m_scores.end(); )
        {
            if (decayed(it->second, now_s) < floor) it = m_scores.erase(it);
            else ++it;
        }
    }

    std::size_t tracked_peers() const { return m_scores.size(); }

private:
    struct Entry { double score{0.0}; double last_s{0.0}; };

    static double decayed(const Entry& e, double now_s)
    {
        const double dt = now_s - e.last_s;
        if (dt <= 0.0) return e.score;
        return e.score * std::exp2(-dt / HALFLIFE_SECONDS);
    }

    std::map<Key, Entry> m_scores;
};

/// The one classification rule for a share_init_verify failure caught on the
/// receive path (NodeImpl::processing_shares), shared with its KAT:
///   SharePoWTargetMiss   -> invalid_pow (both networks)
///   ShareStructureReject -> structural  (both networks)
///   ShareClockReject     -> not scored
///   anything else        -> bad_verify on the DASH v36 network, not scored
///                           on the public network
inline std::optional<Offence> classify_verify_failure(const std::exception& e, bool full_grading)
{
    if (dynamic_cast<const SharePoWTargetMiss*>(&e))
        return Offence::invalid_pow;
    if (dynamic_cast<const ShareStructureReject*>(&e))
        return Offence::structural;
    if (dynamic_cast<const ShareClockReject*>(&e))
        return std::nullopt;
    if (full_grading)
        return Offence::bad_verify;
    return std::nullopt;
}

} // namespace dash::misbehaviour
