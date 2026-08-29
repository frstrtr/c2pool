// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// dash::coin::ServeStalenessSentinel — REPORT-ONLY detector for "we are handing
/// miners a height the network has already passed".
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE INCIDENT (hotel 109.161.52.148, DASH mainnet, 2026-08-07)
/// ─────────────────────────────────────────────────────────────────────────
///
/// The node served h=2518006 to 26 rigs for ONE HOUR while dashd advanced to
/// h=2518028. All of that work was unpayable. A plain restart recovered it
/// (9.7 -> 43.9 TH/s), so nothing was corrupted — the io thread was pegged at
/// 99.9% in userspace and every other thread was parked on a futex.
///
/// The part this header addresses is NOT the peg. It is that NOTHING SAID SO
/// for an hour.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY EVERY EXISTING SIGNAL WAS STRUCTURALLY UNABLE TO FIRE
/// ─────────────────────────────────────────────────────────────────────────
///
/// Staleness signals DO exist in this tree. Each one fails here for a reason
/// that is a property of its design, not a bug:
///
///  (a) kStaleAfter = 30 s / kRetryAfter = 5 s (stratum/work_source.cpp:66,:69)
///      are CACHE TTLs. Expiry schedules a re-source; it is never a verdict.
///      The executor path deliberately keeps serving the stale cache while the
///      refresh runs (work_source.cpp:864-889, :924) — a stale cache is the
///      normal steady state under load, so alarming on it would fire on every
///      benign refresh and train operators to ignore the tag.
///
///  (b) [EMBED-STATUS] (c2pool/main_dash.cpp:6400-6525) is the periodic health
///      line, and it is doubly blind here. Every field it prints —
///      describe_decline(), have_tip/have_mn, payee_cursor, hdr_tip, bestcl —
///      is read out of our OWN NodeCoinState/header chain, which froze WITH the
///      serve path; and its `diag_timer` is a steady_timer on the SAME `ioc`
///      (main_dash.cpp:6399), so when that thread pegged, the line stopped
///      being printed at all. A metric that cannot disagree with the thing it
///      measures is not a check.
///
///  (c) SmlResyncWatchdog (coin/sml_resync_watchdog.hpp) is a real over-time
///      staleness detector — of the SML against OUR tip. A frozen tip makes a
///      frozen SML look perfectly current, so it is silent by construction in
///      exactly this failure.
///
///  (d) The oracle shadow-compare VOIDs a sample on tip-skew by design
///      (coin/embedded_oracle_shadow.hpp:786-791) and its samples arrive on the
///      starved owning thread. It reported a=0 comparisons — accurate, and read
///      by everyone as silence.
///
///  (e) node_topology ALREADY carries header_height, target_height and a
///      `synced` flag (main_dash.cpp:3271-3286). So the claim "there is no
///      wall-clock comparison anywhere" is FALSE and is not made here. What is
///      missing is narrower and exact: those fields are (i) recomputed only
///      when a browser asks, (ii) about the HEADER chain, never about the
///      height actually handed to a miner, and (iii) compared by nobody. A
///      detector that needs a human watching at 04:00 is not a detector.
///
/// The one signal that did not exist anywhere in the tree — verified by
/// `grep -rn 'serve_staleness\|served_height\|STALE-SERVE' src/` returning
/// nothing on master — is a SERVED height, recorded where the template is
/// actually handed out, compared against an INDEPENDENTLY observed height.
/// That is all this class is.
///
/// ─────────────────────────────────────────────────────────────────────────
/// REPORT-ONLY, DELIBERATELY
/// ─────────────────────────────────────────────────────────────────────────
///
/// This class's only output types are a bool + a formatted string. There is no
/// path from an alarm to a serve decision, an arm flip, or a template byte.
/// That is a choice, not an omission: on the production money path a detector
/// that can stop serving turns a false positive (a reorg, a lying peer height,
/// the sentinel's own RPC glitch) into a self-inflicted outage for 26 rigs —
/// strictly worse than the hour of unpayable work it guards against. A false
/// positive here costs a page.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHERE IT MUST BE POLLED FROM
/// ─────────────────────────────────────────────────────────────────────────
///
/// A DEDICATED THREAD. Not `ioc`. Half of what this detects is the death of
/// the io thread, and diag::StallWatchdog's own contract (coin/lane_diag.hpp:
/// 209-219) already states the rule: "A STALL DETECTOR MUST NOT LIVE ON THE
/// PATH IT WATCHES." The existing diag_tick violates that for this failure
/// because it lives on `ioc` (main_dash.cpp:6399), which is why the class is
/// reused here but its poller is not.
///
/// The class itself owns no thread and no clock: `poll()` takes every input as
/// a value, so the whole detector is exercisable in a unit test with a fake
/// clock and injected heights — including the mutation case that proves the
/// skew comparison is load-bearing.

#include <impl/dash/coin/lane_diag.hpp>   // diag::StallWatchdog, diag::steady_now_ms

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// Which sub-check raised. Named so a log scraper can key on the cause and an
/// operator does not have to parse prose.
enum class StaleServeCheck {
    None = 0,
    IoSilence,     ///< D1: the io thread stopped ticking its heartbeat.
    HeightSkew,    ///< D2: served height is behind an independently observed one.
    ServeSilence,  ///< D3: no template handed out at all while miners are attached.
};

inline const char* stale_serve_check_name(StaleServeCheck c)
{
    switch (c) {
        case StaleServeCheck::IoSilence:    return "io-silence";
        case StaleServeCheck::HeightSkew:   return "height-skew";
        case StaleServeCheck::ServeSilence: return "serve-silence";
        default:                            return "none";
    }
}

/// Thresholds. Every one is a field rather than a constant SO THAT A TEST CAN
/// NEUTER IT: the unit suite runs the induced-skew case a second time with
/// `height_skew_blocks` set to the deleted-guard value and asserts the alarm
/// does NOT fire. A guard that cannot be shown to matter has not been tested.
struct ServeStalenessConfig {
    /// D1: silence of the io-thread heartbeat that counts as "the io thread is
    /// gone".
    ///
    /// THIS DEFAULT WAS 10 s AND WOULD HAVE CRIED WOLF ON A HEALTHY NODE. The
    /// arithmetic that retired it, with every input measured rather than
    /// assumed:
    ///
    ///   * one send_notify_work costs ~733 ms on the hotel node — the pre-emit
    ///     gate held across it (stratum/work_source.cpp:853 records the same
    ///     733 ms figure from the incident capture);
    ///   * notify_all runs those SERIALLY over the session snapshot, on the io
    ///     thread, with no yield between them (core/stratum_server.cpp:379-385);
    ///   * 26 attached rigs is therefore 26 x 733 ms = 19.06 s in ONE notify
    ///     round, during which the 1 s heartbeat timer CANNOT run — on a node
    ///     that is perfectly healthy and simply busy;
    ///   * a tip change landing inside a round makes two rounds back to back:
    ///     38.1 s.
    ///
    /// 10 s sat BELOW one round. It would have fired on every tip change with
    /// 14+ rigs attached, and a detector that fires on a healthy node is worth
    /// less than nothing: it trains the operator to skip the tag, which is how
    /// [EMBED-STATUS] became unreadable.
    ///
    /// 60 s sits above two full rounds and far below the fault. The incident's
    /// io handler-queue latency was 13.145 s SUSTAINED for 3600 s — a peg does
    /// not recover, so a 60 s threshold still raises 60 s in and once per
    /// repeat_ms thereafter, i.e. ~59 lines inside the hour that produced zero.
    ///
    /// THE CEILING, STATED SO IT IS FALSIFIABLE: this holds while
    ///     io_silence_ms >= 2 * sessions * 733 ms,
    /// i.e. up to 40 attached sessions at 60 s. A pool above ~40 rigs MUST
    /// raise this or D1 will false-positive on it. The value is a config field
    /// for exactly that reason.
    int64_t io_silence_ms{60000};

    /// D2: how many blocks behind an independently observed height the SERVED
    /// height must be. 1 is the ordinary propagation race (we are mid-block, a
    /// peer already has the next one); 2 is not.
    uint32_t height_skew_blocks{2};

    /// D2: and for how long it must stay that way. DASH targets 2.5-minute
    /// blocks, so 120 s cannot be reached by one block's propagation. The
    /// incident's 22-block/1-hour skew clears this in ~5 minutes.
    int64_t height_skew_sustain_ms{120000};

    /// D3: no template handed out at all, while sessions are attached.
    int64_t serve_silence_ms{300000};

    /// Re-alarm cadence for a condition that stays true. Loud, but not a flood.
    int64_t repeat_ms{60000};
};

/// One poll's inputs. All by value — the sentinel thread must never dereference
/// live coin state (that is the 2026-08-05 heap-corruption shape) and must never
/// take a lock the serve path holds.
struct ServeStalenessSample {
    int64_t  now_ms{0};             ///< steady clock, from the SENTINEL's thread.
    int64_t  io_heartbeat_ms{0};    ///< last value the 1 s ioc timer stored; 0 = never.
    uint32_t served_height{0};      ///< last height actually handed to a miner; 0 = never.
    int64_t  served_at_ms{0};       ///< when that happened (steady).
    uint32_t observed_height{0};    ///< independently observed chain height; 0 = unknown.
    std::string observed_src{"none"};  ///< "rpc" | "peer" | "hdr" — which source won.
    /// TRUE only when `observed_height` came from OUTSIDE this process.
    ///
    /// D2 REFUSES TO RUN WHEN THIS IS FALSE, and that refusal is the whole
    /// point of the sub-check. Our own header tip is not an independent
    /// reference: comparing served-height against it is the node measuring
    /// itself, which is precisely the failure mode this file's catalogue
    /// condemns in (b), (c) and (d) above. A D2 that silently degrades to
    /// self-comparison is not a weaker detector, it is a FALSE ONE — it would
    /// have reported "served == observed, all good" for the whole incident
    /// hour. Unknown must render as unknown.
    bool     observed_independent{false};
    uint32_t sessions{0};           ///< attached stratum sessions.
};

/// What a poll concluded.
///
/// `fired` is true only on the polls that OWE A LINE (rate policy). The
/// standing-condition fields below are true whenever the condition holds,
/// whether or not a line was owed — that split exists because the surface and
/// the log must not be able to disagree: during the incident the log knew and
/// the JSON did not.
///
/// EVERY AGE IS ITS OWN FIELD. A single `age_ms` that meant io-silence on one
/// poll and skew-age on the next is how an operator reads a number that is
/// true and concludes something false; the 2026-08-07 confusion started
/// exactly there. `stale_age_ms` is the age of the condition named by
/// `stale_check` AND NOTHING ELSE.
struct ServeStalenessVerdict {
    bool            fired{false};
    StaleServeCheck check{StaleServeCheck::None};  ///< which check emitted `line`.
    std::string     line;        ///< the full "[STALE-SERVE] ..." payload.

    /// ANY sub-check condition currently true — D1, D2 or D3. Not D2 alone:
    /// in the incident as it truly presented, D1 was the only one that could
    /// see anything, and a `stale` that ignored it left the status surface
    /// reporting health for an hour while the log printed 60 alarms.
    bool            stale{false};
    /// Which condition `stale` refers to, most-severe first (D1 > D2 > D3).
    StaleServeCheck stale_check{StaleServeCheck::None};
    /// Age of the condition named by `stale_check`. 0 when none is raised.
    int64_t         stale_age_ms{0};

    /// Per-check ages, always populated, never overwritten by each other.
    int64_t         io_silent_ms{0};    ///< D1: since the io heartbeat last moved.
    int64_t         skew_age_ms{0};     ///< D2: since served fell behind observed.
    int64_t         serve_quiet_ms{0};  ///< D3: since a template was last handed out.

    /// D2 had an INDEPENDENT reference this poll and therefore actually ran.
    /// False means D2 said nothing — which is not the same claim as "no skew"
    /// and must never be rendered as one.
    bool            d2_armed{false};
};

class ServeStalenessSentinel
{
public:
    ServeStalenessSentinel() = default;
    explicit ServeStalenessSentinel(ServeStalenessConfig cfg) : m_cfg(cfg) {}

    const ServeStalenessConfig& config() const { return m_cfg; }

    /// Poll once. Pure function of (sample, accumulated state) — no clock read,
    /// no I/O, no lock. Returns at most ONE verdict per poll, most-severe
    /// first: a dead io thread explains the other two, so saying all three
    /// would be three lines about one fault.
    ServeStalenessVerdict poll(const ServeStalenessSample& s)
    {
        ServeStalenessVerdict v;

        // ── D1: io-thread liveness ──────────────────────────────────────────
        // The heartbeat is written by a 1 s timer ON ioc. We do not read the io
        // thread's state; we read whether it is still able to write a number.
        // A pegged thread stops writing while remaining perfectly "alive" to
        // every self-reported metric — that is the whole point.
        if (s.io_heartbeat_ms > m_last_io_beat) {
            m_last_io_beat  = s.io_heartbeat_ms;
            m_io_beat_seen_at = s.now_ms;
            m_io_wd.progress(s.now_ms);
        }
        if (!m_io_wd.armed() && s.io_heartbeat_ms > 0) {
            m_io_wd = diag::StallWatchdog(m_cfg.io_silence_ms, m_cfg.repeat_ms);
            m_io_wd.arm(s.now_ms);
            m_last_io_beat    = s.io_heartbeat_ms;
            m_io_beat_seen_at = s.now_ms;
        }

        // ── D2: served-vs-observed skew (state kept regardless of who wins) ──
        // Sustain window, so a single-block propagation race cannot raise it.
        //
        // REFUSE-TO-SELF-COMPARE. `observed_independent` is a hard precondition,
        // not a hint. Without an outside height the honest answer is "D2 did not
        // run"; comparing against our own header tip would make the detector
        // agree with the freeze, which is the exact defect this file exists to
        // close. m_skew_since is cleared on refusal so a later real observation
        // starts a fresh sustain window rather than inheriting a stale one.
        v.d2_armed = s.observed_independent && s.observed_height > 0;
        const bool skew_now =
            v.d2_armed && s.served_height > 0 &&
            (static_cast<uint64_t>(s.served_height) + m_cfg.height_skew_blocks
                 <= static_cast<uint64_t>(s.observed_height));
        if (skew_now) {
            if (m_skew_since == 0) m_skew_since = s.now_ms;
        } else {
            m_skew_since = 0;
        }
        const int64_t skew_age =
            m_skew_since == 0 ? 0 : (s.now_ms - m_skew_since);
        const bool skew_sustained =
            skew_now && skew_age >= m_cfg.height_skew_sustain_ms;

        // ── D3: serve silence, only while miners are actually attached ──────
        if (s.served_height > m_last_served_height ||
            s.served_at_ms  > m_last_served_at) {
            m_last_served_height = s.served_height;
            m_last_served_at     = s.served_at_ms;
            m_serve_wd.progress(s.now_ms);
        }
        if (s.sessions > 0) {
            if (!m_serve_wd.armed()) {
                m_serve_wd = diag::StallWatchdog(m_cfg.serve_silence_ms,
                                                 m_cfg.repeat_ms);
                m_serve_wd.arm(s.now_ms);
            }
        } else {
            m_serve_wd.disarm();
        }

        // ── STANDING CONDITIONS — computed BEFORE the rate policy ───────────
        //
        // This block is the C1 fix. Previously `stale` carried D2 only, so the
        // incident as it TRULY presented — io thread pegged, therefore BOTH
        // ioc-written mirrors frozen, therefore observed == served and D2 blind,
        // while the serve path still trickled the dead height to 26 rigs —
        // produced 60 correct [STALE-SERVE] check=io-silence LOG lines and a
        // status surface that said `stale: false` for the whole hour. An
        // operator reading /api/node_topology during the real event saw nothing
        // wrong. The log and the surface must not be able to disagree.
        //
        // `due()` mutates (it is the rate policy), so the standing state is read
        // with the non-mutating elapsed_ms() and is independent of whether a
        // line is owed this poll.
        v.io_silent_ms   = m_io_wd.elapsed_ms(s.now_ms);
        v.skew_age_ms    = skew_age;
        v.serve_quiet_ms = m_serve_wd.elapsed_ms(s.now_ms);

        const bool io_cond =
            m_io_wd.armed() && v.io_silent_ms >= m_cfg.io_silence_ms;
        const bool serve_cond =
            m_serve_wd.armed() && v.serve_quiet_ms >= m_cfg.serve_silence_ms;

        // Same severity order as the lines: a dead io thread explains the other
        // two, so it is what the surface names.
        if (io_cond) {
            v.stale        = true;
            v.stale_check  = StaleServeCheck::IoSilence;
            v.stale_age_ms = v.io_silent_ms;
        } else if (skew_sustained) {
            v.stale        = true;
            v.stale_check  = StaleServeCheck::HeightSkew;
            v.stale_age_ms = v.skew_age_ms;
        } else if (serve_cond) {
            v.stale        = true;
            v.stale_check  = StaleServeCheck::ServeSilence;
            v.stale_age_ms = v.serve_quiet_ms;
        }

        // ── Rate policy + severity order ────────────────────────────────────
        if (auto d = m_io_wd.due(s.now_ms)) {
            v.fired = true;
            v.check = StaleServeCheck::IoSilence;
            v.line  = format_io(s, *d);
            return v;
        }
        if (skew_sustained && owes_skew_line(s.now_ms)) {
            v.fired = true;
            v.check = StaleServeCheck::HeightSkew;
            v.line  = format_skew(s, skew_age);
            return v;
        }
        if (auto d = m_serve_wd.due(s.now_ms)) {
            v.fired = true;
            v.check = StaleServeCheck::ServeSilence;
            v.line  = format_serve_silence(s, *d);
            return v;
        }
        return v;
    }

    /// Total alarms raised, per check. Lets the status surface say "this has
    /// fired N times" rather than only "it is quiet right now" — the two are
    /// not the same claim, and conflating them is how the last silent hour was
    /// read as health.
    uint32_t io_alarms()    const { return m_io_wd.warnings(); }
    uint32_t skew_alarms()  const { return m_skew_alarms; }
    uint32_t serve_alarms() const { return m_serve_wd.warnings(); }

private:
    bool owes_skew_line(int64_t now)
    {
        if (m_skew_warned && (now - m_skew_last_warn) < m_cfg.repeat_ms)
            return false;
        m_skew_last_warn = now;
        m_skew_warned    = true;
        ++m_skew_alarms;
        return true;
    }

    static std::string ms(int64_t v)
    {
        std::ostringstream os;
        os << (static_cast<double>(v) / 1000.0);
        return os.str();
    }

    std::string format_io(const ServeStalenessSample& s, int64_t elapsed) const
    {
        std::ostringstream os;
        os << "[STALE-SERVE] check=io-silence"
           << " served=" << s.served_height
           << " obs=" << s.observed_height
           << " src=" << s.observed_src
           << " io_silent=" << ms(elapsed) << "s"
           << " threshold=" << ms(m_cfg.io_silence_ms) << "s"
           << " sessions=" << s.sessions
           << " — the io thread has not ticked; served work may be dead";
        return os.str();
    }

    std::string format_skew(const ServeStalenessSample& s, int64_t age) const
    {
        std::ostringstream os;
        os << "[STALE-SERVE] check=height-skew"
           << " served=" << s.served_height
           << " obs=" << s.observed_height
           << " src=" << s.observed_src
           << " behind=" << (static_cast<uint64_t>(s.observed_height)
                             - static_cast<uint64_t>(s.served_height))
           << " threshold=" << m_cfg.height_skew_blocks
           << " age=" << ms(age) << "s"
           << " sustain=" << ms(m_cfg.height_skew_sustain_ms) << "s"
           << " sessions=" << s.sessions
           << " — miners are working a height the network has passed";
        return os.str();
    }

    std::string format_serve_silence(const ServeStalenessSample& s,
                                     int64_t elapsed) const
    {
        std::ostringstream os;
        os << "[STALE-SERVE] check=serve-silence"
           << " served=" << s.served_height
           << " obs=" << s.observed_height
           << " src=" << s.observed_src
           << " quiet=" << ms(elapsed) << "s"
           << " threshold=" << ms(m_cfg.serve_silence_ms) << "s"
           << " sessions=" << s.sessions
           << " — no template handed out while miners are attached";
        return os.str();
    }

    ServeStalenessConfig m_cfg{};

    diag::StallWatchdog  m_io_wd{};
    int64_t              m_last_io_beat{0};
    int64_t              m_io_beat_seen_at{0};

    int64_t              m_skew_since{0};
    int64_t              m_skew_last_warn{0};
    bool                 m_skew_warned{false};
    uint32_t             m_skew_alarms{0};

    diag::StallWatchdog  m_serve_wd{};
    uint32_t             m_last_served_height{0};
    int64_t              m_last_served_at{0};
};

}  // namespace coin
}  // namespace dash
