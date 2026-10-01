#pragma once
// V37 Track A2 / Stage 1 SUPPLY — the carrier REPAIR CONTROL CHANNEL.
// CONSUMER-tree code (src/c2pool/v37/). It lets a node that has fallen behind
// (a) ask a peer for the ORDERED carrier ids that peer appended over a lane
// prefix [a, P), and (b) fetch the retained FRAME BYTES for a bounded set of
// those ids, verifying every byte it is handed.
//
// THIS STAGE SUPPLIES AND VERIFIES BYTES. IT DOES NOT APPLY THEM.
// Nothing in this header admits, appends, folds or credits: there is no
// ReceiptAdmitter call, no settle::fold_eb, no engine, no lane. A fetched frame
// comes back to the caller as VERIFIED BYTES and stops there. Under ruling A the
// served ORDER is a peer's verifiable ASSERTION; it is made trustless by Stage
// 2's replay-to-digest, which is deliberately NOT in this header. What IS closed
// here is the byte-level half: a peer cannot hand us bytes that are not the
// carrier we asked for, because we recompute the id from the bytes.
//
// ── THE OPCODE NAMESPACE (frozen here, backward-tolerant by construction) ───
// carrier_net.hpp frames are [u32 LE length][frame] with NO type byte; frame[0]
// is today the CarrierWire version (0x01 / 0x02 live). That first byte is now
// split, permanently:
//
//      0x01 .. 0x7f   CarrierWire VERSIONS   (consensus-bearing carrier bodies)
//      0x80 .. 0xff   CONTROL OPCODES        (transport repair; never consensus)
//
// The control opcodes are NOT wire versions. They are absent from
// w3_wire_freeze.hpp's kAcceptedVersions, CarrierWire::decode rejects them as
// REJECT_BAD_VERSION, and no frozen v0x01 / v0x02 golden moves because of them.
//
// BACKWARD TOLERANCE IS PROVEN, BOTH DIRECTIONS:
//   * an OLD peer (no repair support) that receives a 0x8x frame runs it into
//     CarrierWire::decode, gets REJECT_BAD_VERSION, logs it and KEEPS the
//     socket — carrier_net.hpp's reader_loop breaks only on a short read or an
//     over-long length prefix, never on a decode verdict;
//   * a REPAIR-AWARE node that receives an opcode it does not implement (a
//     future 0x84+) IGNORES it and COUNTS it, and likewise never drops the peer
//     (SupplyService::on_control -> unknown_opcode).
// So the channel can be extended again without a flag day in either direction.
//
// ── THE FOUR FRAMES ─────────────────────────────────────────────────────────
// Little-endian throughout, the same primitive style as CarrierWire. Every
// frame opens with the same 6-byte control header so a decoder can route and
// correlate before it parses anything else.
//
//   ctrl_hdr := u8  opcode (>= 0x80)
//               u8  ctrl_version (= 0x01)
//               u32 request_id            (echoed verbatim in the response)
//
//   GETORDER  (0x80) := ctrl_hdr
//                       u32 chain_id
//                       u64 a                   (inclusive start position)
//                       u64 p                   (exclusive end = the cut P)
//                       b32 cut_spine_digest    (the ASKER's digest at P)
//                       u32 max_ids             (the asker's own answer bound)
//
//   ORDER     (0x81) := ctrl_hdr
//                       u32 chain_id
//                       u64 a
//                       u64 p_served            (exclusive end actually covered)
//                       u64 lowest_retained     (diagnostic: our vault horizon)
//                       u8  status              (CtrlOrderStatus)
//                       u8  have_spine          (0 | 1)
//                       b32 spine_digest        (at p_served; zeros if !have_spine)
//                       u32 n_ids
//                       { u64 pos ; b32 id } x n_ids      (pos strictly increasing)
//
//   GETFRAMES (0x82) := ctrl_hdr
//                       u32 chain_id
//                       u16 n_ids               (<= kCtrlMaxIdsPerFetch)
//                       b32 id x n_ids
//
//   FRAMES    (0x83) := ctrl_hdr
//                       u32 chain_id
//                       u8  status              (CtrlFramesStatus)
//                       u16 cursor              (requested ids CONSUMED, from 0)
//                       u16 n_unservable
//                       b32 id x n_unservable   (each ALONE over the ceiling)
//                       u16 n_frames
//                       { b32 id ; u32 len ; len bytes } x n_frames
//
// An id the server does not hold is simply ABSENT from FRAMES. The server never
// substitutes, pads or fabricates; the requester treats absence as a
// fail-closed outcome for the PREFIX the answer claims to cover.
//
// ── THE CEILING, AND WHY FRAMES CARRIES A CURSOR ────────────────────────────
// carrier_net.hpp refuses any frame longer than kMaxCarrierFrame (1 MiB) by
// BREAKING the socket — it cannot do otherwise, because the length prefix is
// how it finds the next frame boundary. So an over-long reply does not merely
// fail: it costs the HONEST server the HONEST peer that asked. Every reply this
// channel emits is therefore bounded BELOW that ceiling by construction
// (kCtrlMaxReplyBytes, derived from it below and pinned by static_assert), and
// a fetch too big for one reply is COMPLETED by continuation rather than by
// enlarging the reply:
//
//   * the server serves whole frames in the order asked until the byte budget
//     is spent, then answers TRUNCATED with the `cursor` it served through;
//   * the requester verifies that prefix exactly as before and automatically
//     re-asks from the cursor, until the ask is exhausted;
//   * a frame that ALONE exceeds the budget can never be delivered by any
//     chunking, so it is named in `unservable` and the cursor steps PAST it.
//     That is an EXPLICIT answer, distinct from a missing id — never a silent
//     stall, and never a peer drop.
//
// Progress is monotone: a TRUNCATED reply always has cursor >= 1 (the byte
// budget can only bind after at least one frame is in, and an un-servable or
// absent id advances the cursor by itself), so the continuation loop always
// terminates. A peer claiming truncation at cursor 0 is answering nonsense and
// is failed as MALFORMED — the one shape that could otherwise spin forever.
//
// ── WHAT THE REQUESTER VERIFIES, AND WHY IT IS FAIL-CLOSED ──────────────────
// For every (id, bytes) pair a peer returns:
//   1. the bytes must decode as a CarrierWire frame (which already enforces
//      R_MAX and the W3-MUST identity binding), and
//   2. CarrierWire::decode(bytes).carrier.carrier.hash() must EQUAL the id we
//      asked for — the id IS the carrier's WorkEvent::hash, so this is the
//      bytes-to-id binding, recomputed locally from the bytes, not trusted.
// If ANY pair fails, or ANY requested id is missing, or an id arrives twice, or
// an id arrives that we never asked for, the WHOLE response is rejected: the
// caller's success callback is not invoked, nothing is handed on, and the
// failure is counted per peer. Partial acceptance is not offered — a peer that
// lied about one frame has no standing to be believed about the rest.
// A peer that does not answer at all is bounded by request_timeout: the
// outstanding slot expires, `timeouts` is counted, and the request FAILS. No
// path here waits forever, and no path here drops the peer.
//
// ── PER-PEER DoS BOUNDS ─────────────────────────────────────────────────────
//   * TOKEN BUCKET per peer on the SERVE side (capacity + refill/sec). A peer
//     over budget is counted (`throttled`) and answered with NOTHING — a reply
//     is itself the work we are rationing, so a flooding peer gets exactly zero
//     amplification. Its own requester then fails closed on timeout.
//   * ONE OUTSTANDING REQUEST PER PEER on the FETCH side. A second request
//     while one is in flight is refused locally (`refused_busy`); a response
//     that does not match the outstanding (request_id, opcode) is discarded as
//     `unsolicited`. So a peer cannot make us hold unbounded state, and cannot
//     answer a question we did not ask.
//   * BOUNDED ANSWERS. kCtrlMaxIdsPerOrder / kCtrlMaxIdsPerFetch /
//     kCtrlMaxReplyBytes cap every reply, and the asker's own max_ids can only
//     LOWER them, never raise them. Every one of those caps is ALSO clamped to
//     the transport ceiling on the serve path, so a mis-set option cannot make
//     us emit a frame that would drop the peer we are answering.
//   * BOUNDED CONTINUATION. A truncated reply is re-asked at most
//     max_continuations times, and every round consumes at least one requested
//     id, so a fetch cannot be made to loop.
//   * BOUNDED PEER TABLES. Both sides keep at most max_peer_slots entries and
//     evict the least-recently-used, so peer churn cannot grow memory.
//   * FLAP SAFETY. All per-peer state here is keyed by the transport's PeerId,
//     which is fresh on every connection, and holds NO reference into the frame
//     vault: a peer that connects and disconnects repeatedly cannot evict, age
//     or exhaust another peer's entries, and cannot evict anything from the
//     vault at all — the vault is written only by our OWN admissions. (The
//     complementary half lives in w3_relay.hpp: the re-offer attempt cap now
//     retires an entry from the shallow re-offer SUB-VIEW without evicting it
//     from the vault, so a flapping peer arming forced sweeps can no longer
//     burn the retained bytes another peer still needs.)
//
// THREADING: SupplyService and SupplyRequester each take their own mutex and
// never call into the relay or the vault while holding it beyond a copy-out.
// Both are driven from carrier_net.hpp reader threads (one per peer). The send
// they perform is done with NO lock of theirs held.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "carrier_net.hpp"    // CarrierPeerNode::PeerId, kCtrlOpcodeBase
#include "frame_vault.hpp"
#include "w3_relay.hpp"       // CarrierWire (decode -> hash), Carrier

namespace c2pool::v37n {

// ── opcodes (all >= kCtrlOpcodeBase; never a CarrierWire version) ───────────
constexpr std::uint8_t CTRL_GETORDER  = 0x80;   // ask: your order over [a, P)
constexpr std::uint8_t CTRL_ORDER     = 0x81;   // answer to GETORDER
constexpr std::uint8_t CTRL_GETFRAMES = 0x82;   // ask: bytes for these ids
constexpr std::uint8_t CTRL_FRAMES    = 0x83;   // answer to GETFRAMES
constexpr std::uint8_t kCtrlVersion   = 0x01;   // control-frame layout version
constexpr std::size_t  kCtrlHeaderSize = 6;     // opcode + version + u32 request_id

// Hard answer bounds. An asker may request LESS; it can never request more.
constexpr std::uint32_t kCtrlMaxIdsPerOrder  = 4096;
constexpr std::uint16_t kCtrlMaxIdsPerFetch  = 64;

// ── THE REPLY CEILING (derived from the transport, never chosen) ────────────
// kCtrlMaxReplyBytes is the budget for the FRAME PAYLOAD BYTES in one FRAMES
// reply. It is NOT a round number picked by hand: it is the transport's own
// 1 MiB ceiling MINUS everything else that reply can possibly carry, so the
// ENCODED frame is under the ceiling for every shape the encoder can produce.
// (Before this it was 4 MiB — four times the ceiling — so a perfectly honest
// 20 x 64 KiB answer encoded to 1,311,452 bytes and the requester's reader loop
// broke the socket on the length prefix. That is the bug this derivation ends.)
constexpr std::size_t kCtrlReplyCeiling   = static_cast<std::size_t>(kMaxCarrierFrame);
// FRAMES fixed part: ctrl_hdr(6) + chain(4) + status(1) + cursor(2)
//                    + n_unservable(2) + n_frames(2)
constexpr std::size_t kCtrlFramesFixedBytes = kCtrlHeaderSize + 4 + 1 + 2 + 2 + 2;
constexpr std::size_t kCtrlIdBytes          = 32;          // one b32 id
constexpr std::size_t kCtrlFrameEntryBytes  = 32 + 4;      // b32 id + u32 len  (36 B)
// Slack held back on purpose, so a future field added to this reply cannot
// silently eat into the payload budget and re-open the defect.
constexpr std::size_t kCtrlReplyMargin      = 4096;
// Worst case per reply: every requested id un-servable AND every requested id
// answered. Both lists are capped at kCtrlMaxIdsPerFetch, so reserving both is
// strictly more than any single reply can use.
constexpr std::size_t kCtrlFramesReserved =
      kCtrlFramesFixedBytes
    + static_cast<std::size_t>(kCtrlMaxIdsPerFetch) * kCtrlFrameEntryBytes
    + static_cast<std::size_t>(kCtrlMaxIdsPerFetch) * kCtrlIdBytes
    + kCtrlReplyMargin;
constexpr std::size_t kCtrlMaxReplyBytes = kCtrlReplyCeiling - kCtrlFramesReserved;

// ORDER's own bound, for the same reason. It has always fitted (4096 x 40 B =
// 160 KiB), but nothing PINNED that, so a future bump of kCtrlMaxIdsPerOrder
// could have walked it over the ceiling in silence. Now it cannot compile.
constexpr std::size_t kCtrlOrderFixedBytes =
      kCtrlHeaderSize + 4 + 8 + 8 + 8 + 1 + 1 + 32 + 4;
constexpr std::size_t kCtrlOrderEntryBytes = 8 + 32;       // u64 pos + b32 id

static_assert(kCtrlFramesReserved < kCtrlReplyCeiling,
              "FRAMES overhead alone must fit under the transport ceiling");
static_assert(kCtrlFramesFixedBytes
                  + static_cast<std::size_t>(kCtrlMaxIdsPerFetch) * kCtrlFrameEntryBytes
                  + static_cast<std::size_t>(kCtrlMaxIdsPerFetch) * kCtrlIdBytes
                  + kCtrlMaxReplyBytes
              <= kCtrlReplyCeiling - kCtrlReplyMargin,
              "a full FRAMES reply must encode strictly under kMaxCarrierFrame");
static_assert(kCtrlOrderFixedBytes
                  + static_cast<std::size_t>(kCtrlMaxIdsPerOrder) * kCtrlOrderEntryBytes
                  + kCtrlReplyMargin
              <= kCtrlReplyCeiling,
              "a full ORDER reply must encode strictly under kMaxCarrierFrame");

enum class CtrlOrderStatus : std::uint8_t {
    OK            = 0,
    BELOW_HORIZON = 1,   // `a` predates what the server retains
    DISABLED      = 2,   // the server's vault is off
    BAD_RANGE     = 3,   // a > p, or the asker's bounds were nonsense
    // ★ OVER THE PER-PEER BUDGET, SAID OUT LOUD. Not a refusal of the ASK —
    // the server holds the answer and will serve it — a refusal of the TIMING.
    // An asker that gets this backs off and re-sends the SAME request; an
    // asker that does not understand it treats it as any other non-OK status
    // and fails closed, which is exactly what it did before this existed.
    // ADD-ONLY: the byte layout of CtrlOrder is unchanged, so a node built
    // before this value still decodes the frame and still refuses.
    THROTTLED     = 4,
};

struct CtrlGetOrder {
    std::uint32_t request_id = 0;
    std::uint32_t chain = 0;
    std::uint64_t a = 0;
    std::uint64_t p = 0;
    bytes32       cut_spine_digest{};
    std::uint32_t max_ids = kCtrlMaxIdsPerOrder;
};

struct CtrlOrder {
    std::uint32_t             request_id = 0;
    std::uint32_t             chain = 0;
    std::uint64_t             a = 0;
    std::uint64_t             p_served = 0;
    std::uint64_t             lowest_retained = 0;
    CtrlOrderStatus           status = CtrlOrderStatus::OK;
    bool                      have_spine = false;
    bytes32                   spine_digest{};
    std::vector<VaultOrderId> ids;
};

struct CtrlGetFrames {
    std::uint32_t        request_id = 0;
    std::uint32_t        chain = 0;
    std::vector<bytes32> ids;
};

// How much of the ask this reply covers.
enum class CtrlFramesStatus : std::uint8_t {
    COMPLETE  = 0,   // cursor == the number of ids asked for: nothing is left
    TRUNCATED = 1,   // served through `cursor`; ask again from there
    // ★ over the per-peer budget (see CtrlOrderStatus::THROTTLED). cursor is 0
    // and NOTHING was served: the ask is intact and may be re-sent verbatim.
    THROTTLED = 2,
};

struct CtrlFrames {
    std::uint32_t    request_id = 0;
    std::uint32_t    chain = 0;
    CtrlFramesStatus status = CtrlFramesStatus::COMPLETE;
    // Requested ids consumed, counting from the front of the ASK: served,
    // absent and un-servable ids all advance it.
    std::uint16_t    cursor = 0;
    // Held, but the frame alone is over the ceiling — an explicit answer, not
    // an absence. Always inside ids[0, cursor).
    std::vector<bytes32> unservable;
    std::vector<std::pair<bytes32, std::vector<std::uint8_t>>> frames;
};

// ═══════════════════════════════════════════════════════════════════════════
// CtrlWire — the control-frame codec. Pure, allocation-only, no I/O.
// ═══════════════════════════════════════════════════════════════════════════
class CtrlWire {
public:
    static std::uint8_t opcode_of(const std::vector<std::uint8_t>& b) {
        return b.empty() ? 0 : b[0];
    }
    static bool is_control(const std::vector<std::uint8_t>& b) {
        return !b.empty() && b[0] >= kCtrlOpcodeBase;
    }

    // ── encode ──────────────────────────────────────────────────────────────
    static std::vector<std::uint8_t> encode(const CtrlGetOrder& m) {
        std::vector<std::uint8_t> b;
        hdr(b, CTRL_GETORDER, m.request_id);
        u32(b, m.chain); u64(b, m.a); u64(b, m.p);
        b32(b, m.cut_spine_digest);
        u32(b, std::min<std::uint32_t>(m.max_ids, kCtrlMaxIdsPerOrder));
        return b;
    }
    static std::vector<std::uint8_t> encode(const CtrlOrder& m) {
        std::vector<std::uint8_t> b;
        hdr(b, CTRL_ORDER, m.request_id);
        u32(b, m.chain); u64(b, m.a); u64(b, m.p_served); u64(b, m.lowest_retained);
        b.push_back(static_cast<std::uint8_t>(m.status));
        b.push_back(m.have_spine ? 1 : 0);
        b32(b, m.spine_digest);
        u32(b, static_cast<std::uint32_t>(m.ids.size()));
        for (const VaultOrderId& x : m.ids) { u64(b, x.pos); b32(b, x.id); }
        return b;
    }
    static std::vector<std::uint8_t> encode(const CtrlGetFrames& m) {
        std::vector<std::uint8_t> b;
        hdr(b, CTRL_GETFRAMES, m.request_id);
        u32(b, m.chain);
        u16(b, static_cast<std::uint16_t>(m.ids.size()));
        for (const bytes32& id : m.ids) b32(b, id);
        return b;
    }
    static std::vector<std::uint8_t> encode(const CtrlFrames& m) {
        std::vector<std::uint8_t> b;
        b.reserve(encoded_size(m));
        hdr(b, CTRL_FRAMES, m.request_id);
        u32(b, m.chain);
        b.push_back(static_cast<std::uint8_t>(m.status));
        u16(b, m.cursor);
        u16(b, static_cast<std::uint16_t>(m.unservable.size()));
        for (const bytes32& id : m.unservable) b32(b, id);
        u16(b, static_cast<std::uint16_t>(m.frames.size()));
        for (const auto& [id, f] : m.frames) {
            b32(b, id);
            u32(b, static_cast<std::uint32_t>(f.size()));
            b.insert(b.end(), f.begin(), f.end());
        }
        return b;
    }

    // Exactly what encode() will produce, without producing it. The serve path
    // checks this against the transport ceiling BEFORE it ever builds a frame,
    // so an over-long reply is impossible rather than merely improbable.
    static std::size_t encoded_size(const CtrlFrames& m) {
        std::size_t n = kCtrlFramesFixedBytes + m.unservable.size() * kCtrlIdBytes;
        for (const auto& [id, f] : m.frames) {
            (void)id;
            n += kCtrlFrameEntryBytes + f.size();
        }
        return n;
    }
    static std::size_t encoded_size(const CtrlOrder& m) {
        return kCtrlOrderFixedBytes + m.ids.size() * kCtrlOrderEntryBytes;
    }

    // ── decode (every one is total: a malformed frame is `false`, never UB) ──
    static bool decode(const std::vector<std::uint8_t>& b, CtrlGetOrder& m) {
        std::size_t p = 0;
        if (!rd_hdr(b, p, CTRL_GETORDER, m.request_id)) return false;
        return g32(b, p, m.chain) && g64(b, p, m.a) && g64(b, p, m.p) &&
               g32b(b, p, m.cut_spine_digest) && g32(b, p, m.max_ids) && p == b.size();
    }
    static bool decode(const std::vector<std::uint8_t>& b, CtrlOrder& m) {
        std::size_t p = 0;
        if (!rd_hdr(b, p, CTRL_ORDER, m.request_id)) return false;
        std::uint8_t st = 0, hs = 0;
        std::uint32_t n = 0;
        if (!(g32(b, p, m.chain) && g64(b, p, m.a) && g64(b, p, m.p_served) &&
              g64(b, p, m.lowest_retained) && g8(b, p, st) && g8(b, p, hs) &&
              g32b(b, p, m.spine_digest) && g32(b, p, n)))
            return false;
        if (st > static_cast<std::uint8_t>(CtrlOrderStatus::THROTTLED)) return false;
        if (hs > 1) return false;
        if (n > kCtrlMaxIdsPerOrder) return false;       // hard bound, before ANY alloc
        m.status = static_cast<CtrlOrderStatus>(st);
        m.have_spine = (hs == 1);
        m.ids.clear();
        m.ids.reserve(n);
        std::uint64_t prev = 0;
        for (std::uint32_t i = 0; i < n; ++i) {
            VaultOrderId x;
            if (!(g64(b, p, x.pos) && g32b(b, p, x.id))) return false;
            if (i && x.pos <= prev) return false;         // must be strictly increasing
            prev = x.pos;
            m.ids.push_back(x);
        }
        return p == b.size();
    }
    static bool decode(const std::vector<std::uint8_t>& b, CtrlGetFrames& m) {
        std::size_t p = 0;
        if (!rd_hdr(b, p, CTRL_GETFRAMES, m.request_id)) return false;
        std::uint16_t n = 0;
        if (!(g32(b, p, m.chain) && g16(b, p, n))) return false;
        if (n > kCtrlMaxIdsPerFetch) return false;       // hard bound, before ANY alloc
        m.ids.clear();
        m.ids.reserve(n);
        for (std::uint16_t i = 0; i < n; ++i) {
            bytes32 id{};
            if (!g32b(b, p, id)) return false;
            m.ids.push_back(id);
        }
        return p == b.size();
    }
    static bool decode(const std::vector<std::uint8_t>& b, CtrlFrames& m) {
        std::size_t p = 0;
        if (!rd_hdr(b, p, CTRL_FRAMES, m.request_id)) return false;
        std::uint8_t st = 0;
        std::uint16_t nu = 0, n = 0;
        if (!(g32(b, p, m.chain) && g8(b, p, st) && g16(b, p, m.cursor) &&
              g16(b, p, nu)))
            return false;
        if (st > static_cast<std::uint8_t>(CtrlFramesStatus::THROTTLED)) return false;
        if (nu > kCtrlMaxIdsPerFetch) return false;      // hard bound, before ANY alloc
        if (m.cursor > kCtrlMaxIdsPerFetch) return false;
        m.status = static_cast<CtrlFramesStatus>(st);
        m.unservable.clear();
        m.unservable.reserve(nu);
        for (std::uint16_t i = 0; i < nu; ++i) {
            bytes32 id{};
            if (!g32b(b, p, id)) return false;
            m.unservable.push_back(id);
        }
        if (!g16(b, p, n)) return false;
        if (n > kCtrlMaxIdsPerFetch) return false;
        m.frames.clear();
        m.frames.reserve(n);
        for (std::uint16_t i = 0; i < n; ++i) {
            bytes32 id{};
            std::uint32_t len = 0;
            if (!(g32b(b, p, id) && g32(b, p, len))) return false;
            if (len > kMaxCarrierFrame) return false;     // transport's own ceiling
            if (b.size() - p < len) return false;
            std::vector<std::uint8_t> f(b.begin() + static_cast<std::ptrdiff_t>(p),
                                        b.begin() + static_cast<std::ptrdiff_t>(p + len));
            p += len;
            m.frames.emplace_back(id, std::move(f));
        }
        return p == b.size();
    }

private:
    static void hdr(std::vector<std::uint8_t>& b, std::uint8_t op, std::uint32_t rid) {
        b.push_back(op);
        b.push_back(kCtrlVersion);
        u32(b, rid);
    }
    static bool rd_hdr(const std::vector<std::uint8_t>& b, std::size_t& p,
                       std::uint8_t want_op, std::uint32_t& rid) {
        std::uint8_t op = 0, ver = 0;
        if (!g8(b, p, op) || !g8(b, p, ver)) return false;
        if (op != want_op || ver != kCtrlVersion) return false;
        return g32(b, p, rid);
    }
    static void u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    static void u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    static void u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    static void b32(std::vector<std::uint8_t>& b, const bytes32& h) {
        b.insert(b.end(), h.begin(), h.end());
    }
    static bool g8(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint8_t& v) {
        if (p + 1 > b.size()) return false;
        v = b[p++];
        return true;
    }
    static bool g16(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint16_t& v) {
        if (p + 2 > b.size()) return false;
        v = 0;
        for (int i = 0; i < 2; ++i) v |= static_cast<std::uint16_t>(b[p + i]) << (8 * i);
        p += 2;
        return true;
    }
    static bool g32(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint32_t& v) {
        if (p + 4 > b.size()) return false;
        v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(b[p + i]) << (8 * i);
        p += 4;
        return true;
    }
    static bool g64(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint64_t& v) {
        if (p + 8 > b.size()) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(b[p + i]) << (8 * i);
        p += 8;
        return true;
    }
    static bool g32b(const std::vector<std::uint8_t>& b, std::size_t& p, bytes32& h) {
        if (p + 32 > b.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = b[p + i];
        p += 32;
        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// SupplyService — the SERVE side. Answers GETORDER / GETFRAMES out of the
// FrameVault, under a per-peer token bucket. It never admits, never appends.
// ═══════════════════════════════════════════════════════════════════════════
struct SupplyServeOptions {
    bool          enabled            = true;
    // Per-peer token bucket: `burst` requests immediately, then `refill_per_sec`.
    double        burst              = 8.0;
    double        refill_per_sec     = 2.0;
    std::uint32_t max_ids_per_order  = kCtrlMaxIdsPerOrder;
    std::uint16_t max_ids_per_fetch  = kCtrlMaxIdsPerFetch;
    // Payload budget for ONE FRAMES reply. Every use of it is CLAMPED to
    // kCtrlMaxReplyBytes on the serve path (see clamped_reply_budget), so
    // raising it here cannot make us emit a frame the transport would refuse —
    // the option can only ever make replies SMALLER, which costs another
    // continuation round and nothing else.
    std::size_t   max_reply_bytes    = kCtrlMaxReplyBytes;
    std::size_t   max_peer_slots     = 256;    // LRU-bounded peer table
    // ★ ANSWER THE THROTTLE INSTEAD OF DROPPING IT (F-1).
    // A silent drop is indistinguishable, from the asker's side, from a dead
    // peer: its request slot sits until request_timeout expires it, and the
    // repair that owned the slot is refused for a reason that never happened.
    // With this on, an over-budget request is answered with a THROTTLED status
    // and NOTHING else — no vault read, no ids, no frames — so the asker can
    // back off and re-send. The refusal is cheap and cannot be an
    // amplification lever: a THROTTLED FRAMES reply is 16 bytes against a
    // GETFRAMES ask of up to 2 KiB, and a THROTTLED ORDER reply is 71 bytes
    // against a 61-byte ask (1.16x, with no vault work behind it).
    bool          reply_throttled    = true;
};

// The three serve-side bounds, each clamped to what the transport can carry.
// Read them through these, never from the options directly.
inline std::size_t clamped_reply_budget(const SupplyServeOptions& o) {
    return std::min<std::size_t>(o.max_reply_bytes ? o.max_reply_bytes
                                                   : kCtrlMaxReplyBytes,
                                 kCtrlMaxReplyBytes);
}
// At least 1: a zero frame cap would consume no id and stall the continuation.
inline std::size_t clamped_frames_per_reply(const SupplyServeOptions& o) {
    return std::max<std::size_t>(
        1, std::min<std::size_t>(o.max_ids_per_fetch, kCtrlMaxIdsPerFetch));
}
inline std::size_t clamped_ids_per_order(const SupplyServeOptions& o) {
    return std::max<std::size_t>(
        1, std::min<std::size_t>(o.max_ids_per_order, kCtrlMaxIdsPerOrder));
}

struct SupplyServeStats {
    std::uint64_t requests        = 0;   // control frames routed here
    std::uint64_t order_served    = 0;
    std::uint64_t order_ids       = 0;
    std::uint64_t frames_served   = 0;
    std::uint64_t bytes_served    = 0;
    std::uint64_t throttled       = 0;   // over the per-peer token bucket
    std::uint64_t throttled_replied = 0; // ★ of those, answered with THROTTLED
                                         //   (the rest are the legacy silent drop)
    std::uint64_t malformed       = 0;   // a control frame that did not decode
    std::uint64_t unknown_opcode  = 0;   // >= 0x80 but not one we implement
    std::uint64_t disabled_drop   = 0;
    std::uint64_t send_failed     = 0;
    std::uint64_t peers_evicted   = 0;   // LRU eviction of the peer table
    std::uint64_t frames_truncated = 0;  // ★ replies cut at the budget (cursor sent)
    std::uint64_t frames_unservable = 0; // ★ ids whose frame ALONE is over the ceiling
    std::uint64_t reply_oversize  = 0;   // ★ a reply that would have breached the
                                         //   transport ceiling: NEVER sent. Zero by
                                         //   construction; counted so a regression
                                         //   shows up as a number, not a dropped peer.
};

class SupplyService {
public:
    using PeerId = CarrierPeerNode::PeerId;
    using Clock  = std::chrono::steady_clock;
    // Bound to CarrierPeerNode::send_to. Returns false if the peer is gone.
    using SendFn = std::function<bool(PeerId, const std::vector<std::uint8_t>&)>;
    // Optional: our own committed lane digest at a given prefix. Bind to
    // V37Engine::settlement_view_at(...)->digest (or a snapshot read). Unbound
    // => ORDER answers have_spine = 0 and carries zeros. It is an ASSERTION
    // either way (ruling A); Stage 2 replays to check it.
    using SpineFn = std::function<std::optional<bytes32>(std::uint32_t chain,
                                                         std::uint64_t pos)>;
    // ★ THE CUT PROBE (optional, additive). "Did I PUBLISH a settlement view at
    // exactly this (pos, spine)?" — the asker's OWN cut, checked against our
    // ring. Bind to V37Engine::settlement_view_by_cut(...) != nullptr.
    //
    // It answers the only question a repair actually asks ("do you hold the
    // prefix the winner named?"), which the position-keyed SpineFn cannot: a
    // node whose lane has moved past `pos` has no snapshot AT pos and so
    // asserts nothing, even when it published that very cut minutes ago.
    // Positive-only by construction: a `true` means our committed digest at
    // `pos` IS the asked one, so putting it in `spine_digest` keeps that field's
    // meaning (the SERVER's own digest at p_served) exactly as it was. A
    // `false` asserts nothing — the replay, not this probe, decides.
    using CutProbeFn = std::function<bool(std::uint32_t chain, std::uint64_t pos,
                                          const bytes32& spine)>;
    // Injectable clock, for tests that compress time. Unbound => steady_clock.
    // The token bucket refills in REAL seconds; a harness that drives hours of
    // block production through in wall-seconds has to be able to say so.
    using NowFn = std::function<Clock::time_point()>;

    SupplyService(FrameVault& vault, SendFn send)
        : m_vault(vault), m_send(std::move(send)) {}

    void set_options(const SupplyServeOptions& o) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_opt = o;
    }
    SupplyServeOptions options() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_opt;
    }
    SupplyServeStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_stats;
    }
    void set_spine_probe(SpineFn f) {
        std::lock_guard<std::mutex> lk(m_mtx); m_spine = std::move(f);
    }
    void set_cut_probe(CutProbeFn f) {
        std::lock_guard<std::mutex> lk(m_mtx); m_cut = std::move(f);
    }
    void set_clock(NowFn f) {
        std::lock_guard<std::mutex> lk(m_mtx); m_now = std::move(f);
    }
    void forget_peer(PeerId id) {
        std::lock_guard<std::mutex> lk(m_mtx); m_peers.erase(id);
    }
    std::size_t tracked_peers() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_peers.size();
    }

    // Entry point from carrier_net.hpp's reader thread. `frame[0] >= 0x80` has
    // already been checked by the demux. NEVER drops the peer, NEVER throws:
    // every bad shape is counted and ignored.
    void on_control(PeerId peer, const std::vector<std::uint8_t>& frame) {
        if (frame.empty() || frame[0] < kCtrlOpcodeBase) return;
        const std::uint8_t op = frame[0];

        SupplyServeOptions opt;
        SpineFn spine;
        CutProbeFn cutp;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.requests;
            if (!m_opt.enabled) { ++m_stats.disabled_drop; return; }
            // Responses are not our business: we are the SERVER. A node that is
            // both (the normal case) routes them to SupplyRequester as well.
            if (op != CTRL_GETORDER && op != CTRL_GETFRAMES) {
                if (op != CTRL_ORDER && op != CTRL_FRAMES) ++m_stats.unknown_opcode;
                return;
            }
            opt = m_opt;
            spine = m_spine;
            cutp = m_cut;
        }

        // ── DECODE FIRST, THEN SPEND THE TOKEN ──────────────────────────────
        // A refusal has to name the request it refuses (request_id, chain), so
        // the shape is read before the budget is consulted. That is bounded
        // work over bytes already in hand — no vault read, no allocation past
        // the hard id caps the decoder enforces — and a frame that does not
        // decode is not a request at all: it is counted malformed and costs
        // the asker nothing but also buys it nothing.
        CtrlGetOrder qo;
        CtrlGetFrames qf;
        if (op == CTRL_GETORDER) {
            if (!CtrlWire::decode(frame, qo)) { bump_malformed(); return; }
        } else {
            if (!CtrlWire::decode(frame, qf)) { bump_malformed(); return; }
        }

        bool have_token = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            have_token = take_token_locked(peer);
            if (!have_token) ++m_stats.throttled;
        }
        if (!have_token) {
            // ★ F-1: SAY SO. The old code returned here with no reply at all,
            // which the asker could only discover as a 5 s timeout — and a
            // repair that issues ceil(P/4096) + ceil(P/64) requests back to
            // back runs out of burst part-way through and dies on that
            // timeout, at a prefix set by the bucket rather than by anything
            // about the data. An explicit THROTTLED is a fast, cheap, honest
            // answer the asker can back off on and re-send.
            if (!opt.reply_throttled) return;      // the legacy silent drop
            std::vector<std::uint8_t> refusal;
            if (op == CTRL_GETORDER) {
                CtrlOrder r;
                r.request_id = qo.request_id;
                r.chain = qo.chain;
                r.a = qo.a;
                r.p_served = qo.a;                 // nothing served
                r.status = CtrlOrderStatus::THROTTLED;
                refusal = CtrlWire::encode(r);
            } else {
                CtrlFrames r;
                r.request_id = qf.request_id;
                r.chain = qf.chain;
                r.status = CtrlFramesStatus::THROTTLED;
                r.cursor = 0;                      // nothing consumed
                refusal = CtrlWire::encode(r);
            }
            { std::lock_guard<std::mutex> lk(m_mtx); ++m_stats.throttled_replied; }
            if (m_send && !m_send(peer, refusal)) {
                std::lock_guard<std::mutex> lk(m_mtx);
                ++m_stats.send_failed;
            }
            return;
        }

        std::vector<std::uint8_t> reply;
        if (op == CTRL_GETORDER) {
            const CtrlGetOrder& q = qo;
            const std::size_t cap = clamped_ids_per_order(opt);
            const std::size_t want =
                std::min<std::size_t>(q.max_ids ? q.max_ids : cap, cap);
            const VaultOrder vo = m_vault.serve_order(q.chain, q.a, q.p, want);
            CtrlOrder r;
            r.request_id = q.request_id;
            r.chain = q.chain;
            r.a = vo.a;
            r.p_served = vo.p_served;
            r.lowest_retained = vo.lowest_retained;
            r.status = map_status(vo.status);
            r.ids = vo.ids;
            if (r.status == CtrlOrderStatus::OK) {
                // ★ The CUT probe first: it answers at ANY retained prefix, and
                // it answers the asker's own question. Only when the whole ask
                // was served ([a, p) complete at p) does it address the cut the
                // asker named; a truncated leg falls back to the position probe.
                if (cutp && vo.p_served == q.p &&
                    cutp(q.chain, vo.p_served, q.cut_spine_digest)) {
                    r.have_spine = true;
                    r.spine_digest = q.cut_spine_digest;
                } else if (spine) {
                    if (auto d = spine(q.chain, vo.p_served)) {
                        r.have_spine = true;
                        r.spine_digest = *d;
                    }
                }
            }
            reply = CtrlWire::encode(r);
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.order_served;
            m_stats.order_ids += r.ids.size();
        } else {
            const CtrlGetFrames& q = qf;
            // ★ THE CEILING, ENFORCED WHERE THE BYTES ARE CHOSEN. Both bounds
            // are the CLAMPED ones, so however the options are set the reply is
            // built to fit under kMaxCarrierFrame.
            std::vector<std::pair<bytes32, std::vector<std::uint8_t>>> out;
            const VaultServeChunk ch = m_vault.serve_frames_chunk(
                q.ids, clamped_frames_per_reply(opt), clamped_reply_budget(opt), out);
            CtrlFrames r;
            r.request_id = q.request_id;
            r.chain = q.chain;
            r.status = ch.truncated ? CtrlFramesStatus::TRUNCATED
                                    : CtrlFramesStatus::COMPLETE;
            r.cursor = static_cast<std::uint16_t>(
                std::min<std::size_t>(ch.cursor, kCtrlMaxIdsPerFetch));
            r.unservable = ch.unservable;
            r.frames = std::move(out);
            std::size_t nb = 0;
            for (const auto& [id, f] : r.frames) { (void)id; nb += f.size(); }
            // Belt AND braces: the derivation above makes this unreachable, so
            // if it ever fires the derivation broke. Refuse to send rather than
            // hand the honest peer a frame its reader loop must break on.
            const std::size_t sz = CtrlWire::encoded_size(r);
            if (sz > kCtrlReplyCeiling) {
                std::lock_guard<std::mutex> lk(m_mtx);
                ++m_stats.reply_oversize;
                return;
            }
            reply = CtrlWire::encode(r);
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.frames_served;
            m_stats.bytes_served += nb;
            if (ch.truncated) ++m_stats.frames_truncated;
            m_stats.frames_unservable += ch.unservable.size();
        }

        // The ORDER path's own ceiling check. Also unreachable (the
        // static_assert on kCtrlMaxIdsPerOrder pins it at compile time), and
        // also counted rather than assumed.
        if (reply.size() > kCtrlReplyCeiling) {
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.reply_oversize;
            return;
        }

        // Sent with NO lock of ours held: a slow peer stalls only its own
        // socket (carrier_net.hpp per-descriptor write lock + SO_SNDTIMEO).
        if (m_send && !m_send(peer, reply)) {
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.send_failed;
        }
    }

private:
    static CtrlOrderStatus map_status(VaultOrderStatus s) {
        switch (s) {
            case VaultOrderStatus::OK:            return CtrlOrderStatus::OK;
            case VaultOrderStatus::BELOW_HORIZON: return CtrlOrderStatus::BELOW_HORIZON;
            case VaultOrderStatus::DISABLED:      return CtrlOrderStatus::DISABLED;
            case VaultOrderStatus::BAD_RANGE:     return CtrlOrderStatus::BAD_RANGE;
        }
        return CtrlOrderStatus::BAD_RANGE;
    }
    void bump_malformed() {
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_stats.malformed;
    }

    struct Bucket {
        double            tokens = 0.0;
        Clock::time_point last{};
        Clock::time_point touched{};
    };

    // Per-peer token bucket + LRU-bounded peer table. Peer churn cannot grow
    // memory, and one peer's budget is entirely its own.
    bool take_token_locked(PeerId peer) {
        const Clock::time_point now = m_now ? m_now() : Clock::now();
        auto it = m_peers.find(peer);
        if (it == m_peers.end()) {
            evict_lru_locked();
            Bucket b;
            b.tokens = m_opt.burst;
            b.last = now;
            b.touched = now;
            it = m_peers.emplace(peer, b).first;
        } else {
            const double dt =
                std::chrono::duration<double>(now - it->second.last).count();
            it->second.tokens =
                std::min(m_opt.burst, it->second.tokens + dt * m_opt.refill_per_sec);
            it->second.last = now;
            it->second.touched = now;
        }
        if (it->second.tokens < 1.0) return false;
        it->second.tokens -= 1.0;
        return true;
    }
    void evict_lru_locked() {
        while (m_peers.size() + 1 > m_opt.max_peer_slots && !m_peers.empty()) {
            auto victim = m_peers.begin();
            for (auto i = m_peers.begin(); i != m_peers.end(); ++i)
                if (i->second.touched < victim->second.touched) victim = i;
            m_peers.erase(victim);
            ++m_stats.peers_evicted;
        }
    }

    FrameVault&              m_vault;
    SendFn                   m_send;
    SpineFn                  m_spine;
    CutProbeFn               m_cut;
    NowFn                    m_now;
    mutable std::mutex       m_mtx;
    SupplyServeOptions       m_opt{};
    SupplyServeStats         m_stats{};
    std::map<PeerId, Bucket> m_peers;
};

// ═══════════════════════════════════════════════════════════════════════════
// SupplyRequester — the FETCH side. One outstanding request per peer, every
// returned frame verified against the id we asked for, fail-closed throughout.
// It hands the caller VERIFIED BYTES and nothing else: no admit, no fold.
// ═══════════════════════════════════════════════════════════════════════════
enum class SupplyFailure : std::uint8_t {
    TIMEOUT,          // the peer did not answer inside request_timeout
    MALFORMED,        // the answer did not decode
    UNSOLICITED,      // right opcode, wrong request_id (or none outstanding)
    HASH_MISMATCH,    // ★ a peer handed us bytes that are not the id we asked for
    MISSING_ID,       // ★ an id we asked for was absent from the answer
    DUPLICATE_ID,     // the same id twice in one answer
    UNDECODABLE_FRAME,// the served bytes are not a valid CarrierWire frame
    SERVER_REFUSED,   // ORDER came back with a non-OK status
    UNSERVABLE_ID,    // ★ the server HOLDS it, but the frame alone is over the
                      //   transport ceiling: it can never be delivered here.
                      //   DISTINCT from MISSING_ID, and never a stall.
    CONTINUATION_LIMIT,// a truncated fetch needed more rounds than allowed
    THROTTLED,        // ★ the server kept saying "over budget" and we ran out of
                      //   re-sends. Fail-closed, exactly like any other refusal.
};

struct SupplyFetchOptions {
    std::chrono::milliseconds request_timeout{5000};
    std::uint16_t             max_ids_per_fetch = kCtrlMaxIdsPerFetch;
    std::size_t               max_peer_slots    = 256;
    // ── ★ THE BACKOFF (F-1, asker's half) ───────────────────────────────────
    // A THROTTLED answer says the server holds the data and will serve it, just
    // not now. Re-send the SAME request after a backoff that doubles from
    // `throttle_backoff` and is capped at `throttle_backoff_max`, at most
    // `max_throttle_retries` times; after that the fetch fails closed with
    // SupplyFailure::THROTTLED. Bounded in BOTH directions: a fetch can consume
    // at most max_throttle_retries extra round trips per request, and a server
    // that throttles forever produces a refusal rather than a hang. The default
    // schedule (250 ms doubling to 2 s, 8 times) spans ~9 s, which is more than
    // the 4 s a shipped bucket (burst 8, 2/s) needs to refill completely.
    std::chrono::milliseconds throttle_backoff{250};
    std::chrono::milliseconds throttle_backoff_max{2000};
    std::uint32_t             max_throttle_retries = 8;
    // How many follow-up GETFRAMES one fetch may issue when the server answers
    // TRUNCATED. Every round consumes at least one requested id and a fetch
    // asks at most kCtrlMaxIdsPerFetch ids, so the default can never bind in
    // practice; it exists so a peer that answers nonsense still terminates.
    std::uint32_t             max_continuations = 128;
};

struct SupplyFetchStats {
    std::uint64_t orders_requested = 0;
    std::uint64_t orders_ok        = 0;
    std::uint64_t frames_requested = 0;
    std::uint64_t frames_ok        = 0;   // whole responses fully verified
    std::uint64_t frames_verified  = 0;   // individual frames that verified
    std::uint64_t hash_mismatch    = 0;   // ★ fail-closed: bytes != id
    std::uint64_t missing_id       = 0;   // ★ fail-closed: id never answered
    std::uint64_t duplicate_id     = 0;
    std::uint64_t undecodable      = 0;
    std::uint64_t timeouts         = 0;
    std::uint64_t refused_busy     = 0;   // one outstanding request per peer
    std::uint64_t unsolicited      = 0;
    std::uint64_t malformed        = 0;
    std::uint64_t server_refused   = 0;
    std::uint64_t send_failed      = 0;
    std::uint64_t truncated_replies = 0;  // ★ answers that covered only a prefix
    std::uint64_t continuations     = 0;  // ★ follow-up GETFRAMES we issued
    std::uint64_t fetches_completed = 0;  // ★ asks driven through to the last id
    std::uint64_t unservable_id     = 0;  // ★ ids the server named un-servable
    std::uint64_t continuation_limit = 0; // ★ a fetch stopped by max_continuations
    std::uint64_t throttled_replies  = 0; // ★ answers that said "over budget"
    std::uint64_t throttle_retries   = 0; // ★ re-sends those cost us
    std::uint64_t throttle_exhausted = 0; // ★ fetches that ran out of re-sends
};

// A frame that PASSED verification: the bytes, and the decoded carrier, with
// hash(decoded) == id proven locally. Handing the decoded carrier along saves
// the caller a second decode; it does NOT make it admitted.
struct VerifiedFrame {
    bytes32                   id{};
    std::vector<std::uint8_t> frame;
    Carrier                   carrier;
};

class SupplyRequester {
public:
    using PeerId = CarrierPeerNode::PeerId;
    using Clock  = std::chrono::steady_clock;
    using SendFn = std::function<bool(PeerId, const std::vector<std::uint8_t>&)>;
    using OrderFn  = std::function<void(PeerId, const CtrlOrder&)>;
    using FramesFn = std::function<void(PeerId, const std::vector<VerifiedFrame>&)>;
    using FailFn   = std::function<void(PeerId, SupplyFailure)>;
    // Ids the server holds but cannot put on this channel (each frame alone is
    // over the transport ceiling). Delivered ALONGSIDE the verified frames of
    // the same answer, so a caller learns exactly which ids to obtain another
    // way instead of waiting for bytes that will never come.
    using UnservableFn = std::function<void(PeerId, const std::vector<bytes32>&)>;
    // Injectable clock (see SupplyService::NowFn). tick() still takes an
    // explicit `now` so a harness can drive the deadline edge directly; when it
    // does, it must drive the SERVE side's clock with the same value or the two
    // halves disagree about how much time the token bucket has had to refill.
    using NowFn = std::function<Clock::time_point()>;

    explicit SupplyRequester(SendFn send) : m_send(std::move(send)) {}

    void set_options(const SupplyFetchOptions& o) {
        std::lock_guard<std::mutex> lk(m_mtx); m_opt = o;
    }
    SupplyFetchOptions options() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_opt;
    }
    SupplyFetchStats stats() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_stats;
    }
    void set_on_order(OrderFn f)   { std::lock_guard<std::mutex> lk(m_mtx); m_on_order = std::move(f); }
    void set_on_frames(FramesFn f) { std::lock_guard<std::mutex> lk(m_mtx); m_on_frames = std::move(f); }
    void set_on_fail(FailFn f)     { std::lock_guard<std::mutex> lk(m_mtx); m_on_fail = std::move(f); }
    void set_on_unservable(UnservableFn f) {
        std::lock_guard<std::mutex> lk(m_mtx); m_on_unservable = std::move(f);
    }
    // GAP-2 SEAM (IdOfFrameFn): how the id of a served frame is recomputed from
    // its BYTES. Unset (the default, every Family-A caller) = the CarrierWire
    // path below, unchanged. The Family-B receipt relay binds it to
    // "decode fb_receipt -> keccak256(hashing_blob)" so a served receipt is
    // held to the same bytes-to-id binding a carrier is; nullopt = undecodable.
    // VerifiedFrame::carrier stays default-constructed on this path.
    using IdOfFrameFn = std::function<std::optional<bytes32>(const std::vector<std::uint8_t>&)>;
    void set_id_of_frame(IdOfFrameFn f) {
        std::lock_guard<std::mutex> lk(m_mtx); m_id_of_frame = std::move(f);
    }
    void set_clock(NowFn f) { std::lock_guard<std::mutex> lk(m_mtx); m_now = std::move(f); }

    bool busy(PeerId p) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_out.find(p) != m_out.end();
    }
    std::size_t outstanding() const {
        std::lock_guard<std::mutex> lk(m_mtx); return m_out.size();
    }
    // A disconnected peer's outstanding slot is released immediately; nothing
    // here survives the connection, so a flapping peer accumulates no state.
    void forget_peer(PeerId p) {
        std::lock_guard<std::mutex> lk(m_mtx); m_out.erase(p);
    }

    // ── ask: your ordered carrier ids over [a, P) ───────────────────────────
    // false => refused locally (already one request outstanding to this peer,
    // or the send failed). Never blocks, never waits.
    bool request_order(PeerId peer, std::uint32_t chain, std::uint64_t a,
                       std::uint64_t p, const bytes32& my_spine_at_p,
                       std::uint32_t max_ids = kCtrlMaxIdsPerOrder) {
        CtrlGetOrder q;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_out.count(peer)) { ++m_stats.refused_busy; return false; }
            evict_lru_locked();
            q.request_id = ++m_next_rid;
            q.chain = chain;
            q.a = a;
            q.p = p;
            q.cut_spine_digest = my_spine_at_p;
            q.max_ids = std::min(max_ids, kCtrlMaxIdsPerOrder);
            Outstanding o;
            o.request_id = q.request_id;
            o.expect = CTRL_ORDER;
            o.deadline = now_locked() + m_opt.request_timeout;
            o.chain = chain;
            o.a = a;
            o.p = p;
            o.spine = my_spine_at_p;
            o.max_ids = q.max_ids;
            m_out.emplace(peer, std::move(o));
            ++m_stats.orders_requested;
        }
        return dispatch(peer, CtrlWire::encode(q));
    }

    // ── ask: the bytes for these ids ────────────────────────────────────────
    // The ASK is bounded by max_ids_per_fetch; the ANSWER is bounded by the
    // transport ceiling, which is a different bound entirely. When the server
    // cannot fit the whole ask in one reply it says so with a cursor, and this
    // class re-asks from there until the ask is exhausted — the caller sees the
    // same verified-bytes callback, one invocation per verified chunk, and does
    // not have to know the fetch was split.
    bool request_frames(PeerId peer, std::uint32_t chain, std::vector<bytes32> ids) {
        CtrlGetFrames q;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (ids.empty() || ids.size() > m_opt.max_ids_per_fetch) return false;
            if (m_out.count(peer)) { ++m_stats.refused_busy; return false; }
            evict_lru_locked();
            Outstanding o;
            o.chain = chain;
            o.ids = std::move(ids);
            o.from = 0;
            arm_frames_locked(peer, o, q);
            ++m_stats.frames_requested;
        }
        return dispatch(peer, CtrlWire::encode(q));
    }

    // ── responses in ────────────────────────────────────────────────────────
    // Called from the reader thread for any frame[0] >= 0x80. Requests
    // (GETORDER / GETFRAMES) are not ours — they belong to SupplyService — and
    // an opcode we do not implement is IGNORED, never a peer drop.
    void on_control(PeerId peer, const std::vector<std::uint8_t>& frame) {
        if (frame.empty() || frame[0] < kCtrlOpcodeBase) return;
        const std::uint8_t op = frame[0];
        if (op != CTRL_ORDER && op != CTRL_FRAMES) return;   // not a response to us

        if (op == CTRL_ORDER) {
            CtrlOrder r;
            if (!CtrlWire::decode(frame, r)) { fail(peer, SupplyFailure::MALFORMED, true); return; }
            Outstanding o;
            if (!claim(peer, CTRL_ORDER, r.request_id, o)) {
                fail(peer, SupplyFailure::UNSOLICITED, false);
                return;
            }
            // ★ F-1: "over budget" is not a refusal of the ASK. Re-send it,
            // after a backoff, a bounded number of times.
            if (r.status == CtrlOrderStatus::THROTTLED) {
                schedule_retry(peer, std::move(o));
                return;
            }
            if (r.status != CtrlOrderStatus::OK) {
                // ★ F-4: the STATUS reaches the caller. Every non-OK ORDER used
                // to become an opaque SERVER_REFUSED with the order callback
                // never invoked, which made RepairDriver::on_order's
                // BELOW_HORIZON branch dead code and left `order_failed` at
                // zero while the vault horizon was refusing hundreds of
                // repairs. The answer IS an answer: hand it over, with its
                // status and its lowest_retained intact, and report the failure
                // afterwards so a caller that only watches failures still sees
                // one.
                OrderFn ocb;
                { std::lock_guard<std::mutex> lk(m_mtx); ocb = m_on_order; }
                if (ocb) ocb(peer, r);
                fail(peer, SupplyFailure::SERVER_REFUSED, false);
                return;
            }
            OrderFn cb;
            {
                std::lock_guard<std::mutex> lk(m_mtx);
                ++m_stats.orders_ok;
                cb = m_on_order;
            }
            if (cb) cb(peer, r);
            return;
        }

        CtrlFrames r;
        if (!CtrlWire::decode(frame, r)) { fail(peer, SupplyFailure::MALFORMED, true); return; }
        Outstanding o;
        if (!claim_frames(peer, r.request_id, o)) {
            fail(peer, SupplyFailure::UNSOLICITED, false);
            return;
        }
        if (r.status == CtrlFramesStatus::THROTTLED) {
            // Nothing was served and nothing was consumed: ids[from, to) is
            // still exactly the ask. Re-send it verbatim after the backoff.
            if (r.cursor != 0 || !r.frames.empty() || !r.unservable.empty()) {
                fail(peer, SupplyFailure::MALFORMED, false);
                return;
            }
            schedule_retry(peer, std::move(o));
            return;
        }

        // ── WHAT THE ANSWER IS ALLOWED TO CLAIM ─────────────────────────────
        // The chunk we asked for is ids[from, to). `cursor` is how much of THAT
        // the answer covers. Three shapes are nonsense and are refused before
        // any verification, because each of them would either hide a missing id
        // or spin the continuation loop:
        //   * a cursor past the chunk we asked for;
        //   * COMPLETE that does not cover the whole chunk;
        //   * TRUNCATED at cursor 0 — no progress, so re-asking would repeat
        //     forever. The serve side cannot produce it (an absent or
        //     un-servable id advances the cursor by itself, and the byte budget
        //     can only bind once a frame is already in), so a peer that sends it
        //     is misbehaving, not merely constrained.
        const std::size_t chunk = o.to - o.from;
        const bool truncated = (r.status == CtrlFramesStatus::TRUNCATED);
        if (r.cursor > chunk ||
            (!truncated && r.cursor != chunk) ||
            (truncated && r.cursor == 0)) {
            fail(peer, SupplyFailure::MALFORMED, false);
            return;
        }
        const std::vector<bytes32> covered(o.ids.begin() + static_cast<std::ptrdiff_t>(o.from),
                                           o.ids.begin() + static_cast<std::ptrdiff_t>(o.from + r.cursor));

        // ── VERIFICATION. Fail-closed on the FIRST problem, over the prefix the
        // answer CLAIMS to cover: nothing is handed on unless every id in that
        // prefix was either delivered-and-verified or named un-servable, and
        // every delivered frame's recomputed carrier hash equals the id we asked
        // for. Truncation narrows WHAT is claimed; it never softens the check.
        std::map<bytes32, std::size_t> seen;
        for (const bytes32& id : r.unservable) {
            if (!seen.emplace(id, 1).second) {
                fail(peer, SupplyFailure::DUPLICATE_ID, false, /*dup=*/true);
                return;
            }
            if (std::find(covered.begin(), covered.end(), id) == covered.end()) {
                fail(peer, SupplyFailure::UNSOLICITED, false);
                return;                                   // an id we never asked for
            }
        }
        IdOfFrameFn id_of_frame;   // GAP-2 seam, copied out under the lock
        { std::lock_guard<std::mutex> lk(m_mtx); id_of_frame = m_id_of_frame; }
        std::vector<VerifiedFrame> verified;
        verified.reserve(r.frames.size());
        for (const auto& [id, bytes] : r.frames) {
            if (!seen.emplace(id, 0).second) {
                fail(peer, SupplyFailure::DUPLICATE_ID, false, /*dup=*/true);
                return;                     // twice, or served AND called un-servable
            }
            if (std::find(covered.begin(), covered.end(), id) == covered.end()) {
                fail(peer, SupplyFailure::UNSOLICITED, false);
                return;                                   // an id we never asked for
            }
            if (id_of_frame) {   // GAP-2: a non-CarrierWire frame family (see set_id_of_frame)
                const std::optional<bytes32> got = id_of_frame(bytes);
                if (!got) {
                    fail(peer, SupplyFailure::UNDECODABLE_FRAME, false, false, /*undec=*/true);
                    return;
                }
                if (!(*got == id)) {
                    fail(peer, SupplyFailure::HASH_MISMATCH, false, false, false, /*hash=*/true);
                    return;
                }
                VerifiedFrame v;
                v.id = id;
                v.frame = bytes;
                verified.push_back(std::move(v));
                continue;
            }
            const DecodeResult dr = CarrierWire::decode(bytes);
            if (!dr.ok()) {
                fail(peer, SupplyFailure::UNDECODABLE_FRAME, false, false, /*undec=*/true);
                return;
            }
            // ★ THE BINDING: the id is the carrier's WorkEvent::hash. Recompute
            // it from the BYTES the peer sent. A peer that substituted any other
            // carrier — or flipped a single byte of this one — fails here.
            if (!(dr.carrier.carrier.hash() == id)) {
                fail(peer, SupplyFailure::HASH_MISMATCH, false, false, false, /*hash=*/true);
                return;
            }
            VerifiedFrame v;
            v.id = id;
            v.frame = bytes;
            v.carrier = dr.carrier;
            verified.push_back(std::move(v));
        }
        for (const bytes32& id : covered) {
            if (!seen.count(id)) {
                fail(peer, SupplyFailure::MISSING_ID, false, false, false, false,
                     /*missing=*/true);
                return;
            }
        }

        FramesFn cb;
        UnservableFn ucb;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (!verified.empty()) {
                ++m_stats.frames_ok;
                m_stats.frames_verified += verified.size();
            }
            if (truncated) ++m_stats.truncated_replies;
            m_stats.unservable_id += r.unservable.size();
            cb = m_on_frames;
            ucb = m_on_unservable;
        }
        if (cb && !verified.empty()) cb(peer, verified);
        // ★ THE EXPLICIT UN-SERVABLE ANSWER. Reported through BOTH the ids
        // callback (so a caller knows exactly which ones) and the failure
        // callback (so a caller that only watches failures still sees it). It
        // is not a stall and it is not a drop: the fetch carries on.
        if (!r.unservable.empty()) {
            if (ucb) ucb(peer, r.unservable);
            fail(peer, SupplyFailure::UNSERVABLE_ID, false);
        }

        if (!truncated) {
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.fetches_completed;
            return;
        }

        // ── CONTINUE. Re-ask from the cursor, on the same peer, with a fresh
        // deadline. The slot was released by claim_frames, so this re-arms it.
        CtrlGetFrames q;
        bool stopped = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (o.rounds + 1 > m_opt.max_continuations) {
                ++m_stats.continuation_limit;
                stopped = true;
            } else if (m_out.count(peer)) {
                // Something else claimed this peer's one slot while we verified.
                // Do not fight it: the caller can re-ask the remainder itself.
                ++m_stats.refused_busy;
                stopped = true;
            } else {
                o.from += r.cursor;
                o.rounds += 1;
                arm_frames_locked(peer, o, q);
                ++m_stats.continuations;
            }
        }
        if (stopped) {
            // Not continuing: say so explicitly rather than leaving the caller
            // waiting for bytes that are not coming.
            fail(peer, SupplyFailure::CONTINUATION_LIMIT, false);
            return;
        }
        (void)dispatch(peer, CtrlWire::encode(q));
    }

    // Expire outstanding requests whose deadline has passed. Drive it from the
    // send-side idle tick (carrier_send.hpp) or any daemon timer. Returns the
    // number expired. A timed-out request FAILS — it never silently hangs, and
    // the peer is never dropped for it.
    std::size_t tick(Clock::time_point now = Clock::time_point{}) {
        std::vector<PeerId> late;
        std::vector<std::pair<PeerId, std::vector<std::uint8_t>>> resend;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (now == Clock::time_point{}) now = now_locked();
            // ── the re-sends first: a slot waiting on a backoff is NOT late ──
            for (auto& [peer, o] : m_out) {
                if (!o.awaiting_retry || now < o.retry_at) continue;
                o.awaiting_retry = false;
                o.request_id = ++m_next_rid;
                o.deadline = now + m_opt.request_timeout;
                if (o.expect == CTRL_ORDER) {
                    CtrlGetOrder q;
                    q.request_id = o.request_id;
                    q.chain = o.chain;
                    q.a = o.a;
                    q.p = o.p;
                    q.cut_spine_digest = o.spine;
                    q.max_ids = o.max_ids;
                    resend.emplace_back(peer, CtrlWire::encode(q));
                } else {
                    CtrlGetFrames q;
                    q.request_id = o.request_id;
                    q.chain = o.chain;
                    q.ids.assign(o.ids.begin() + static_cast<std::ptrdiff_t>(o.from),
                                 o.ids.begin() + static_cast<std::ptrdiff_t>(o.to));
                    resend.emplace_back(peer, CtrlWire::encode(q));
                }
            }
            for (auto it = m_out.begin(); it != m_out.end(); ) {
                if (it->second.awaiting_retry) { ++it; continue; }
                if (now >= it->second.deadline) {
                    late.push_back(it->first);
                    it = m_out.erase(it);
                    ++m_stats.timeouts;
                } else {
                    ++it;
                }
            }
        }
        // The re-sends go out with NO lock held, exactly as every other send
        // does. dispatch() drops the slot itself if the send fails.
        for (const auto& [p, f] : resend) (void)dispatch(p, f);
        FailFn cb;
        { std::lock_guard<std::mutex> lk(m_mtx); cb = m_on_fail; }
        if (cb) for (PeerId p : late) cb(p, SupplyFailure::TIMEOUT);
        return late.size();
    }

private:
    struct Outstanding {
        std::uint32_t        request_id = 0;
        std::uint8_t         expect = 0;
        Clock::time_point    deadline{};
        // GETFRAMES only. `ids` is the WHOLE ask; [from, to) is the chunk this
        // request covers. A truncated answer moves `from` forward by the cursor
        // it served through and re-arms — so the ask itself never changes, and
        // the remainder is always exactly ids[from, to).
        std::vector<bytes32> ids;
        std::uint32_t        chain = 0;
        std::size_t          from = 0;
        std::size_t          to = 0;
        std::uint32_t        rounds = 0;   // continuations spent on this fetch
        // ── GETORDER only: everything needed to RE-SEND the same ask ────────
        std::uint64_t        a = 0;
        std::uint64_t        p = 0;
        bytes32              spine{};
        std::uint32_t        max_ids = kCtrlMaxIdsPerOrder;
        // ── the backoff state (both shapes) ─────────────────────────────────
        bool                 awaiting_retry = false;  // nothing is on the wire
        Clock::time_point    retry_at{};
        std::uint32_t        retries = 0;             // re-sends already spent
    };

    // Arm (or re-arm) the one outstanding GETFRAMES slot for `peer` over
    // o.ids[o.from, end) and build the request that goes with it. Caller holds
    // m_mtx; the send happens outside the lock.
    void arm_frames_locked(PeerId peer, Outstanding o, CtrlGetFrames& q) {
        const std::size_t end =
            std::min<std::size_t>(o.ids.size(),
                                  o.from + std::min<std::size_t>(m_opt.max_ids_per_fetch,
                                                                 kCtrlMaxIdsPerFetch));
        o.to = end;
        o.request_id = ++m_next_rid;
        o.expect = CTRL_FRAMES;
        o.awaiting_retry = false;
        o.deadline = now_locked() + m_opt.request_timeout;
        q.request_id = o.request_id;
        q.chain = o.chain;
        q.ids.assign(o.ids.begin() + static_cast<std::ptrdiff_t>(o.from),
                     o.ids.begin() + static_cast<std::ptrdiff_t>(o.to));
        m_out.insert_or_assign(peer, std::move(o));
    }

    bool dispatch(PeerId peer, const std::vector<std::uint8_t>& frame) {
        SendFn s;
        { std::lock_guard<std::mutex> lk(m_mtx); s = m_send; }
        if (s && s(peer, frame)) return true;
        std::lock_guard<std::mutex> lk(m_mtx);
        ++m_stats.send_failed;
        m_out.erase(peer);              // never leave a slot pinned by a dead send
        return false;
    }

    // Consume the outstanding slot iff it matches (opcode, request_id). One
    // outstanding request per peer means an answer can only ever satisfy the
    // question actually asked.
    bool claim(PeerId peer, std::uint8_t op, std::uint32_t rid, Outstanding& out) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_out.find(peer);
        if (it == m_out.end()) return false;
        if (it->second.expect != op || it->second.request_id != rid) return false;
        out = std::move(it->second);
        m_out.erase(it);
        return true;
    }

    Clock::time_point now_locked() const {   // caller holds m_mtx
        return m_now ? m_now() : Clock::now();
    }

    // ── ★ THE BOUNDED RE-SEND ───────────────────────────────────────────────
    // Put the SAME request back in the peer's one slot, marked as not-yet-sent,
    // with a deadline that cannot fire before the backoff has elapsed. tick()
    // — the cadence the daemon already drives from carrier_send's idle hook —
    // is what puts it back on the wire. Nothing sleeps, nothing spins, and a
    // server that throttles forever produces exactly max_throttle_retries extra
    // round trips and then a THROTTLED failure.
    void schedule_retry(PeerId peer, Outstanding o) {
        FailFn cb;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            ++m_stats.throttled_replies;
            if (o.retries >= m_opt.max_throttle_retries) {
                ++m_stats.throttle_exhausted;
                cb = m_on_fail;
            } else {
                std::chrono::milliseconds back = m_opt.throttle_backoff;
                for (std::uint32_t i = 0; i < o.retries && back < m_opt.throttle_backoff_max; ++i)
                    back *= 2;
                if (back > m_opt.throttle_backoff_max) back = m_opt.throttle_backoff_max;
                const Clock::time_point now = now_locked();
                o.retries += 1;
                o.awaiting_retry = true;
                o.retry_at = now + back;
                o.deadline = o.retry_at + m_opt.request_timeout;
                ++m_stats.throttle_retries;
                m_out.insert_or_assign(peer, std::move(o));
                return;
            }
        }
        if (cb) cb(peer, SupplyFailure::THROTTLED);
    }
    // Same, but hands back the whole fetch state so the answer can be checked
    // against the chunk it belongs to and, if truncated, continued.
    bool claim_frames(PeerId peer, std::uint32_t rid, Outstanding& out) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_out.find(peer);
        if (it == m_out.end()) return false;
        if (it->second.expect != CTRL_FRAMES || it->second.request_id != rid)
            return false;
        out = std::move(it->second);
        m_out.erase(it);
        return true;
    }

    void fail(PeerId peer, SupplyFailure f, bool clear_slot,
              bool dup = false, bool undec = false, bool hash = false,
              bool missing = false) {
        FailFn cb;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            switch (f) {
                case SupplyFailure::MALFORMED:      ++m_stats.malformed; break;
                case SupplyFailure::UNSOLICITED:    ++m_stats.unsolicited; break;
                case SupplyFailure::SERVER_REFUSED: ++m_stats.server_refused; break;
                default: break;
            }
            if (dup)     ++m_stats.duplicate_id;
            if (undec)   ++m_stats.undecodable;
            if (hash)    ++m_stats.hash_mismatch;
            if (missing) ++m_stats.missing_id;
            if (clear_slot) m_out.erase(peer);
            cb = m_on_fail;
        }
        if (cb) cb(peer, f);
    }

    void evict_lru_locked() {
        while (m_out.size() + 1 > m_opt.max_peer_slots && !m_out.empty()) {
            auto victim = m_out.begin();
            for (auto i = m_out.begin(); i != m_out.end(); ++i)
                if (i->second.deadline < victim->second.deadline) victim = i;
            m_out.erase(victim);
        }
    }

    SendFn                        m_send;
    NowFn                         m_now;
    mutable std::mutex            m_mtx;
    SupplyFetchOptions            m_opt{};
    SupplyFetchStats              m_stats{};
    std::map<PeerId, Outstanding> m_out;
    std::uint32_t                 m_next_rid = 0;
    OrderFn                       m_on_order;
    FramesFn                      m_on_frames;
    FailFn                        m_on_fail;
    UnservableFn                  m_on_unservable;
    IdOfFrameFn                   m_id_of_frame;   // GAP-2 seam; empty = CarrierWire
};

} // namespace c2pool::v37n
