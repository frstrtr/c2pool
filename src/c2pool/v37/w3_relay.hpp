#pragma once
// V37 Track A2 / W3 — carrier relay over the v36 p2p layer.
// CONSUMER-tree code (src/c2pool/v37/), stacked on the W2 receipt layer
// (w2_receipt.hpp / w2_admission.hpp). This slice owns the RELAY / wire layer
// ONLY; it never touches v37_engine.hpp or v37_lane_executor.hpp internals
// (disjoint file ownership with the W4-unblock lane), and it never calls
// Lane::push / receive() — every append goes through W2 admission into the W0
// V37Engine seam, and every read is an immutable snapshot (O1, §6 of the spec).
//
// Spec: /home/ubuntu/v37-work/v37-a2-w3-relay-spec.md (§2 wire extension, §3
// relay/gossip, §4 block-winning unconditional append, §5 ordering + dedup
// interplay, §8.4 bloat hook, and the closing "W3-MUST" identity-binding
// requirement). Wire contract of record: docs/c2pool-v37-share-format.md
// (frstrtr/the, blob 08f157df) §1-§8 — the RDWR receipt envelope / carrier
// rules; this header is the draft-v0 encode/decode of that contract (W3-B5:
// the byte freeze is a Phase-B integrator item, so this layout is PROVISIONAL,
// and the §8.1 differential compares digests, not wire bytes).
//
// ── the v36 transport this layer REUSES (cite, never reinvent) ──────────────
// W3 adds ZERO new transport. A carrier is an extended share body, not a new
// message type; it rides the existing shares/sharereq/sharereply verbs and the
// existing broadcast path. In production ICarrierTransport is bound to the v36
// seams (verified present in this tree on 2026-09-04):
//   * SEND choke point : pool::Peer::write(std::unique_ptr<RawMessage>)
//                        (src/pool/peer.hpp:55 — every outbound pool message in
//                         every coin lane; bumps core::obs::p2p_stats()).
//   * forward loop     : NodeImpl::broadcast_share / post_broadcast_share
//                        (src/impl/ltc/node.cpp:969 / :942 — the proven ltc
//                         reference; walks un-broadcast shares, sends to each
//                         peer in m_peers, then commit_broadcast_marks marks
//                         ONLY what reached >=1 peer).
//   * RECEIVE choke    : pool::NodeBridge::handle (src/pool/node.hpp) ->
//                        pool::Protocol::handle_message (src/pool/protocol.hpp).
//   * sync / catch-up  : pool::download::DownloadGate (src/pool/share_download.hpp).
// CarrierRelay drives those through the ICarrierTransport seam so the relay
// logic (decode / bind-check / dedup / bloat / unconditional-append) is unit-
// testable stdlib-only, exactly like the W0/W1/W2 suites; the loopback-socket
// transport in the KAT is a test binding of the SAME seam.

#include <array>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>

#include "w2_admission.hpp"   // ReceiptAdmitter, WorkEvent, W2_R_MAX, ...
#include "w2_receipt.hpp"

namespace c2pool::v37n {

// W3 draft-v0 wire version tag (W3-B5: provisional until the integrator freezes
// the byte packing at Phase-B exit). Present so a later freeze is a visible bump.
constexpr std::uint8_t W3_WIRE_VERSION = 0x01;

// R_MAX is the W2-layer consensus bound (share-format §7); W3 enforces it at
// DECODE, before any push (spec §2.3 / WT-1). Named through W2 so there is one
// definition, never a second copy that could drift.
constexpr std::uint32_t W3_R_MAX = W2_R_MAX;

// ── a carrier = ordinary share + 0..R_MAX receipts (spec §2.1) ──────────────
struct Carrier {
    WorkEvent carrier;                 // the ordinary V37 share (advances clock)
    std::vector<WorkEvent> receipts;   // ref-protected payload, order-free
};

// ── decode dispositions ─────────────────────────────────────────────────────
enum class WireStatus {
    OK,
    REJECT_TRUNCATED,          // ran off the end of the buffer (malformed)
    REJECT_BAD_VERSION,        // unknown wire version tag
    REJECT_RMAX,              // > R_MAX receipts: whole carrier rejected (§2.3)
    REJECT_CARRIER_UNBOUND,   // W3-MUST: carrier identity != descriptor key
};

// Why a single receipt was dropped at decode (carrier still stands, §2.4/WT-2).
enum class ReceiptWireDrop {
    MISBOUND_IDENTITY,        // W3-MUST: receipt identity != descriptor key
};

struct DecodeResult {
    WireStatus status = WireStatus::OK;
    Carrier carrier;                                    // valid iff status==OK
    // receipts rejected at DECODE (not admission) with the reason. The carrier
    // and the surviving receipts stand; a mis-bound receipt never rides on.
    std::vector<std::pair<std::string, ReceiptWireDrop>> dropped;
    bool ok() const { return status == WireStatus::OK; }
};

// ═══════════════════════════════════════════════════════════════════════════
// Wire codec (spec §2; share-format §1/§3) — draft v0, provisional (W3-B5).
// Little-endian fixed-width fields, simple length prefixes, no varints. The
// carrier's receipts ride the ref_hash-committed region conceptually; here they
// are serialized in-body so a downloaded carrier carries its receipts with it
// (spec §3.3 — receipts add nothing to the sync protocol).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierWire {
public:
    static std::vector<std::uint8_t> encode(const Carrier& c) {
        std::vector<std::uint8_t> b;
        b.push_back(W3_WIRE_VERSION);
        put_event(b, c.carrier);
        // receipt_count is a single byte; R_MAX=4 fits trivially. Encoders never
        // emit > R_MAX (the emitter is bounded); a decoder that SEES > R_MAX
        // rejects the whole carrier (§2.3, WT-1).
        b.push_back(static_cast<std::uint8_t>(c.receipts.size()));
        for (const WorkEvent& r : c.receipts) put_event(b, r);
        return b;
    }

    // Decode + enforce the two decode-time consensus/anti-forgery rules:
    //   (1) R_MAX: a carrier presenting > R_MAX receipts is malformed => the
    //       WHOLE carrier is rejected (never truncate-and-accept; truncation
    //       would make the digest ambiguous — spec §2.3).
    //   (2) W3-MUST identity binding (the W2->W3 seam obligation, spec close):
    //       preimage.identity == descriptor.identity_key() on EVERY event.
    //       * carrier mis-bound  => whole-carrier reject (credit-misdirection
    //         on the carrier itself is fatal);
    //       * receipt mis-bound  => that receipt dropped, carrier STANDS
    //         (a mis-bound receipt is never a fork tool, and is never relayed on).
    static DecodeResult decode(const std::vector<std::uint8_t>& b) {
        DecodeResult out;
        std::size_t p = 0;
        std::uint8_t ver = 0;
        if (!get_u8(b, p, ver)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (ver != W3_WIRE_VERSION) { out.status = WireStatus::REJECT_BAD_VERSION; return out; }

        WorkEvent carrier;
        if (!get_event(b, p, carrier)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        std::uint8_t rc = 0;
        if (!get_u8(b, p, rc)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
        if (rc > W3_R_MAX) { out.status = WireStatus::REJECT_RMAX; return out; }  // (1)

        std::vector<WorkEvent> receipts;
        receipts.reserve(rc);
        for (std::uint8_t i = 0; i < rc; ++i) {
            WorkEvent r;
            if (!get_event(b, p, r)) { out.status = WireStatus::REJECT_TRUNCATED; return out; }
            receipts.push_back(std::move(r));
        }
        // Trailing bytes are a malformed frame (we consumed a fixed structure).
        if (p != b.size()) { out.status = WireStatus::REJECT_TRUNCATED; return out; }

        // (2a) carrier identity binding — fatal.
        if (!identity_bound(carrier)) {
            out.status = WireStatus::REJECT_CARRIER_UNBOUND;
            return out;
        }
        // (2b) per-receipt identity binding — drop the offender, carrier stands.
        out.carrier.carrier = std::move(carrier);
        for (WorkEvent& r : receipts) {
            if (!identity_bound(r)) {
                out.dropped.emplace_back(r.tag, ReceiptWireDrop::MISBOUND_IDENTITY);
                continue;   // NOT carried on — forgery is not amplified
            }
            out.carrier.receipts.push_back(std::move(r));
        }
        out.status = WireStatus::OK;
        return out;
    }

    // The W3-MUST predicate, isolated so the KAT can assert it directly.
    // W2 binds the PoW to `identity` but credits under `descriptor`; in the
    // synthetic model these are decoupled fields and W2 does NOT check their
    // correspondence (deferred, SF-OQ1/OQ4). W3 closes the seam here.
    static bool identity_bound(const WorkEvent& e) {
        return e.identity == e.descriptor.identity_key();
    }

private:
    static void put_u8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }
    static void put_u16(std::vector<std::uint8_t>& b, std::uint16_t v) {
        for (int i = 0; i < 2; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_u64(std::vector<std::uint8_t>& b, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back((std::uint8_t)(v >> (8 * i)));
    }
    static void put_bytes32(std::vector<std::uint8_t>& b, const bytes32& h) {
        b.insert(b.end(), h.begin(), h.end());
    }
    static void put_ref(std::vector<std::uint8_t>& b, const ::v37::ScriptRef& r) {
        put_u8(b, static_cast<std::uint8_t>(r.kind));
        put_u8(b, static_cast<std::uint8_t>(r.payload.size()));
        b.insert(b.end(), r.payload.begin(), r.payload.end());
    }
    static void put_desc(std::vector<std::uint8_t>& b, const ::v37::PayoutDescriptor& d) {
        put_ref(b, d.pay);
        put_u8(b, d.attribution.has_value() ? 1 : 0);
        if (d.attribution.has_value()) put_ref(b, *d.attribution);
        put_u16(b, static_cast<std::uint16_t>(d.aux.size()));
        for (const auto& e : d.aux) { put_u32(b, e.chain_id); put_ref(b, e.ref); }
        put_u16(b, static_cast<std::uint16_t>(d.raw_script.size()));
        b.insert(b.end(), d.raw_script.begin(), d.raw_script.end());
    }
    static void put_str(std::vector<std::uint8_t>& b, const std::string& s) {
        put_u16(b, static_cast<std::uint16_t>(s.size()));
        b.insert(b.end(), s.begin(), s.end());
    }
    static void put_event(std::vector<std::uint8_t>& b, const WorkEvent& e) {
        put_u32(b, e.chain_id);
        put_bytes32(b, e.identity);
        put_bytes32(b, e.prev_block_hash);
        put_bytes32(b, e.prev_own_share);
        put_u32(b, e.lz_bits);
        put_u64(b, e.nonce);
        put_desc(b, e.descriptor);
        put_str(b, e.tag);   // local bookkeeping (NOT in preimage); carried so a
                             // round-trip is exact, never covered by PoW/consensus.
    }

    static bool get_u8(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint8_t& v) {
        if (p + 1 > b.size()) return false;
        v = b[p++]; return true;
    }
    static bool get_u16(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint16_t& v) {
        if (p + 2 > b.size()) return false;
        v = 0; for (int i = 0; i < 2; ++i) v |= (std::uint16_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_u32(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint32_t& v) {
        if (p + 4 > b.size()) return false;
        v = 0; for (int i = 0; i < 4; ++i) v |= (std::uint32_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_u64(const std::vector<std::uint8_t>& b, std::size_t& p, std::uint64_t& v) {
        if (p + 8 > b.size()) return false;
        v = 0; for (int i = 0; i < 8; ++i) v |= (std::uint64_t)b[p++] << (8 * i);
        return true;
    }
    static bool get_bytes32(const std::vector<std::uint8_t>& b, std::size_t& p, bytes32& h) {
        if (p + 32 > b.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = b[p++];
        return true;
    }
    static bool get_ref(const std::vector<std::uint8_t>& b, std::size_t& p, ::v37::ScriptRef& r) {
        std::uint8_t kind = 0, len = 0;
        if (!get_u8(b, p, kind) || !get_u8(b, p, len)) return false;
        if (p + len > b.size()) return false;
        r.kind = static_cast<::v37::ScriptKind>(kind);
        r.payload.assign(b.begin() + p, b.begin() + p + len);
        p += len;
        return true;
    }
    static bool get_desc(const std::vector<std::uint8_t>& b, std::size_t& p, ::v37::PayoutDescriptor& d) {
        if (!get_ref(b, p, d.pay)) return false;
        std::uint8_t has_attr = 0;
        if (!get_u8(b, p, has_attr)) return false;
        if (has_attr) {
            ::v37::ScriptRef a;
            if (!get_ref(b, p, a)) return false;
            d.attribution = a;
        }
        std::uint16_t naux = 0;
        if (!get_u16(b, p, naux)) return false;
        d.aux.clear();
        for (std::uint16_t i = 0; i < naux; ++i) {
            ::v37::AuxEntry e;
            if (!get_u32(b, p, e.chain_id) || !get_ref(b, p, e.ref)) return false;
            d.aux.push_back(std::move(e));
        }
        std::uint16_t rs = 0;
        if (!get_u16(b, p, rs)) return false;
        if (p + rs > b.size()) return false;
        d.raw_script.assign(b.begin() + p, b.begin() + p + rs);
        p += rs;
        return true;
    }
    static bool get_str(const std::vector<std::uint8_t>& b, std::size_t& p, std::string& s) {
        std::uint16_t n = 0;
        if (!get_u16(b, p, n)) return false;
        if (p + n > b.size()) return false;
        s.assign(b.begin() + p, b.begin() + p + n);
        p += n;
        return true;
    }
    static bool get_event(const std::vector<std::uint8_t>& b, std::size_t& p, WorkEvent& e) {
        if (!get_u32(b, p, e.chain_id)) return false;
        if (!get_bytes32(b, p, e.identity)) return false;
        if (!get_bytes32(b, p, e.prev_block_hash)) return false;
        if (!get_bytes32(b, p, e.prev_own_share)) return false;
        if (!get_u32(b, p, e.lz_bits)) return false;
        if (!get_u64(b, p, e.nonce)) return false;
        if (!get_desc(b, p, e.descriptor)) return false;
        if (!get_str(b, p, e.tag)) return false;
        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// Relay dedup set (spec §5.2, right column) — NETWORK HYGIENE ONLY.
// Keyed on the carrier's own header hash. This set is NEVER consensus, NEVER a
// digest leaf, and MUST NOT gate the W2 consensus append (rule §5.2.1:
// relay-seen != chain-have). It is physically separate from the W2 DedupWindow
// (rule §5.2.4: they must not share a prune trigger) and starts empty on a W6
// rebuild (rule §5.2.3). Pruning here follows v36 policy (peer lifetime / cycle
// reset) — modeled as a caller-driven clear(); it has no consensus effect.
// ═══════════════════════════════════════════════════════════════════════════
class RelaySeenSet {
public:
    // Returns true if this carrier hash was NOT seen before (i.e. relay it).
    bool mark_and_test(const bytes32& carrier_hash) {
        return m_seen.insert(carrier_hash).second;
    }
    bool seen(const bytes32& carrier_hash) const {
        return m_seen.count(carrier_hash) != 0;
    }
    void clear() { m_seen.clear(); }        // v36-policy prune (no consensus effect)
    std::size_t size() const { return m_seen.size(); }
private:
    std::set<bytes32> m_seen;
};

// ═══════════════════════════════════════════════════════════════════════════
// Carrier-bloat measurement hook (spec §8.4; feeds testnet BM-2).
// OBSERVE-ONLY, OFF BY DEFAULT — modeled on the v36 opt-in p2p observe surface
// (core::obs::p2p_stats(), the relaxed fetch_add counters in
// src/pool/peer.hpp / src/pool/node.hpp). NEVER in any digest, NEVER on the
// consensus path (it is the magnifying glass, not the mechanism). Provisional
// simnet readings only; real numbers are Phase-B BM-2.
// ═══════════════════════════════════════════════════════════════════════════
struct CarrierBloatStats {
    bool enabled = false;

    std::uint64_t carriers_accepted = 0;
    std::array<std::uint64_t, W3_R_MAX + 1> receipt_count_hist{};  // [0..R_MAX]
    std::uint64_t carrier_body_bytes = 0;       // Σ whole-carrier wire bytes
    std::uint64_t receipt_payload_bytes = 0;    // Σ receipt-only wire bytes
    std::uint64_t wire_bytes_sent = 0;          // Σ over the per-peer send loop
    std::uint64_t relay_received = 0;
    std::uint64_t relay_dedup_hits = 0;         // echoes suppressed
    std::uint64_t download_fanin = 0;           // DownloadGate in-flight/retry

    void observe_accepted(const std::vector<std::uint8_t>& whole_frame,
                          const Carrier& c) {
        if (!enabled) return;
        ++carriers_accepted;
        std::size_t n = c.receipts.size();
        if (n <= W3_R_MAX) ++receipt_count_hist[n];
        carrier_body_bytes += whole_frame.size();
        // receipt-only bytes = whole frame - (version + carrier + count) prefix.
        Carrier bare; bare.carrier = c.carrier;
        receipt_payload_bytes +=
            whole_frame.size() - CarrierWire::encode(bare).size();
    }
    void observe_sent(std::size_t bytes, std::size_t n_peers) {
        if (!enabled) return;
        wire_bytes_sent += (std::uint64_t)bytes * n_peers;   // flood amplification
    }
    void observe_received(bool was_dedup_hit) {
        if (!enabled) return;
        ++relay_received;
        if (was_dedup_hit) ++relay_dedup_hits;
    }

    // The BM-2 ratios (guarded against divide-by-zero).
    double bytes_per_carrier() const {
        return carriers_accepted ? (double)carrier_body_bytes / carriers_accepted : 0.0;
    }
    double bytes_per_receipt() const {
        std::uint64_t rc = 0;
        for (std::size_t k = 0; k <= W3_R_MAX; ++k) rc += k * receipt_count_hist[k];
        return rc ? (double)receipt_payload_bytes / rc : 0.0;
    }
    double bloat_ratio() const {   // receipt payload / total carrier bytes
        return carrier_body_bytes ? (double)receipt_payload_bytes / carrier_body_bytes : 0.0;
    }
    double dedup_hit_rate() const {
        return relay_received ? (double)relay_dedup_hits / relay_received : 0.0;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// The transport seam (spec §1.3 / §3) — REUSE, not reinvent.
// Production impl: forward to pool::Peer::write over the m_peers set, driven by
// NodeImpl::broadcast_share (marking only what reached >=1 peer via
// commit_broadcast_marks). The KAT impl is a loopback-socket binding of the
// SAME seam. n_peers() lets the bloat hook account flood amplification.
// ═══════════════════════════════════════════════════════════════════════════
struct ICarrierTransport {
    virtual ~ICarrierTransport() = default;
    // Flood the frame to every peer. Returns the number of peers it reached
    // (>=1 means the v36 layer would commit_broadcast_marks; 0 means DEFER —
    // the share stays in-chain and un-marked, retried later, NEVER dropped).
    virtual std::size_t broadcast(const std::vector<std::uint8_t>& frame) = 0;
    virtual std::size_t n_peers() const = 0;
};

// ═══════════════════════════════════════════════════════════════════════════
// CarrierRelay — the flood-fill + admission-routing orchestrator.
//
// The append is ALWAYS via the W2 admission callback (into the W0 V37Engine
// seam). This class holds NO lane reference and calls NO executor method — it
// only routes decoded carriers into W2 and decides relay (§1.2, O1).
//
// Two dedup mechanisms are kept strictly separate (§5.2): the W2 DedupWindow
// (consensus, inside the admit callback) and this class's RelaySeenSet (network
// hygiene). Relay-seen NEVER gates the consensus append — that is the whole
// point of the block-winning guarantee (§4).
// ═══════════════════════════════════════════════════════════════════════════
class CarrierRelay {
public:
    // The admission callback wraps a W2 ReceiptAdmitter + the V37Engine sink.
    // It returns the admission Result so the relay can report credit outcomes.
    using AdmitFn = std::function<
        ReceiptAdmitter::Result(const WorkEvent& carrier,
                                const std::vector<WorkEvent>& receipts)>;

    CarrierRelay(AdmitFn admit, ICarrierTransport& transport)
        : m_admit(std::move(admit)), m_transport(transport) {}

    CarrierBloatStats& stats() { return m_stats; }
    RelaySeenSet& seen() { return m_seen; }

    struct Outcome {
        WireStatus wire = WireStatus::OK;
        ReceiptAdmitter::Result admission;   // valid iff wire==OK
        bool admitted = false;               // a fresh consensus append happened
        bool relayed = false;                // re-broadcast onward
        std::size_t peers_reached = 0;
        std::vector<std::pair<std::string, ReceiptWireDrop>> wire_dropped;
    };

    // ── inbound (peer -> us), spec §3.2 ─────────────────────────────────────
    // decode (enforce R_MAX + W3-MUST binding) -> W2 admission -> relay onward.
    // The relay-seen set suppresses the ECHO only; a novel carrier still admits.
    Outcome handle_inbound(const std::vector<std::uint8_t>& frame) {
        Outcome o;
        DecodeResult dr = CarrierWire::decode(frame);
        o.wire = dr.status;
        o.wire_dropped = dr.dropped;
        if (!dr.ok()) return o;                 // malformed / R_MAX / carrier unbound

        bool novel_to_relay = !m_seen.seen(dr.carrier.carrier.hash());
        m_stats.observe_received(!novel_to_relay);

        // Consensus append is INDEPENDENT of relay-seen (§5.2.1). Admit always;
        // W2's own window is the authority on credit-once.
        o.admission = m_admit(dr.carrier.carrier, dr.carrier.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(dr.carrier), dr.carrier);

        // Relay onward only if novel to the relay layer (flood-fill dedup, §5.2).
        // We re-encode the CLEANED carrier so a mis-bound receipt dropped at
        // decode is never amplified onto the network.
        if (novel_to_relay && o.admitted) {
            m_seen.mark_and_test(dr.carrier.carrier.hash());
            o.peers_reached = do_broadcast(dr.carrier);
            o.relayed = o.peers_reached > 0;
        }
        return o;
    }

    // ── local carrier (mined, or newly accepted), spec §3.1 ─────────────────
    // Ordinary local flow: admit, then relay (marking only what reached a peer).
    Outcome handle_local(const Carrier& c) {
        Outcome o;
        o.wire = WireStatus::OK;
        o.admission = m_admit(c.carrier, c.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(c), c);
        if (o.admitted && m_seen.mark_and_test(c.carrier.hash())) {
            o.peers_reached = do_broadcast(c);
            o.relayed = o.peers_reached > 0;
        }
        return o;
    }

    // ── the block-winning-carrier guarantee (spec §4, W3-G1) ────────────────
    // A carrier that is ALSO a valid mainchain block solution MUST be appended
    // and credited UNCONDITIONALLY — never gated by:
    //   (1) relay dedup — we do NOT consult m_seen before appending;
    //   (2) admission backpressure / rate-limit — there is no shed path here;
    //   (3) a busy submit path — the admit callback funnels into the V37Engine
    //       MPSC mailbox (a lock-free-ish enqueue, NOT a try_to_lock that can
    //       defer forever — the v36 stratum-freeze bug, spec §3.4);
    // Append is unconditional; RELAY may still legitimately defer (0 peers) and
    // retry — the credit is NEVER conditional on the relay succeeding (§4 close,
    // the #889/#903 defect: a block-winning share silently dropped => PPLNS loss).
    Outcome append_block_winner(const Carrier& c) {
        Outcome o;
        o.wire = WireStatus::OK;
        // Unconditional append: no m_seen check, no backpressure gate.
        o.admission = m_admit(c.carrier, c.receipts);
        o.admitted = (o.admission.carrier_status == CarrierStatus::OK);
        if (o.admitted) m_stats.observe_accepted(re_encode(c), c);
        // Relay is best-effort and may defer; append already stands.
        m_seen.mark_and_test(c.carrier.hash());
        o.peers_reached = do_broadcast(c);
        o.relayed = o.peers_reached > 0;
        return o;
    }

private:
    std::vector<std::uint8_t> re_encode(const Carrier& c) const {
        return CarrierWire::encode(c);
    }
    std::size_t do_broadcast(const Carrier& c) {
        std::vector<std::uint8_t> frame = CarrierWire::encode(c);
        std::size_t np = m_transport.n_peers();
        std::size_t reached = m_transport.broadcast(frame);
        m_stats.observe_sent(frame.size(), reached ? reached : np);
        return reached;
    }

    AdmitFn m_admit;
    ICarrierTransport& m_transport;
    RelaySeenSet m_seen;
    CarrierBloatStats m_stats;
};

} // namespace c2pool::v37n
