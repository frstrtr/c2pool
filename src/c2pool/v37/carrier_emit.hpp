#pragma once
// V37 Track A2 — carrier SEND-SIDE emitter primitives (the deferred half of
// #1532). CONSUMER-tree code (src/c2pool/v37/). mint_work_event() grinds THIS
// node's own work as a W3 carrier; CarrierEmitter hands it to
// CarrierRelay::handle_local — which admits it into the node's own V37Engine
// AND floods the FROZEN CarrierWire frame (W3-B5) to every peer. With the
// node's real IMainchainIndex bound (carrier_index.hpp LiveMainchainIndex), the
// emitted carrier references a REAL mainchain block (its prev_block_hash is a
// live dashd block hash in header/internal byte order), so a remote node's real
// index resolves it and accounts it — completing the bidirectional cross-node
// share flow.
//
// SCOPE (Track A2 step (b)(3)): the DAEMON no longer uses CarrierEmitter — it
// binds CarrierSendQueue (carrier_send.hpp), which reuses mint_work_event and
// adds per-miner identities, the off-hot-path worker and the W3-G1 block-winner
// path. CarrierEmitter stays as the SINGLE-IDENTITY test emitter the multinode
// KAT (MN-4 / MN-5) drives synchronously.
//
// NON-CONSENSUS: exactly like the receive side, every append rides
// CarrierRelay -> CarrierIngest -> V37Engine (never src/sharechain/v37 canon).
//
// HONEST BOUNDARY (S-1 / real share format, out of scope here): the minted work
// is the SYNTHETIC RDWR PoW envelope (sha256d preimage ground to `lz_bits`
// leading zero bits), NOT a real DASH X11 block-header PoW. What step (b) makes
// real is the WIRE (frozen), the INDEX (live dashd), and the cross-node FLOW
// (a carrier keyed to a real block). The PoW difficulty schedule stays the
// synthetic consensus_lz until real share format lands.
//
// stdlib-only (POSIX not needed here; the socket lives in carrier_net.hpp).

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

#include "w2_receipt.hpp"   // WorkEvent, bytes32, consensus_lz, W2_GENESIS_PREV_OWN
#include "w3_relay.hpp"     // Carrier, CarrierRelay

namespace c2pool::v37n {

// Grind a synthetic-PoW WorkEvent to `lz_bits` leading zero bits, self-bound to
// `desc` (identity == desc.identity_key(), so W3-MUST holds on the wire), and
// referencing `prev_block_internal` (a recent mainchain block hash, INTERNAL/
// header byte order). Returns nullopt if the nonce budget is exhausted (the
// caller must never block a hot path forever). `lz_bits` in the 8..9 range the
// synthetic schedule uses is ~2^lz expected tries — trivially cheap.
inline std::optional<WorkEvent>
mint_work_event(std::uint32_t chain_id, const ::v37::PayoutDescriptor& desc,
                const bytes32& prev_block_internal, const bytes32& prev_own,
                unsigned lz_bits, std::string tag, u64 nonce_base,
                u64 max_tries = (u64(1) << 24)) {
    WorkEvent ev;
    ev.chain_id        = chain_id;
    ev.identity        = desc.identity_key();
    ev.descriptor      = desc;
    ev.prev_block_hash = prev_block_internal;
    ev.prev_own_share  = prev_own;
    ev.lz_bits         = lz_bits;
    ev.tag             = std::move(tag);
    for (u64 i = 0; i < max_tries; ++i) {
        ev.nonce = nonce_base + i;
        if (ev.meets_own_target()) return ev;
    }
    return std::nullopt;
}

// ═══════════════════════════════════════════════════════════════════════════
// CarrierEmitter — mints and relays THIS node's own wins as carriers.
//
// One emitter per node, bound to the node's CarrierRelay and its own payout
// descriptor. emit_own_win() mints a carrier for a win keyed to a real
// mainchain block, admits it locally, and floods it. The own-share chain
// advances only on a locally-ADMITTED carrier (so a rejected mint never leaves
// a dangling prev_own). Thread-safe: the daemon calls this from the stratum
// submit thread; the KAT from the test thread.
// ═══════════════════════════════════════════════════════════════════════════
class CarrierEmitter {
public:
    CarrierEmitter(CarrierRelay& relay, std::uint32_t chain_id,
                   ::v37::PayoutDescriptor desc)
        : m_relay(relay), m_chain(chain_id), m_desc(std::move(desc)) {}

    struct EmitResult {
        bool minted = false;                 // false => nonce budget exhausted
        CarrierRelay::Outcome outcome;       // valid iff minted
    };

    // Emit a carrier for a win that built on the mainchain block whose hash is
    // `prev_block_internal` (header/internal byte order). `lz_bits` MUST equal
    // consensus_lz(height_of(prev_block_internal)) so the admitter's R-1 target
    // pinning accepts it (the daemon computes it from the live parent height).
    EmitResult emit_own_win(const bytes32& prev_block_internal, unsigned lz_bits,
                            std::string tag) {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto ev = mint_work_event(m_chain, m_desc, prev_block_internal,
                                  m_last_own, lz_bits, std::move(tag),
                                  (m_salt++) << 40);
        EmitResult r;
        if (!ev) return r;
        r.minted = true;
        Carrier c;
        c.carrier = *ev;
        r.outcome = m_relay.handle_local(c);
        if (r.outcome.admitted) {
            m_last_own = ev->hash();   // chain forward only on a real append
            ++m_emitted;
        }
        return r;
    }

    // Diagnostics only (never consensus): locally-admitted own carriers.
    std::uint64_t emitted() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_emitted;
    }

private:
    CarrierRelay&           m_relay;
    std::uint32_t           m_chain;
    ::v37::PayoutDescriptor m_desc;
    mutable std::mutex      m_mtx;
    bytes32                 m_last_own = W2_GENESIS_PREV_OWN;
    u64                     m_salt = 0;
    std::uint64_t           m_emitted = 0;
};

} // namespace c2pool::v37n
