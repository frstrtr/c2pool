// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// The admission check order mirrors monero-project/monero
// cryptonote_core/tx_pool.cpp add_tx and cryptonote_core.cpp
// handle_incoming_tx_pre, so that a {reason, drop_offence} pair here is
// comparable with what monerod would have told the same peer.
// ---------------------------------------------------------------------------
#include "xmr_relayed_txpool.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

namespace c2pool::xmr::native {
namespace {

using Reason = TxRelayVerdict::Reason;

TxRelayVerdict verdict(Reason r, bool drop, const Hash& id = Hash{},
                       AdmissionEvidence ev = AdmissionEvidence::None) {
    TxRelayVerdict v;
    v.reason       = r;
    v.drop_offense = drop;
    v.id           = id;
    v.evidence     = ev;
    return v;
}

// Compare fee rates without a 128-bit type: a.fee/a.weight vs b.fee/b.weight
// as a.fee*b.weight vs b.fee*a.weight, with the products carried in two 64-bit
// halves. Monero fees reach 10^13 and weights 10^5, so the product does not
// overflow today -- but "does not overflow today" is exactly the reasoning that
// ages badly in a comparator that decides which transaction gets mined.
struct U128 {
    std::uint64_t hi = 0, lo = 0;
};

U128 mul64(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t a_lo = a & 0xffffffffull, a_hi = a >> 32;
    const std::uint64_t b_lo = b & 0xffffffffull, b_hi = b >> 32;

    const std::uint64_t p0 = a_lo * b_lo;
    const std::uint64_t p1 = a_lo * b_hi;
    const std::uint64_t p2 = a_hi * b_lo;
    const std::uint64_t p3 = a_hi * b_hi;

    const std::uint64_t mid   = (p0 >> 32) + (p1 & 0xffffffffull) + (p2 & 0xffffffffull);
    U128 r;
    r.lo = (p0 & 0xffffffffull) | (mid << 32);
    r.hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    return r;
}

bool u128_less(const U128& a, const U128& b) noexcept {
    return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo;
}

// True when `a` pays strictly better per unit of weight than `b`.
bool better_fee_rate(const RelayedTx& a, const RelayedTx& b) noexcept {
    const U128 lhs = mul64(a.fee, b.weight ? b.weight : 1);
    const U128 rhs = mul64(b.fee, a.weight ? a.weight : 1);
    if (u128_less(rhs, lhs)) return true;
    if (u128_less(lhs, rhs)) return false;
    // Deterministic tie-break: older first, then by id, so two nodes with the
    // same pool produce the same backlog order.
    if (a.time_received != b.time_received) return a.time_received < b.time_received;
    return a.id < b.id;
}

} // namespace

RelayedTxPool::RelayedTxPool(TxpoolConfig cfg, ClockFn clock)
    : cfg_(std::move(cfg)), clock_(std::move(clock)) {}

std::uint64_t RelayedTxPool::now() const {
    if (clock_) return clock_();
    return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------
std::vector<TxRelayVerdict> RelayedTxPool::on_relayed(
        const PeerRef& from, std::vector<std::vector<std::uint8_t>> blobs, bool fluff) {
    std::vector<TxRelayVerdict> out;
    out.reserve(blobs.size());

    std::lock_guard<std::mutex> lk(mu_);
    expire_old_locked();

    for (auto& blob : blobs)
        out.push_back(admit_locked(from, std::move(blob), fluff));

    return out;
}

TxRelayVerdict RelayedTxPool::admit_locked(const PeerRef& from,
                                           std::vector<std::uint8_t>&& blob, bool fluff) {
    // 0) The synchronisation gate. monerod ignores relayed transactions while
    //    it is not at the tip, and so must we: a transaction judged against the
    //    wrong tip is judged against the wrong rules.
    if (!synced_) {
        ++stats_.rejected;
        return verdict(Reason::NotSynced, false);
    }

    // 1) Size, before anything touches the bytes.
    if (blob.size() > cfg_.max_tx_blob_size) {
        ++stats_.rejected;
        return verdict(Reason::TooBig, true);
    }

    // 2) Decode. Structural failures are drop offences (monerod drops a peer
    //    that sends a transaction that does not parse); an unsupported rct type
    //    is reported as BadVersion, which is what it is at HF16.
    DecodedTx d;
    const TxDecodeStatus st = decode_relayed_tx(blob.data(), blob.size(), d);
    if (st != TxDecodeStatus::Ok) {
        ++stats_.rejected;
        switch (st) {
            case TxDecodeStatus::UnsupportedRctType:
                return verdict(Reason::BadVersion, true);
            default:
                return verdict(Reason::Structural, true);
        }
    }

    // 3) The structural relay table, in monerod's order so the drop/no-drop
    //    split matches.
    if (d.w.version != 2) {
        ++stats_.rejected;
        return verdict(Reason::BadVersion, true, d.id);
    }
    if (d.w.weight > cfg_.max_tx_weight) {
        ++stats_.rejected;
        return verdict(Reason::WeightLimit, true, d.id);
    }
    if (d.w.n_outputs < cfg_.min_outputs || d.w.n_outputs > cfg_.max_outputs) {
        ++stats_.rejected;
        return verdict(Reason::Structural, true, d.id);
    }
    if (d.w.n_inputs == 0) {
        ++stats_.rejected;
        return verdict(Reason::Structural, true, d.id);
    }
    for (std::uint64_t ring : d.w.ring_sizes) {
        if (ring != cfg_.required_ring_size) {
            ++stats_.rejected;
            return verdict(Reason::BadRing, true, d.id);
        }
    }
    // Key images pairwise distinct WITHIN the transaction
    // (check_tx_inputs_keyimages_diff).
    for (std::size_t i = 0; i < d.w.key_images.size(); ++i)
        for (std::size_t j = i + 1; j < d.w.key_images.size(); ++j)
            if (d.w.key_images[i] == d.w.key_images[j]) {
                ++stats_.rejected;
                return verdict(Reason::Structural, true, d.id);
            }
    // The two NO-DROP structural rules: both are relay policy rather than
    // consensus, so a peer running an older policy is not misbehaving.
    if (d.w.extra_size > cfg_.max_extra_size) {
        ++stats_.rejected;
        return verdict(Reason::ExtraTooBig, false, d.id);
    }
    if (d.w.unlock_time != 0) {
        ++stats_.rejected;
        return verdict(Reason::UnlockNotZero, false, d.id);
    }

    // 4) Already held? Bump the sighting bookkeeping and say so. Re-sighting
    //    never resets time_received (the 5-second template gate is measured
    //    from the FIRST sighting) and never un-fluffs a transaction.
    if (auto it = by_id_.find(d.id); it != by_id_.end()) {
        RelayedTx& e = it->second;
        const std::uint32_t before_peers = e.seen_from_peers();
        const bool          before_fluff = e.seen_fluff;
        e.peers.insert(from.peer_id);
        e.seen_fluff = e.seen_fluff || fluff;
        ++stats_.duplicates;
        // A newly corroborated or newly fluffed transaction can become
        // selectable, which is a change to the backlog.
        if (e.seen_from_peers() != before_peers || e.seen_fluff != before_fluff)
            ++backlog_version_;
        return verdict(Reason::Duplicate, false, d.id, e.evidence);
    }

    // 5) NON-INPUT CONSENSUS -- the R-VAL heavy leg. Commitment balance, range
    //    proofs, key-image domain. This is what makes a bad-VALUE transaction a
    //    rejection rather than a block the network throws away.
    AdmissionEvidence evidence = AdmissionEvidence::Structural;
    if (cfg_.verify_non_input_consensus) {
        const rct::RctVerifyStatus vs = rct::verify_non_input_consensus(d.rct);
        if (vs != rct::RctVerifyStatus::Ok) {
            ++stats_.rejected;
            return verdict(Reason::ProofFail, true, d.id, evidence);
        }
        evidence |= AdmissionEvidence::NonInputConsensus;
    }

    // 6) Key-image conflict against the pool. First-seen wins (see the header):
    //    the newcomer is refused, the incumbent keeps its place, and the peer is
    //    not scored down -- monerod's no-drop double-spend classification.
    for (const Hash& ki : d.rct.key_images) {
        if (ki_owners_.find(ki) != ki_owners_.end()) {
            ++stats_.rejected;
            ++stats_.rejected_key_image_conflict;
            return verdict(Reason::KeyImageConflict, false, d.id, evidence);
        }
    }

    // 7) Room. Cap eviction drops the worst-paying transactions first; a
    //    transaction that cannot displace anything is refused, and that is not
    //    the sending peer's fault either.
    if (!make_room_locked(blob.size(), d.w.fee, d.w.weight)) {
        ++stats_.rejected;
        return verdict(Reason::PoolFull, false, d.id, evidence);
    }

    RelayedTx e;
    e.id            = d.id;
    e.blob          = std::move(blob);
    e.blob_size     = d.w.blob_size;
    e.weight        = d.w.weight;
    e.fee           = d.w.fee;
    e.rct_type      = d.w.rct_type;
    e.n_inputs      = static_cast<std::uint16_t>(d.w.n_inputs);
    e.n_outputs     = static_cast<std::uint16_t>(d.w.n_outputs);
    e.key_images    = d.rct.key_images;
    e.time_received = now();
    e.peers.insert(from.peer_id);
    e.seen_fluff = fluff;
    e.evidence   = evidence;

    insert_locked(std::move(e));
    ++stats_.accepted;
    return verdict(Reason::Accepted, false, d.id, evidence);
}

void RelayedTxPool::insert_locked(RelayedTx&& tx) {
    const Hash id = tx.id;
    pool_bytes_ += tx.blob.size();
    for (const Hash& ki : tx.key_images) ki_owners_[ki] = id;
    arrival_.push_back(id);
    by_id_.emplace(id, std::move(tx));
    ++backlog_version_;
}

void RelayedTxPool::erase_locked(const Hash& id) {
    auto it = by_id_.find(id);
    if (it == by_id_.end()) return;

    pool_bytes_ -= it->second.blob.size();
    for (const Hash& ki : it->second.key_images) {
        auto o = ki_owners_.find(ki);
        if (o != ki_owners_.end() && o->second == id) ki_owners_.erase(o);
    }
    by_id_.erase(it);
    arrival_.erase(std::remove(arrival_.begin(), arrival_.end(), id), arrival_.end());
    ++backlog_version_;
}

bool RelayedTxPool::is_pinned_locked(const Hash& id) const {
    for (const auto& [tid, ids] : pins_) {
        (void)tid;
        if (std::find(ids.begin(), ids.end(), id) != ids.end()) return true;
    }
    return false;
}

bool RelayedTxPool::make_room_locked(std::uint64_t incoming_bytes, std::uint64_t incoming_fee,
                                     std::uint64_t incoming_weight) {
    if (pool_bytes_ + incoming_bytes <= cfg_.max_pool_bytes) return true;
    // A transaction larger than the whole cap can never be held, and must not
    // cost the pool a single eviction on its way to being refused.
    if (incoming_bytes > cfg_.max_pool_bytes) return false;

    RelayedTx probe;
    probe.fee           = incoming_fee;
    probe.weight        = incoming_weight;
    probe.time_received = now();

    // Plan the eviction BEFORE performing any of it. Evicting first and then
    // discovering the newcomer does not fit would leave the pool emptied by a
    // transaction it never accepted -- which is a free way to wipe a pool.
    std::vector<const RelayedTx*> candidates;
    candidates.reserve(by_id_.size());
    for (const auto& [id, e] : by_id_)
        if (!is_pinned_locked(id)) candidates.push_back(&e);

    // Worst-paying first: a pinned body is not a candidate at any price,
    // because it is the body of a template that can still win a block.
    std::sort(candidates.begin(), candidates.end(),
              [](const RelayedTx* a, const RelayedTx* b) { return better_fee_rate(*b, *a); });

    std::vector<Hash> victims;
    std::uint64_t     freed = 0;
    for (const RelayedTx* e : candidates) {
        if (pool_bytes_ - freed + incoming_bytes <= cfg_.max_pool_bytes) break;
        // Never evict something that pays better than what is arriving.
        if (!better_fee_rate(probe, *e)) return false;
        victims.push_back(e->id);
        freed += e->blob.size();
    }
    if (pool_bytes_ - freed + incoming_bytes > cfg_.max_pool_bytes) return false;

    for (const Hash& id : victims) {
        erase_locked(id);
        ++stats_.evicted_cap;
    }
    return true;
}

std::size_t RelayedTxPool::expire_old_locked() {
    const std::uint64_t t = now();

    // arrival_ is in insertion order and time_received is monotone in it, so
    // the scan stops at the first entry young enough to keep. A PINNED entry
    // that is old enough to go is skipped rather than ending the scan: its
    // template still needs the body, but the entries behind it are still due.
    std::vector<Hash> expired;
    for (const Hash& id : arrival_) {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) continue;          // stale arrival slot
        if (t < it->second.time_received + cfg_.max_age_seconds) break;
        if (is_pinned_locked(id)) continue;
        expired.push_back(id);
    }
    for (const Hash& id : expired) {
        erase_locked(id);
        ++stats_.evicted_age;
    }
    // Drop the arrival slots that no longer name anything.
    while (!arrival_.empty() && by_id_.find(arrival_.front()) == by_id_.end())
        arrival_.pop_front();

    return expired.size();
}

std::size_t RelayedTxPool::expire_old() {
    std::lock_guard<std::mutex> lk(mu_);
    return expire_old_locked();
}

std::vector<Hash> RelayedTxPool::complement_request_ids() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<Hash> ids;
    ids.reserve(std::min<std::size_t>(by_id_.size(), MAX_TXPOOL_COMPLEMENT_IDS));
    for (const Hash& id : arrival_) {
        if (ids.size() >= MAX_TXPOOL_COMPLEMENT_IDS) break;
        if (by_id_.find(id) != by_id_.end()) ids.push_back(id);
    }
    return ids;
}

// ---------------------------------------------------------------------------
// Snapshot (C4)
// ---------------------------------------------------------------------------
std::vector<node::TxBacklogEntry> RelayedTxPool::snapshot_locked(
        const TxpoolSelectPolicy& p) const {
    std::vector<const RelayedTx*> keep;
    keep.reserve(by_id_.size());

    for (const auto& [id, e] : by_id_) {
        (void)id;
        if (!covers(e.evidence, p.required)) continue;
        if (e.seen_from_peers() < p.min_peers) continue;
        if (!e.seen_fluff && !p.allow_stem) continue;
        keep.push_back(&e);
    }

    // Fee rate descending: the order the assembler's knapsack expects to see,
    // and a deterministic one (the comparator has a total tie-break).
    std::sort(keep.begin(), keep.end(),
              [](const RelayedTx* a, const RelayedTx* b) { return better_fee_rate(*a, *b); });

    std::vector<node::TxBacklogEntry> out;
    out.reserve(keep.size());
    for (const RelayedTx* e : keep) {
        node::TxBacklogEntry b;
        b.id            = e->id;
        b.blob_size     = e->blob_size;
        b.weight        = e->weight;
        b.fee           = e->fee;
        b.time_received = e->time_received;
        out.push_back(b);
    }
    return out;
}

std::vector<node::TxBacklogEntry> RelayedTxPool::selectable_backlog() const {
    std::lock_guard<std::mutex> lk(mu_);
    return snapshot_locked(cfg_.policy);
}

std::vector<node::TxBacklogEntry> RelayedTxPool::selectable_backlog(
        const TxpoolSelectPolicy& p) const {
    std::lock_guard<std::mutex> lk(mu_);
    return snapshot_locked(p);
}

TxpoolSelectPolicy RelayedTxPool::policy() const {
    std::lock_guard<std::mutex> lk(mu_);
    return cfg_.policy;
}

std::uint64_t RelayedTxPool::backlog_version() const {
    std::lock_guard<std::mutex> lk(mu_);
    return backlog_version_;
}

// ---------------------------------------------------------------------------
// Bodies (C2 and C5)
// ---------------------------------------------------------------------------
bool RelayedTxPool::get_tx(const Hash& id, std::vector<std::uint8_t>& full_blob) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = by_id_.find(id);
    if (it == by_id_.end()) return false;
    full_blob = it->second.blob;
    return true;
}

bool RelayedTxPool::get_blobs(const std::vector<Hash>&                ids,
                              std::vector<std::vector<std::uint8_t>>& out,
                              std::vector<Hash>&                      missing) {
    std::lock_guard<std::mutex> lk(mu_);
    out.clear();
    missing.clear();
    out.reserve(ids.size());
    for (const Hash& id : ids) {
        auto it = by_id_.find(id);
        if (it == by_id_.end()) { missing.push_back(id); continue; }
        out.push_back(it->second.blob);
    }
    return missing.empty();
}

void RelayedTxPool::pin(const Hash& template_id, const std::vector<Hash>& ids) {
    std::lock_guard<std::mutex> lk(mu_);
    pins_[template_id] = ids;
    stats_.pinned_templates = pins_.size();
}

void RelayedTxPool::unpin(const Hash& template_id) {
    std::lock_guard<std::mutex> lk(mu_);
    pins_.erase(template_id);
    stats_.pinned_templates = pins_.size();
}

// ---------------------------------------------------------------------------
// Chain context (C2)
// ---------------------------------------------------------------------------
void RelayedTxPool::on_block_connected(const BlockTxEvent& ev) {
    std::lock_guard<std::mutex> lk(mu_);

    for (const Hash& id : ev.tx_hashes) {
        if (by_id_.find(id) == by_id_.end()) continue;
        erase_locked(id);
        ++stats_.evicted_mined;
    }

    // The key images of the block's transactions kill any pool entry that
    // shares one, mined id or not. This is the double-spend race the pool CAN
    // resolve without history: the other spend is now on the chain.
    for (const Hash& ki : ev.key_images) {
        auto o = ki_owners_.find(ki);
        if (o == ki_owners_.end()) continue;
        const Hash victim = o->second;
        erase_locked(victim);
        ++stats_.evicted_conflict;
    }
}

void RelayedTxPool::on_block_disconnected(const BlockTxEvent& ev) {
    // Bodies returned by the index are BEST EFFORT and carry no authority
    // (contracts/types.hpp must-fix d), so they go back through the SAME
    // admission path as anything off the wire: decoded again, verified again.
    if (ev.tx_blobs.empty()) return;

    PeerRef self;
    self.peer_id = 0;
    self.addr    = "reorg";

    std::vector<std::vector<std::uint8_t>> blobs = ev.tx_blobs;
    // A transaction that was in a block was, by definition, publicly fluffed.
    on_relayed(self, std::move(blobs), /*dandelionpp_fluff=*/true);
}

void RelayedTxPool::set_synced(bool synced) {
    std::lock_guard<std::mutex> lk(mu_);
    synced_ = synced;
}

bool RelayedTxPool::synced() const {
    std::lock_guard<std::mutex> lk(mu_);
    return synced_;
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------
TxpoolStats RelayedTxPool::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    TxpoolStats s = stats_;
    s.count  = by_id_.size();
    s.bytes  = pool_bytes_;
    s.weight = 0;
    for (const auto& [id, e] : by_id_) {
        (void)id;
        s.weight += e.weight;
    }
    s.pinned_templates = pins_.size();
    return s;
}

std::vector<TxpoolFact> RelayedTxPool::facts() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<TxpoolFact> out;
    out.reserve(by_id_.size());
    for (const auto& [id, e] : by_id_) {
        TxpoolFact f;
        f.id            = id;
        f.weight        = e.weight;
        f.fee           = e.fee;
        f.blob_size     = e.blob_size;
        f.evidence      = e.evidence;
        f.peers         = e.seen_from_peers();
        f.time_received = e.time_received;
        out.push_back(f);
    }
    return out;
}

bool RelayedTxPool::contains(const Hash& id) const {
    std::lock_guard<std::mutex> lk(mu_);
    return by_id_.find(id) != by_id_.end();
}

bool RelayedTxPool::lookup(const Hash& id, RelayedTx& out) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = by_id_.find(id);
    if (it == by_id_.end()) return false;
    out = it->second;
    return true;
}

std::size_t RelayedTxPool::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return by_id_.size();
}

} // namespace c2pool::xmr::native
