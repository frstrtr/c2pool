// overlay.go — finality-gated owed/overlay ledger (V37 m2 Drop 3).
//
// Drop 2 (compaction.go) gave the durable, position-free per-identity accrued
// balance: what the pool OWES a miner for work it has folded in. That owed
// total is off-chain accounting only (work-receipts.md: OWED is a ledger, never
// an on-chain address). This drop adds the finality gate that turns owed into
// paid: the overlay that earmarks a payout when a block is FOUND, and the
// settlement that discharges it only once that block is FINAL.
//
// The core problem this solves is reorg safety on the payout side. A found
// block is not yet permanent — the chain can reorg it away before it reaches
// finality depth K. So a payout must not become irreversible the instant a
// block is found; it must stay reversible until the block is as final as the
// work that funded it. That is the SYMMETRIC finality-gate (the round-4/5
// conceded fix): the payout side gates on the same finality depth K
// (Geometry.FinalityDepthK) that seals the work side. Work becomes irreversible
// at depth K; a payout becomes irreversible at depth K; neither sooner.
//
// The state is three integer ledgers over one identity space, and every
// transition just moves weight between them, conserving the per-identity total:
//
//		accrued[id]  ==  owed[id] + pending[id] + settled[id]      (I-CONSERVE)
//
//	  - owed:    accrued work not yet earmarked to any live block payout.
//	  - pending: earmarked to a found-but-not-final block's overlay; reversible.
//	  - settled: paid out by a finalized block; irreversible.
//
// The three block transitions the m1 settlement state machine names map exactly
// onto weight moves that leave I-CONSERVE invariant:
//
//	BlockFound     -> OverlayAdded      owed    -> pending   (earmark, reversible)
//	BlockFinalized -> OwedSettled       pending -> settled   (+ OverlayCleared)
//	BlockOrphaned  -> OverlayReverted   pending -> owed      (snapshot restore)
//
// Because Found only MOVES owed into a keyed overlay and Orphaned moves the
// exact same weight back, a found→orphaned round trip restores the prior state
// bit-for-bit — the digest returns identical (the KEYED_CRDT snapshot-revert
// property). Multiple blocks can be pending at once (a fork with several
// candidate tips); each overlay is keyed by block id and drawn from the shared
// owed pool, so disjoint or sufficiently-funded found events compose
// order-independently.
//
// Determinism is absolute, same mandate as buffer.go and compaction.go:
// fixed-width integer serialization, integer add/sub, no floating point, no
// wall-clock, no map iteration in any consensus-visible path (Digest sorts
// identities and block ids before hashing). Nothing here is wired to
// production — this is the Drop-3 prototype substrate only.
package mrr

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// ApplyResult is the disposition of one block transition. Exactly one applies;
// like the buffer, the ledger never silently drops — a rejected or no-effect
// transition is reported, not swallowed. On any non-mutating result the state
// (and therefore the Digest) is left bit-identical.
type ApplyResult uint8

const (
	// OverlayAdded: BlockFound accepted — the payout was earmarked owed->pending.
	OverlayAdded ApplyResult = iota
	// OwedSettled: BlockFinalized applied — pending->settled, overlay cleared.
	OwedSettled
	// OverlayReverted: BlockOrphaned applied — pending->owed, overlay reverted.
	OverlayReverted
	// NotFinal: Finalize called below finality depth K; the gate held, nothing
	// moved (the payout stays reversible in the overlay).
	NotFinal
	// BlockKnown: BlockFound for a block id that is already pending; unchanged.
	BlockKnown
	// BlockUnknown: Finalize/Orphan of a block id that is not pending; unchanged.
	BlockUnknown
	// Overdraw: a found overlay would draw more than an identity's available
	// owed; the whole transition is rejected atomically (nothing mutated).
	Overdraw
)

func (r ApplyResult) String() string {
	switch r {
	case OverlayAdded:
		return "overlay_added"
	case OwedSettled:
		return "owed_settled"
	case OverlayReverted:
		return "overlay_reverted"
	case NotFinal:
		return "not_final"
	case BlockKnown:
		return "block_known"
	case BlockUnknown:
		return "block_unknown"
	case Overdraw:
		return "overdraw"
	default:
		return "unknown"
	}
}

// overlay is one found-but-not-final block's tentative payout: identity ->
// amount earmarked from owed. Every amount is > 0 (zero payout entries fold to
// nothing, exactly as a zero-weight Fold does), so an id is present iff it is
// paid something by this block.
type overlay struct {
	amt map[uint64]uint64
}

func (o *overlay) total() uint64 {
	var sum uint64
	for _, a := range o.amt {
		sum += a
	}
	return sum
}

// Settlement is the finality-gated owed/overlay ledger. The zero value is not
// usable; construct with NewSettlement or NewSettlementFromLedger.
type Settlement struct {
	finalityK uint32              // K: depth at which a payout may settle (symmetric gate)
	owed      map[uint64]uint64   // id -> accrued, un-earmarked (absent iff 0)
	pending   map[uint64]*overlay // blockID -> reversible earmark (absent iff never found / cleared)
	settled   map[uint64]uint64   // id -> paid-and-final (absent iff 0)
}

// NewSettlement returns an empty finality-gated ledger whose payout side seals
// at depth finalityK — the same K (Geometry.FinalityDepthK) that seals the
// work side, so the gate is symmetric.
func NewSettlement(finalityK uint32) *Settlement {
	return &Settlement{
		finalityK: finalityK,
		owed:      make(map[uint64]uint64),
		pending:   make(map[uint64]*overlay),
		settled:   make(map[uint64]uint64),
	}
}

// NewSettlementFromLedger seeds owed from a compacted Drop-2 Ledger — the owed
// base IS the self-carry accrued balance — without mutating or depending on the
// Ledger's internals (it reads only the exported sorted Identities/Balance).
func NewSettlementFromLedger(l *Ledger, finalityK uint32) *Settlement {
	s := NewSettlement(finalityK)
	for _, id := range l.Identities() {
		s.owed[id] = l.Balance(id) // Balance is always > 0 for a listed id
	}
	return s
}

// Accrue folds work into the owed base (self-carry), mirroring Ledger.Fold: a
// zero-weight accrual is a no-op that creates no phantom entry.
func (s *Settlement) Accrue(id, weight uint64) {
	if weight == 0 {
		return
	}
	s.owed[id] += weight
}

// availableOwed is the ceiling a new found overlay may draw for an identity.
// owed is decremented at BlockFound, so it already excludes every live earmark;
// available owed is therefore just the current owed. Kept as a named method so
// the guard (draw <= availableOwed) reads clearly at the call site.
func (s *Settlement) availableOwed(id uint64) uint64 { return s.owed[id] }

// BlockFound records a found block's tentative payout and earmarks it owed ->
// pending (OverlayAdded). Validation is two-pass and atomic: if the block id is
// already pending (BlockKnown) or any payout entry exceeds the identity's owed
// (Overdraw), nothing is mutated. Zero-amount entries are skipped (no phantom
// earmark), exactly as a zero-weight Fold creates no entry.
func (s *Settlement) BlockFound(blockID uint64, payout []Contribution) ApplyResult {
	if _, dup := s.pending[blockID]; dup {
		return BlockKnown
	}
	// Pass 1: coalesce the payout per identity and validate against owed. A
	// payout may name an identity twice; the earmark is the sum, and the sum is
	// what must fit within owed.
	want := make(map[uint64]uint64, len(payout))
	for _, c := range payout {
		if c.Weight == 0 {
			continue
		}
		want[c.ID] += c.Weight
	}
	for id, a := range want {
		if a > s.availableOwed(id) {
			return Overdraw
		}
	}
	// Pass 2: commit — move owed -> pending. Registers the block even if the
	// coalesced payout is empty (a found block that pays nobody is still a
	// tracked pending block, so a later Finalize/Orphan is well-defined).
	o := &overlay{amt: make(map[uint64]uint64, len(want))}
	for id, a := range want {
		s.owed[id] -= a
		if s.owed[id] == 0 {
			delete(s.owed, id) // keep owed free of zero entries (canonical form)
		}
		o.amt[id] = a
	}
	s.pending[blockID] = o
	return OverlayAdded
}

// Finalize applies BlockFinalized -> OwedSettled + OverlayCleared, but only if
// the block has reached finality depth K (the symmetric gate). depth is the
// block's confirmation depth on the active chain; depth < K holds the gate and
// returns NotFinal with no mutation. At or past K, the earmarked overlay moves
// pending -> settled and is cleared. An unknown (not pending) block is
// BlockUnknown.
func (s *Settlement) Finalize(blockID uint64, depth uint32) ApplyResult {
	o, ok := s.pending[blockID]
	if !ok {
		return BlockUnknown
	}
	if depth < s.finalityK {
		return NotFinal
	}
	for id, a := range o.amt {
		s.settled[id] += a // a is always > 0
	}
	delete(s.pending, blockID)
	return OwedSettled
}

// Orphan applies BlockOrphaned -> OverlayReverted: the reversible earmark moves
// pending -> owed, exactly restoring the pre-found owed balances (snapshot
// revert). An unknown (not pending) block is BlockUnknown. There is no depth
// gate — an orphan can happen at any depth below K, which is precisely why the
// payout was held reversible.
func (s *Settlement) Orphan(blockID uint64) ApplyResult {
	o, ok := s.pending[blockID]
	if !ok {
		return BlockUnknown
	}
	for id, a := range o.amt {
		s.owed[id] += a // restore; a is always > 0
	}
	delete(s.pending, blockID)
	return OverlayReverted
}

// Owed reports an identity's un-earmarked accrued balance.
func (s *Settlement) Owed(id uint64) uint64 { return s.owed[id] }

// Settled reports an identity's paid-and-final total.
func (s *Settlement) Settled(id uint64) uint64 { return s.settled[id] }

// Pending reports an identity's total currently earmarked across all found-but-
// not-final blocks.
func (s *Settlement) Pending(id uint64) uint64 {
	var sum uint64
	for _, o := range s.pending {
		sum += o.amt[id]
	}
	return sum
}

// Accrued reports an identity's full carried work: owed + pending + settled.
// I-CONSERVE holds this equal to everything ever accrued for the id, across
// every transition.
func (s *Settlement) Accrued(id uint64) uint64 {
	return s.owed[id] + s.Pending(id) + s.settled[id]
}

// OwedTotal, PendingTotal, SettledTotal are the summed ledgers (deterministic).
func (s *Settlement) OwedTotal() uint64    { return sumMap(s.owed) }
func (s *Settlement) SettledTotal() uint64 { return sumMap(s.settled) }
func (s *Settlement) PendingTotal() uint64 {
	var sum uint64
	for _, o := range s.pending {
		sum += o.total()
	}
	return sum
}

// PendingBlocks is the count of currently found-but-not-final blocks.
func (s *Settlement) PendingBlocks() int { return len(s.pending) }

func sumMap(m map[uint64]uint64) uint64 {
	var sum uint64
	for _, v := range m {
		sum += v
	}
	return sum
}

// sortedIDs returns a map's keys ascending — the canonical iteration order
// (never range a map in a consensus-visible path).
func sortedIDs(m map[uint64]uint64) []uint64 {
	ids := make([]uint64, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Digest is the canonical SHA-256 commitment over the whole finality-gated
// state: a header (finality K, the three section lengths), then the owed,
// settled, and pending sections, each with ids/blocks in ascending order. The
// header shape domain-separates this from the buffer and ledger digests (they
// commit to different things and must never collide). Because Found only moves
// owed into a keyed overlay and Orphan moves the identical weight back, a
// found->orphaned round trip reproduces the exact prior digest.
func (s *Settlement) Digest() Digest {
	h := sha256.New()
	var hdr [28]byte
	binary.LittleEndian.PutUint32(hdr[0:4], s.finalityK)
	binary.LittleEndian.PutUint64(hdr[4:12], uint64(len(s.owed)))
	binary.LittleEndian.PutUint64(hdr[12:20], uint64(len(s.settled)))
	binary.LittleEndian.PutUint64(hdr[20:28], uint64(len(s.pending)))
	h.Write(hdr[:])

	var rec [16]byte
	writeSection := func(m map[uint64]uint64) {
		for _, id := range sortedIDs(m) {
			binary.LittleEndian.PutUint64(rec[0:8], id)
			binary.LittleEndian.PutUint64(rec[8:16], m[id])
			h.Write(rec[:])
		}
	}
	writeSection(s.owed)
	writeSection(s.settled)

	// Pending: block ids ascending; each block writes its id + entry count, then
	// its (id, amount) entries ascending.
	blocks := make([]uint64, 0, len(s.pending))
	for b := range s.pending {
		blocks = append(blocks, b)
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i] < blocks[j] })
	var bhdr [16]byte
	for _, b := range blocks {
		o := s.pending[b]
		binary.LittleEndian.PutUint64(bhdr[0:8], b)
		binary.LittleEndian.PutUint64(bhdr[8:16], uint64(len(o.amt)))
		h.Write(bhdr[:])
		writeSection(o.amt)
	}

	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
