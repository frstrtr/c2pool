// compaction.go — self-carry compaction (V37 m2 Drop 2).
//
// The Roundabout buffer (buffer.go, Drop 1) holds transient, position-indexed
// live work: weight accumulates into absolute bins and falls out of the live
// set when the bin-clock advances past the window. Settlement, though, must
// credit an identity's work as one durable, position-free running total that
// SURVIVES window expiry — otherwise a small miner's sub-threshold work, spread
// thin across many bins and forever expiring out of the window, is forfeited
// (the V36 failure this milestone removes; small-miner-equity §6).
//
// Compaction is the deterministic fold from the position-indexed representation
// into a position-free, per-identity accrued Ledger. "Self-carry" is the
// property that a miner carries its OWN work forward: contributions folded into
// the Ledger persist as an accrued balance regardless of whether the originating
// share has since expired from the live window. Many scattered per-bin
// contributions for one identity collapse ("compact") into a single owed total.
//
// Scope fence. This drop is the accounting SUBSTRATE only. It has NO finality
// gating, NO block-found overlay, and NO owed->settled transition — that is the
// finality-gated owed/overlay ledger (Drop 3), deliberately NOT in this file.
// Here every folded contribution is simply "accrued"; nothing settles, nothing
// reverts, no block event exists.
//
// Determinism is absolute, same mandate as geometry.go and buffer.go:
// fixed-width integer serialization, integer add, no floating point, no
// wall-clock, no map iteration in any consensus-visible path (the Digest sorts
// identities before hashing). Accrual is integer addition, which is commutative
// and associative, so the canonical Digest is invariant to the order in which
// contributions are folded and to how they are batched across sub-ledgers
// (compact-then-digest == digest-then-compact). That invariance is the
// compaction-level analogue of the buffer's order-independent digest and is
// pinned as a property test, not asserted in prose.
package mrr

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

// Contribution is one scored unit of work attributed to a payout identity: the
// same (id, weight) pair the buffer ingests, viewed for accrual rather than for
// windowing. Weight is integer score; a zero-weight contribution is not work
// and folds to nothing (see Ledger.Fold).
type Contribution struct {
	ID     uint64
	Weight uint64
}

// Ledger is the compacted accrued balance: payout identity -> total integer
// weight owed, summed across every contribution ever folded in. It is the
// position-free consolidation of windowed work — one entry per identity, no
// matter how many bins that identity's work was spread across. There is no
// expiry here: the Ledger is the durable carry that outlives the live window.
//
// The zero value is not usable; construct with NewLedger.
type Ledger struct {
	bal map[uint64]uint64 // id -> accrued weight; an id is absent iff its total is 0
}

// NewLedger returns an empty accrued Ledger.
func NewLedger() *Ledger {
	return &Ledger{bal: make(map[uint64]uint64)}
}

// Fold accrues weight to an identity's running balance (self-carry: the balance
// persists independently of the live window). Accrual is integer addition, so
// Fold is commutative and associative across identities and across repeated
// folds of the same identity.
//
// A zero-weight fold is a no-op that creates no entry: accruing zero work must
// leave the Ledger — and therefore its Digest — identical to not folding at all,
// so that Digest(Compact(S ∪ {(id,0)})) == Digest(Compact(S)). This keeps the
// canonical form free of phantom zero-balance identities.
func (l *Ledger) Fold(id, weight uint64) {
	if weight == 0 {
		return
	}
	l.bal[id] += weight
}

// FoldContributions folds a batch in one call. Order within the batch does not
// affect the result (commutativity).
func (l *Ledger) FoldContributions(cs []Contribution) {
	for _, c := range cs {
		l.Fold(c.ID, c.Weight)
	}
}

// Compact builds a fresh Ledger from a batch of contributions — the position-
// free consolidation of a set of scored work units. Compact(cs) is exactly an
// empty Ledger with cs folded in; grouping/order of cs is irrelevant.
func Compact(cs []Contribution) *Ledger {
	l := NewLedger()
	l.FoldContributions(cs)
	return l
}

// Merge folds every balance of other into l (self-carry across sub-ledgers).
// Because accrual is associative and commutative, merging compacted sub-ledgers
// is identical to compacting the union of their contributions:
//
//	Digest(Merge(Compact(A), Compact(B))) == Digest(Compact(A ∪ B)).
//
// This is the homomorphism that makes "compact-then-digest == digest-then-
// compact" hold for any partition of the contribution multiset.
func (l *Ledger) Merge(other *Ledger) {
	for id, w := range other.bal {
		l.bal[id] += w // w is always > 0 by the Fold invariant
	}
}

// Balance reports an identity's accrued total (0 if never credited).
func (l *Ledger) Balance(id uint64) uint64 { return l.bal[id] }

// Len is the number of distinct credited identities.
func (l *Ledger) Len() int { return len(l.bal) }

// Total is the sum of all accrued balances — the full carried work, including
// contributions whose originating shares have expired from any live window.
func (l *Ledger) Total() uint64 {
	var sum uint64
	for _, w := range l.bal {
		sum += w
	}
	return sum
}

// Identities returns the credited identities in ascending order — the canonical
// iteration order (never range a map in a consensus-visible path).
func (l *Ledger) Identities() []uint64 {
	ids := make([]uint64, 0, len(l.bal))
	for id := range l.bal {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Digest is the canonical SHA-256 commitment over the compacted Ledger: a
// header carrying the distinct-identity count, then each credited identity in
// ascending order with its accrued weight. Sorting identities makes the digest
// independent of fold order and of how contributions were batched across
// sub-ledgers — the compaction-level commutativity property. A divergence here
// is a determinism bug or a tamper and surfaces as an immediate mismatch.
//
// The header count is domain separation from the buffer digest: the two commit
// to different things (per-identity accrued totals vs per-bin live weight) and
// must never collide by construction.
func (l *Ledger) Digest() Digest {
	h := sha256.New()
	var hdr [8]byte
	binary.LittleEndian.PutUint64(hdr[:], uint64(len(l.bal)))
	h.Write(hdr[:])
	var rec [16]byte
	for _, id := range l.Identities() {
		binary.LittleEndian.PutUint64(rec[0:8], id)
		binary.LittleEndian.PutUint64(rec[8:16], l.bal[id])
		h.Write(rec[:])
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
