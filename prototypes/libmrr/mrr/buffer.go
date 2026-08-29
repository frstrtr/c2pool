// buffer.go — the MRR Roundabout buffer (V37 m2 Drop 1).
//
// The Roundabout is the bin-clock ring that ingests scored shares into the
// live PPLNS-style window. It is the settlement machine's front stage: shares
// arrive (possibly out of order within the fine span), are deduplicated by
// identity, accumulate integer weight into their absolute bin, and fall out of
// the live set exactly when the monotone bin-clock advances past them.
//
// This file prototypes the buffer against the m1 TLA settlement spec's front
// invariants — dedup (a live share counts once), expiry (a share older than
// the window is not live), and bin-clock convergence (the head is monotone and
// the live set is a pure function of head + the accepted, non-expired shares).
// Self-carry compaction (Drop 2) and the finality-gated owed/overlay ledger
// (Drop 3) build on this stage; they are NOT in this file.
//
// Determinism is absolute, same mandate as geometry.go: fixed-width integer
// serialization, integer comparisons, no floating point, no wall-clock. The
// canonical Digest is order-independent (commutative) over the accepted live
// set — two ingest orderings of the same live shares hash identically — which
// is the buffer-level analogue of the overlay-commutativity property.
package mrr

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"sort"
)

// IngestResult is the disposition of a single Ingest call. Exactly one of the
// three outcomes applies; the buffer never silently drops (§9 R-3) — a rejected
// share is reported, not swallowed.
type IngestResult uint8

const (
	// Accepted: the share was credited into its bin and is now live.
	Accepted IngestResult = iota
	// Duplicate: a share with this identity is already live; the buffer is
	// unchanged (Ingest is idempotent over a live identity).
	Duplicate
	// Expired: the share's bin lies at or below head-window; it is outside the
	// live window and is not credited.
	Expired
)

func (r IngestResult) String() string {
	switch r {
	case Accepted:
		return "accepted"
	case Duplicate:
		return "duplicate"
	case Expired:
		return "expired"
	default:
		return "unknown"
	}
}

// ErrZeroWindow is returned by NewBuffer when the geometry's window is zero.
var ErrZeroWindow = errors.New("mrr: buffer window (WindowBins) is zero")

// binSlot is one ring cell. It is "used" while an absolute bin currently
// occupies it; bin==the absolute index it holds. weight is the summed integer
// score credited to that bin; ids are the share identities credited to it, in
// ingest order (sorted only at Digest time, so the digest is order-independent).
type binSlot struct {
	bin    uint64
	weight uint64
	ids    []uint64
	used   bool
}

// Buffer is the Roundabout bin-clock ring. The live window is the half-open
// interval (head-window, head] in absolute bin indices; a bin maps to ring slot
// (bin & mask). Capacity is the smallest power of two >= window, so no two live
// bins ever alias the same slot.
type Buffer struct {
	window  uint64            // W: live-window width in bins (Geometry.WindowBins)
	mask    uint64            // capacity-1; capacity = nextPow2(window)
	head    uint64            // bin-clock: highest live bin index (valid iff hasHead)
	hasHead bool              // false until the first Accepted share
	slots   []binSlot         // ring, len == capacity
	live    map[uint64]uint64 // id -> bin, for O(1) window-wide dedup and eviction
}

// NewBuffer constructs a Roundabout buffer sized from the geometry's window.
// The buffer depends only on WindowBins; the full geometry is taken so the
// constructor signature stays stable as later phases consume more dimensions.
func NewBuffer(g Geometry) (*Buffer, error) {
	if g.WindowBins == 0 {
		return nil, ErrZeroWindow
	}
	w := uint64(g.WindowBins)
	capacity := nextPow2(w)
	return &Buffer{
		window: w,
		mask:   capacity - 1,
		slots:  make([]binSlot, capacity),
		live:   make(map[uint64]uint64),
	}, nil
}

// nextPow2 returns the smallest power of two >= n (>= 1 for n<=1).
func nextPow2(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	if n&(n-1) == 0 {
		return n
	}
	return uint64(1) << bits.Len64(n)
}

// Ingest credits a share of the given identity, absolute bin, and integer
// weight. It advances the bin-clock (monotone) when the share sits ahead of the
// current head, evicting anything the advance pushes out of the window. Returns
// the disposition; the buffer state is a pure function of the accepted,
// non-expired shares and the resulting head.
func (b *Buffer) Ingest(id, bin, weight uint64) IngestResult {
	// Expiry is judged against the CURRENT head, before any advance: a share
	// that is already outside the window cannot resurrect it.
	if b.hasHead && bin+b.window <= b.head {
		return Expired
	}
	// Bin-clock advance (monotone). A share ahead of head moves the clock
	// forward and evicts bins that thereby leave the window.
	if !b.hasHead {
		b.head = bin
		b.hasHead = true
	} else if bin > b.head {
		b.advance(bin)
	}
	// Dedup across the whole live window, keyed on identity.
	if _, dup := b.live[id]; dup {
		return Duplicate
	}
	s := &b.slots[bin&b.mask]
	if !s.used || s.bin != bin {
		*s = binSlot{bin: bin, used: true}
	}
	s.weight += weight
	s.ids = append(s.ids, id)
	b.live[id] = bin
	return Accepted
}

// advance moves head forward to newHead (> head), evicting every bin that was
// live and now falls at or below newHead-window. Work is bounded by capacity:
// bins older than that were already evicted or overwritten.
func (b *Buffer) advance(newHead uint64) {
	if newHead >= b.window {
		thresh := newHead - b.window // bins <= thresh are expired under newHead
		var lo uint64
		if b.head+1 >= b.window {
			lo = b.head + 1 - b.window // oldest bin that was live under old head
		}
		hi := thresh
		if b.head < hi {
			hi = b.head // nothing above the old head was ever ingested
		}
		if span := b.mask + 1; hi >= lo && hi-lo+1 > span {
			lo = hi + 1 - span // clamp to capacity
		}
		for x := lo; x <= hi; x++ {
			s := &b.slots[x&b.mask]
			if s.used && s.bin == x {
				for _, id := range s.ids {
					delete(b.live, id)
				}
				*s = binSlot{}
			}
		}
	}
	b.head = newHead
}

// liveLo returns the lowest bin index currently in the window (0 if the window
// underruns the origin). Valid only when hasHead.
func (b *Buffer) liveLo() uint64 {
	if b.head+1 >= b.window {
		return b.head + 1 - b.window
	}
	return 0
}

// Head reports the current bin-clock and whether it has been set.
func (b *Buffer) Head() (uint64, bool) { return b.head, b.hasHead }

// LiveCount is the number of distinct live shares in the window.
func (b *Buffer) LiveCount() int { return len(b.live) }

// LiveSum is the total integer weight of the live window (the PPLNS-window
// scored total, pre-decay). O(window); deterministic.
func (b *Buffer) LiveSum() uint64 {
	if !b.hasHead {
		return 0
	}
	var sum uint64
	for x := b.liveLo(); x <= b.head; x++ {
		s := &b.slots[x&b.mask]
		if s.used && s.bin == x {
			sum += s.weight
		}
	}
	return sum
}

// Digest is the canonical SHA-256 commitment over the live buffer state:
// the window and head header, then each live bin in ascending bin order with
// its summed weight and its share ids sorted ascending. Sorting the ids makes
// the digest independent of ingest order (commutativity): any two ingest
// sequences producing the same live set hash identically. A divergence here is
// a determinism bug or a tamper and shows up as an immediate mismatch.
func (b *Buffer) Digest() Digest {
	h := sha256.New()
	var hdr [17]byte
	binary.LittleEndian.PutUint64(hdr[0:8], b.window)
	if b.hasHead {
		binary.LittleEndian.PutUint64(hdr[8:16], b.head)
		hdr[16] = 1
	}
	h.Write(hdr[:])
	if b.hasHead {
		var rec [20]byte
		var idb [8]byte
		for x := b.liveLo(); x <= b.head; x++ {
			s := &b.slots[x&b.mask]
			if !s.used || s.bin != x {
				continue
			}
			ids := make([]uint64, len(s.ids))
			copy(ids, s.ids)
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			binary.LittleEndian.PutUint64(rec[0:8], x)
			binary.LittleEndian.PutUint64(rec[8:16], s.weight)
			binary.LittleEndian.PutUint32(rec[16:20], uint32(len(ids)))
			h.Write(rec[:])
			for _, id := range ids {
				binary.LittleEndian.PutUint64(idb[:], id)
				h.Write(idb[:])
			}
		}
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}
