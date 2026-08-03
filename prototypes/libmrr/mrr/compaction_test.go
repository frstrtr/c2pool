package mrr

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// --- KAT-3 golden replay ---------------------------------------------------
//
// Compaction must reproduce every pinned vector: the running total, distinct-
// identity count, and canonical digest after each fold, plus the hand-derived
// final balances. A change to any digest here is a change to the consensus-
// visible accrued commitment and must be deliberate (regenerate with
// cmd/genkat3 and review the diff).

type katContrib struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

type katBalance struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

type katLedgerStep struct {
	Index  int    `json:"index"`
	Total  uint64 `json:"total"`
	Len    int    `json:"len"`
	Digest string `json:"digest_hex"`
}

type katCompScenario struct {
	Name        string          `json:"name"`
	Contribs    []katContrib    `json:"contribs"`
	Trace       []katLedgerStep `json:"trace"`
	Want        []katBalance    `json:"want_balances"`
	WantTotal   uint64          `json:"want_total"`
	WantLen     int             `json:"want_len"`
	FinalDigest string          `json:"final_digest_hex"`
}

func loadKAT3(t *testing.T) []katCompScenario {
	t.Helper()
	b, err := os.ReadFile("testdata/kat3_compaction_vectors.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var scs []katCompScenario
	if err := json.Unmarshal(b, &scs); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(scs) == 0 {
		t.Fatal("no golden scenarios")
	}
	return scs
}

func TestKAT3_CompactionGolden(t *testing.T) {
	for _, sc := range loadKAT3(t) {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			if len(sc.Contribs) != len(sc.Trace) {
				t.Fatalf("contribs/trace length mismatch: %d vs %d", len(sc.Contribs), len(sc.Trace))
			}
			l := NewLedger()
			for i, c := range sc.Contribs {
				l.Fold(c.ID, c.Weight)
				w := sc.Trace[i]
				if l.Total() != w.Total {
					t.Fatalf("step %d: total=%d, want %d", i, l.Total(), w.Total)
				}
				if l.Len() != w.Len {
					t.Fatalf("step %d: len=%d, want %d", i, l.Len(), w.Len)
				}
				d := l.Digest()
				if got := hex.EncodeToString(d[:]); got != w.Digest {
					t.Fatalf("step %d: digest\n got %s\nwant %s", i, got, w.Digest)
				}
			}
			if l.Total() != sc.WantTotal || l.Len() != sc.WantLen {
				t.Fatalf("final: total=%d len=%d, want %d/%d", l.Total(), l.Len(), sc.WantTotal, sc.WantLen)
			}
			if l.Len() != len(sc.Want) {
				t.Fatalf("final len=%d but want_balances has %d", l.Len(), len(sc.Want))
			}
			for _, b := range sc.Want {
				if got := l.Balance(b.ID); got != b.Weight {
					t.Fatalf("balance[%d]=%d, want %d", b.ID, got, b.Weight)
				}
			}
			d := l.Digest()
			if got := hex.EncodeToString(d[:]); got != sc.FinalDigest {
				t.Fatalf("final digest\n got %s\nwant %s", got, sc.FinalDigest)
			}
		})
	}
}

// --- Property tests --------------------------------------------------------

// The pinned invariant: the compacted digest is invariant to fold order and to
// how contributions are batched across sub-ledgers — compact-then-digest ==
// digest-then-compact. Proved three ways: any permutation of a single fold
// stream, and the split-compact-then-merge homomorphism.
func TestLedger_CompactDigestCommute(t *testing.T) {
	base := []Contribution{
		{1, 5}, {2, 3}, {1, 7}, {3, 1}, {1, 2}, {2, 4},
		{9, 100}, {4, 8}, {9, 1}, {2, 6},
	}
	canon := Compact(base).Digest()

	// Every rotation is a distinct fold order; all must hash identically.
	for r := 0; r < len(base); r++ {
		perm := make([]Contribution, len(base))
		for i := range base {
			perm[i] = base[(i+r)%len(base)]
		}
		if Compact(perm).Digest() != canon {
			t.Fatalf("rotation %d changed the compacted digest (fold order leaked)", r)
		}
	}

	// Reverse order.
	rev := make([]Contribution, len(base))
	for i := range base {
		rev[len(base)-1-i] = base[i]
	}
	if Compact(rev).Digest() != canon {
		t.Fatal("reverse fold order changed the compacted digest")
	}

	// Sorted-by-weight order.
	byW := make([]Contribution, len(base))
	copy(byW, base)
	sort.SliceStable(byW, func(i, j int) bool { return byW[i].Weight < byW[j].Weight })
	if Compact(byW).Digest() != canon {
		t.Fatal("weight-sorted fold order changed the compacted digest")
	}

	// Split-compact-then-merge at every cut point == compact of the union.
	for cut := 0; cut <= len(base); cut++ {
		a := Compact(base[:cut])
		b := Compact(base[cut:])
		a.Merge(b)
		if a.Digest() != canon {
			t.Fatalf("split at %d then merge changed the compacted digest", cut)
		}
		if a.Total() != Compact(base).Total() {
			t.Fatalf("split at %d then merge changed the total", cut)
		}
	}
}

// Merge is commutative: Merge(A,B) and Merge(B,A) agree on every balance and
// on the digest.
func TestLedger_MergeCommutative(t *testing.T) {
	a := []Contribution{{1, 5}, {2, 3}, {5, 9}}
	b := []Contribution{{2, 4}, {3, 7}, {5, 1}}
	ab := Compact(a)
	ab.Merge(Compact(b))
	ba := Compact(b)
	ba.Merge(Compact(a))
	if ab.Digest() != ba.Digest() {
		t.Fatal("Merge is not commutative on the digest")
	}
	if ab.Total() != ba.Total() {
		t.Fatalf("Merge total differs: %d vs %d", ab.Total(), ba.Total())
	}
}

// A zero-weight fold is a no-op: it creates no entry and leaves the digest
// identical to not folding at all.
func TestLedger_ZeroWeightIsNoOp(t *testing.T) {
	l := NewLedger()
	l.Fold(1, 10)
	l.Fold(2, 20)
	before := l.Digest()
	beforeLen := l.Len()
	l.Fold(3, 0)
	l.Fold(1, 0)
	l.Fold(999, 0)
	if l.Digest() != before {
		t.Fatal("zero-weight fold changed the digest")
	}
	if l.Len() != beforeLen {
		t.Fatalf("zero-weight fold changed len: %d -> %d", beforeLen, l.Len())
	}
	if l.Balance(3) != 0 || l.Balance(999) != 0 {
		t.Fatal("zero-weight fold created a phantom entry")
	}
}

// Two empty ledgers hash equal; the digest changes once real work is folded.
func TestLedger_EmptyDigestStable(t *testing.T) {
	if NewLedger().Digest() != NewLedger().Digest() {
		t.Fatal("two empty ledgers must hash equal")
	}
	l := NewLedger()
	empty := l.Digest()
	l.Fold(1, 1)
	if l.Digest() == empty {
		t.Fatal("digest must change after the first credited fold")
	}
}

// Self-carry: the Ledger carries a miner's work forward past window expiry that
// the Roundabout buffer forgets. Feeding the same unique-id stream to both, the
// ledger total equals the buffer live sum while everything is in-window; after
// the bin-clock advances and evicts, the buffer live sum drops but the ledger
// total is unchanged — the work is carried, not forfeited.
func TestLedger_SelfCarryOutlivesBufferExpiry(t *testing.T) {
	type share struct{ id, bin, w uint64 }
	// All bins within a window of 16, unique ids: no dedup, no expiry yet.
	shares := []share{
		{1, 100, 5}, {2, 101, 7}, {3, 104, 11}, {4, 112, 3}, {5, 114, 9},
	}
	buf, err := NewBuffer(geomForWindow(16))
	if err != nil {
		t.Fatalf("NewBuffer: %v", err)
	}
	led := NewLedger()
	var fullTotal uint64
	for _, s := range shares {
		if r := buf.Ingest(s.id, s.bin, s.w); r != Accepted {
			t.Fatalf("ingest id=%d: %s, want accepted", s.id, r)
		}
		led.Fold(s.id, s.w)
		fullTotal += s.w
	}
	// In-window: the two accountings agree.
	if buf.LiveSum() != led.Total() {
		t.Fatalf("in-window mismatch: buffer live sum %d != ledger total %d", buf.LiveSum(), led.Total())
	}
	if led.Total() != fullTotal {
		t.Fatalf("ledger total %d != full accrued %d", led.Total(), fullTotal)
	}

	// Advance the bin-clock far enough to evict every original share from the
	// live window (does NOT touch the ledger).
	buf.Ingest(6, 200, 1)
	if buf.LiveSum() >= fullTotal {
		t.Fatalf("expected buffer live sum to drop below %d after eviction, got %d", fullTotal, buf.LiveSum())
	}
	// The ledger still carries every unit of the expired work.
	if led.Total() != fullTotal {
		t.Fatalf("self-carry violated: ledger total %d != %d after buffer eviction", led.Total(), fullTotal)
	}
	for _, s := range shares {
		if led.Balance(s.id) != s.w {
			t.Fatalf("carried balance[%d]=%d, want %d", s.id, led.Balance(s.id), s.w)
		}
	}
}

// Identities() is sorted ascending and lists exactly the credited set.
func TestLedger_IdentitiesSorted(t *testing.T) {
	l := Compact([]Contribution{{5, 1}, {2, 1}, {9, 1}, {2, 1}, {1, 1}})
	ids := l.Identities()
	want := []uint64{1, 2, 5, 9}
	if len(ids) != len(want) {
		t.Fatalf("ids=%v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids=%v not ascending/exact, want %v", ids, want)
		}
	}
}
