package mrr

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// --- KAT-4 golden replay ---------------------------------------------------
//
// The finality-gated ledger must reproduce every pinned vector: the disposition,
// owed/pending/settled totals, and canonical digest after each transition, the
// hand-derived final owed/settled balances, and each snapshot-revert digest
// pair. A change to any digest here is a change to the consensus-visible
// settlement commitment and must be deliberate (regenerate with cmd/genkat4 and
// review the diff).

type katContribJSON struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

type katEvent struct {
	Kind   string           `json:"kind"`
	ID     uint64           `json:"id"`
	Weight uint64           `json:"weight"`
	Depth  uint32           `json:"depth"`
	Payout []katContribJSON `json:"payout"`
}

type katOverlayStep struct {
	Index        int    `json:"index"`
	Result       string `json:"result"`
	OwedTotal    uint64 `json:"owed_total"`
	PendingTotal uint64 `json:"pending_total"`
	SettledTotal uint64 `json:"settled_total"`
	Digest       string `json:"digest_hex"`
}

type katOverlayBalance struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

type katOverlayScenario struct {
	Name              string              `json:"name"`
	FinalityK         uint32              `json:"finality_k"`
	Events            []katEvent          `json:"events"`
	Trace             []katOverlayStep    `json:"trace"`
	WantOwed          []katOverlayBalance `json:"want_owed"`
	WantSettled       []katOverlayBalance `json:"want_settled"`
	WantOwedTotal     uint64              `json:"want_owed_total"`
	WantPendingTotal  uint64              `json:"want_pending_total"`
	WantSettledTotal  uint64              `json:"want_settled_total"`
	AssertDigestEqual [][2]int            `json:"assert_digest_equal"`
	FinalDigest       string              `json:"final_digest_hex"`
}

func loadKAT4(t *testing.T) []katOverlayScenario {
	t.Helper()
	b, err := os.ReadFile("testdata/kat4_overlay_vectors.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var scs []katOverlayScenario
	if err := json.Unmarshal(b, &scs); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(scs) == 0 {
		t.Fatal("no golden scenarios")
	}
	return scs
}

// applyEvent drives one golden event through s and returns its disposition
// string, exactly as genkat4 does.
func applyEvent(s *Settlement, e katEvent) string {
	switch e.Kind {
	case "accrue":
		s.Accrue(e.ID, e.Weight)
		return "accrued"
	case "found":
		p := make([]Contribution, len(e.Payout))
		for i, c := range e.Payout {
			p[i] = Contribution{ID: c.ID, Weight: c.Weight}
		}
		return s.BlockFound(e.ID, p).String()
	case "finalize":
		return s.Finalize(e.ID, e.Depth).String()
	case "orphan":
		return s.Orphan(e.ID).String()
	default:
		return "BAD_KIND:" + e.Kind
	}
}

func TestKAT4_OverlayGolden(t *testing.T) {
	for _, sc := range loadKAT4(t) {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			if len(sc.Events) != len(sc.Trace) {
				t.Fatalf("events/trace length mismatch: %d vs %d", len(sc.Events), len(sc.Trace))
			}
			s := NewSettlement(sc.FinalityK)
			for i, e := range sc.Events {
				res := applyEvent(s, e)
				w := sc.Trace[i]
				if res != w.Result {
					t.Fatalf("step %d: result=%q, want %q", i, res, w.Result)
				}
				if s.OwedTotal() != w.OwedTotal || s.PendingTotal() != w.PendingTotal || s.SettledTotal() != w.SettledTotal {
					t.Fatalf("step %d: totals owed=%d pending=%d settled=%d, want %d/%d/%d",
						i, s.OwedTotal(), s.PendingTotal(), s.SettledTotal(),
						w.OwedTotal, w.PendingTotal, w.SettledTotal)
				}
				d := s.Digest()
				if got := hex.EncodeToString(d[:]); got != w.Digest {
					t.Fatalf("step %d: digest\n got %s\nwant %s", i, got, w.Digest)
				}
			}

			// Final hand-derived owed/settled sets (exact membership + amount).
			if s.OwedTotal() != sc.WantOwedTotal || s.SettledTotal() != sc.WantSettledTotal || s.PendingTotal() != sc.WantPendingTotal {
				t.Fatalf("final totals owed=%d pending=%d settled=%d, want %d/%d/%d",
					s.OwedTotal(), s.PendingTotal(), s.SettledTotal(),
					sc.WantOwedTotal, sc.WantPendingTotal, sc.WantSettledTotal)
			}
			for _, b := range sc.WantOwed {
				if g := s.Owed(b.ID); g != b.Weight {
					t.Fatalf("owed[%d]=%d, want %d", b.ID, g, b.Weight)
				}
			}
			for _, b := range sc.WantSettled {
				if g := s.Settled(b.ID); g != b.Weight {
					t.Fatalf("settled[%d]=%d, want %d", b.ID, g, b.Weight)
				}
			}

			// Snapshot-revert obligations declared in the golden.
			for _, pair := range sc.AssertDigestEqual {
				if sc.Trace[pair[0]].Digest != sc.Trace[pair[1]].Digest {
					t.Fatalf("snapshot-revert failed: digest[%d] != digest[%d]", pair[0], pair[1])
				}
			}

			d := s.Digest()
			if got := hex.EncodeToString(d[:]); got != sc.FinalDigest {
				t.Fatalf("final digest\n got %s\nwant %s", got, sc.FinalDigest)
			}
		})
	}
}

// --- Property tests --------------------------------------------------------

// Snapshot revert: a found->orphaned round trip restores the exact prior state,
// bit-for-bit, at every point in an arbitrary event history. This is the
// core reorg-safety property — no payout leaves a trace once its block is
// orphaned.
func TestSettlement_RevertRoundTrip(t *testing.T) {
	s := NewSettlement(5)
	s.Accrue(1, 30)
	s.Accrue(2, 20)
	s.Accrue(3, 10)
	// Another block already pending, to prove the revert is independent of
	// unrelated overlay state.
	if r := s.BlockFound(900, []Contribution{{3, 10}}); r != OverlayAdded {
		t.Fatalf("setup found: %s", r)
	}
	before := s.Digest()

	if r := s.BlockFound(901, []Contribution{{1, 30}, {2, 15}}); r != OverlayAdded {
		t.Fatalf("found 901: %s", r)
	}
	if s.Digest() == before {
		t.Fatal("found did not change the digest")
	}
	if r := s.Orphan(901); r != OverlayReverted {
		t.Fatalf("orphan 901: %s", r)
	}
	if s.Digest() != before {
		t.Fatal("found->orphan did not restore the prior digest (snapshot revert violated)")
	}
	// Owed for the touched ids is exactly restored.
	if s.Owed(1) != 30 || s.Owed(2) != 20 {
		t.Fatalf("owed not restored: id1=%d id2=%d", s.Owed(1), s.Owed(2))
	}
}

// Found-order commutativity: two blocks over disjoint identities found in either
// order reach the identical digest — both while both are pending and after both
// finalize. The keyed overlays draw from the shared owed pool without ordering
// interference when they do not contend for the same id.
func TestSettlement_FoundOrderCommutes(t *testing.T) {
	build := func(firstA bool) *Settlement {
		s := NewSettlement(2)
		s.Accrue(1, 10)
		s.Accrue(2, 10)
		s.Accrue(3, 10)
		s.Accrue(4, 10)
		a := func() { s.BlockFound(500, []Contribution{{1, 10}, {2, 10}}) }
		b := func() { s.BlockFound(501, []Contribution{{3, 10}, {4, 10}}) }
		if firstA {
			a()
			b()
		} else {
			b()
			a()
		}
		return s
	}
	ab, ba := build(true), build(false)
	if ab.Digest() != ba.Digest() {
		t.Fatal("found order changed the pending digest (commutativity violated)")
	}
	// Finalize both in opposite orders; end-state still agrees.
	ab.Finalize(500, 2)
	ab.Finalize(501, 2)
	ba.Finalize(501, 2)
	ba.Finalize(500, 2)
	if ab.Digest() != ba.Digest() {
		t.Fatal("finalize order changed the settled digest")
	}
	if ab.SettledTotal() != 40 || ab.OwedTotal() != 0 || ab.PendingTotal() != 0 {
		t.Fatalf("unexpected end-state: owed=%d pending=%d settled=%d",
			ab.OwedTotal(), ab.PendingTotal(), ab.SettledTotal())
	}
}

// Symmetric finality gate: a payout may not settle before depth K. Finalize
// below K is a no-op (NotFinal) that leaves the digest untouched and the overlay
// reversible; at/above K it settles.
func TestSettlement_SymmetricFinalityGate(t *testing.T) {
	const K = 6
	s := NewSettlement(K)
	s.Accrue(1, 100)
	s.BlockFound(1, []Contribution{{1, 100}})
	pendingDigest := s.Digest()

	for depth := uint32(0); depth < K; depth++ {
		if r := s.Finalize(1, depth); r != NotFinal {
			t.Fatalf("depth %d: result=%s, want not_final", depth, r)
		}
		if s.Digest() != pendingDigest {
			t.Fatalf("depth %d: below-K finalize mutated state", depth)
		}
		if s.SettledTotal() != 0 {
			t.Fatalf("depth %d: settled before finality", depth)
		}
		// Still reversible while the gate holds.
	}
	if r := s.Finalize(1, K); r != OwedSettled {
		t.Fatalf("depth K: result=%s, want owed_settled", r)
	}
	if s.SettledTotal() != 100 || s.Settled(1) != 100 || s.PendingTotal() != 0 {
		t.Fatalf("post-settle: settled=%d pending=%d", s.SettledTotal(), s.PendingTotal())
	}
}

// I-CONSERVE: owed + pending + settled equals total accrued after every
// transition, regardless of the event mix.
func TestSettlement_Conservation(t *testing.T) {
	s := NewSettlement(3)
	type ev struct {
		kind   string
		id     uint64
		w      uint64
		depth  uint32
		payout []Contribution
	}
	var accrued uint64
	evs := []ev{
		{kind: "accrue", id: 1, w: 50},
		{kind: "accrue", id: 2, w: 40},
		{kind: "found", id: 10, payout: []Contribution{{1, 50}, {2, 20}}},
		{kind: "accrue", id: 2, w: 5},
		{kind: "found", id: 11, payout: []Contribution{{2, 25}}},
		{kind: "finalize", id: 10, depth: 3},
		{kind: "orphan", id: 11},
		{kind: "finalize", id: 11, depth: 9}, // unknown now -> no-op
	}
	for i, e := range evs {
		switch e.kind {
		case "accrue":
			s.Accrue(e.id, e.w)
			accrued += e.w
		case "found":
			s.BlockFound(e.id, e.payout)
		case "finalize":
			s.Finalize(e.id, e.depth)
		case "orphan":
			s.Orphan(e.id)
		}
		if got := s.OwedTotal() + s.PendingTotal() + s.SettledTotal(); got != accrued {
			t.Fatalf("step %d (%s): conservation broke: sum=%d accrued=%d", i, e.kind, got, accrued)
		}
	}
}

// A found overlay may not draw more than an identity's owed; the whole
// transition is rejected atomically and nothing is mutated.
func TestSettlement_OverdrawRejectedAtomic(t *testing.T) {
	s := NewSettlement(2)
	s.Accrue(1, 10)
	s.Accrue(2, 10)
	before := s.Digest()
	// id2 wants 11 but only 10 is owed -> Overdraw; id1's valid 10 must NOT be
	// applied (atomic rejection).
	if r := s.BlockFound(1, []Contribution{{1, 10}, {2, 11}}); r != Overdraw {
		t.Fatalf("result=%s, want overdraw", r)
	}
	if s.Digest() != before {
		t.Fatal("overdraw partially mutated state")
	}
	if s.Owed(1) != 10 || s.PendingBlocks() != 0 {
		t.Fatalf("overdraw left residue: owed1=%d blocks=%d", s.Owed(1), s.PendingBlocks())
	}
}

// Two overlays cannot double-spend the same owed: after the first draws it, the
// second sees reduced availability and is rejected.
func TestSettlement_NoDoubleSpendAcrossBlocks(t *testing.T) {
	s := NewSettlement(2)
	s.Accrue(1, 10)
	if r := s.BlockFound(1, []Contribution{{1, 8}}); r != OverlayAdded {
		t.Fatalf("first found: %s", r)
	}
	// Only 2 owed remains available; a second draw of 5 must be rejected.
	if r := s.BlockFound(2, []Contribution{{1, 5}}); r != Overdraw {
		t.Fatalf("second found: %s, want overdraw", r)
	}
	// A draw within the remainder succeeds.
	if r := s.BlockFound(3, []Contribution{{1, 2}}); r != OverlayAdded {
		t.Fatalf("third found: %s", r)
	}
	if s.Owed(1) != 0 || s.PendingTotal() != 10 {
		t.Fatalf("owed=%d pending=%d, want 0/10", s.Owed(1), s.PendingTotal())
	}
}

// The owed base seeds from a compacted Drop-2 Ledger (cross-link): the
// Settlement's owed exactly equals the ledger's per-identity accrued balances.
func TestSettlement_FromLedgerSeedsOwed(t *testing.T) {
	l := Compact([]Contribution{{1, 5}, {2, 3}, {1, 7}, {3, 1}})
	s := NewSettlementFromLedger(l, 4)
	if s.OwedTotal() != l.Total() {
		t.Fatalf("owed total %d != ledger total %d", s.OwedTotal(), l.Total())
	}
	for _, id := range l.Identities() {
		if s.Owed(id) != l.Balance(id) {
			t.Fatalf("owed[%d]=%d != balance %d", id, s.Owed(id), l.Balance(id))
		}
	}
}

// Duplicate found and unknown finalize/orphan are reported no-ops.
func TestSettlement_KnownAndUnknownBlocks(t *testing.T) {
	s := NewSettlement(2)
	s.Accrue(1, 10)
	if r := s.BlockFound(1, []Contribution{{1, 5}}); r != OverlayAdded {
		t.Fatalf("found: %s", r)
	}
	before := s.Digest()
	if r := s.BlockFound(1, []Contribution{{1, 1}}); r != BlockKnown {
		t.Fatalf("dup found: %s, want block_known", r)
	}
	if r := s.Finalize(999, 9); r != BlockUnknown {
		t.Fatalf("finalize unknown: %s, want block_unknown", r)
	}
	if r := s.Orphan(999); r != BlockUnknown {
		t.Fatalf("orphan unknown: %s, want block_unknown", r)
	}
	if s.Digest() != before {
		t.Fatal("a no-op transition mutated state")
	}
}

// Two empty settlements hash equal; the digest changes once work is accrued.
// Finality K is part of the commitment, so it separates otherwise-equal states.
func TestSettlement_EmptyDigestStableAndKSeparated(t *testing.T) {
	if NewSettlement(4).Digest() != NewSettlement(4).Digest() {
		t.Fatal("two empty settlements must hash equal")
	}
	if NewSettlement(4).Digest() == NewSettlement(5).Digest() {
		t.Fatal("different finality K must not collide")
	}
	s := NewSettlement(4)
	empty := s.Digest()
	s.Accrue(1, 1)
	if s.Digest() == empty {
		t.Fatal("digest must change after the first accrual")
	}
}

// A zero-weight accrual is a no-op that creates no phantom owed entry.
func TestSettlement_ZeroAccrueNoOp(t *testing.T) {
	s := NewSettlement(3)
	s.Accrue(1, 10)
	before := s.Digest()
	s.Accrue(2, 0)
	s.Accrue(1, 0)
	if s.Digest() != before {
		t.Fatal("zero accrual changed the digest")
	}
	if s.Owed(2) != 0 || s.OwedTotal() != 10 {
		t.Fatalf("zero accrual created residue: owed2=%d total=%d", s.Owed(2), s.OwedTotal())
	}
}
