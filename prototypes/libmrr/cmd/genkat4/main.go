// genkat4 regenerates the KAT-4 golden vectors for the finality-gated
// owed/overlay ledger (V37 m2 Drop 3). Run on a reference build; paste stdout
// into mrr/testdata/kat4_overlay_vectors.json. The generator drives a scripted
// event stream (accrue / found / finalize / orphan) through a Settlement and,
// before it emits any vector, ASSERTS:
//
//   - the disposition, owed/pending/settled totals, and canonical digest at
//     each step;
//   - I-CONSERVE at every step: owed_total + pending_total + settled_total ==
//     total accrued so far (weight is conserved across every transition);
//   - the hand-derived final owed and settled balances (exact sets, no extras);
//   - each declared snapshot-revert pair: the digest after a found->orphaned
//     round trip is bit-identical to the digest before the block was found.
//
// A wrong implementation cannot mint a golden. overlay_test.go then
// independently replays the committed vectors and re-checks every field, and
// the property tests pin the algebra (revert round-trip, found-order
// commutativity, the symmetric finality gate).
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"libmrr/mrr"
)

// contrib is one payout entry (identity, amount) inside a found block.
type contrib struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

// event is one scripted transition. Kind selects which fields are read:
//
//	accrue:   ID = identity, Weight = work folded into owed
//	found:    ID = blockID,  Payout = tentative per-identity payout
//	finalize: ID = blockID,  Depth  = confirmation depth (gate vs finality K)
//	orphan:   ID = blockID
type event struct {
	Kind   string    `json:"kind"`
	ID     uint64    `json:"id"`
	Weight uint64    `json:"weight,omitempty"`
	Depth  uint32    `json:"depth,omitempty"`
	Payout []contrib `json:"payout,omitempty"`
}

// balance is one identity's final owed or settled total (sorted by id).
type balance struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

// step is the observable post-state after applying event i (0-indexed).
type step struct {
	Index        int    `json:"index"`
	Result       string `json:"result"` // ApplyResult string, or "accrued"
	OwedTotal    uint64 `json:"owed_total"`
	PendingTotal uint64 `json:"pending_total"`
	SettledTotal uint64 `json:"settled_total"`
	Digest       string `json:"digest_hex"`
}

// scenario is a named event script plus hand-derived final expectations.
type scenario struct {
	Name      string  `json:"name"`
	FinalityK uint32  `json:"finality_k"`
	Events    []event `json:"events"`
	Trace     []step  `json:"trace"`
	// Hand-derived final state (asserted before emit).
	WantOwed         []balance `json:"want_owed"`
	WantSettled      []balance `json:"want_settled"`
	WantOwedTotal    uint64    `json:"want_owed_total"`
	WantPendingTotal uint64    `json:"want_pending_total"`
	WantSettledTotal uint64    `json:"want_settled_total"`
	// AssertDigestEqual lists [a,b] step-index pairs whose digests must match —
	// the snapshot-revert obligation (found->orphan restores the prior digest).
	AssertDigestEqual [][2]int `json:"assert_digest_equal,omitempty"`
	FinalDigest       string   `json:"final_digest_hex"`
}

func scenarios() []scenario {
	return []scenario{
		{
			// One block's full lifecycle: accrue owed, find the block (owed ->
			// pending), try to finalize BELOW depth K (gate holds, NotFinal), then
			// finalize AT depth K (pending -> settled). Includes a zero-amount
			// payout entry (id 4) that must earmark nothing.
			Name:      "single_block_lifecycle",
			FinalityK: 6,
			Events: []event{
				{Kind: "accrue", ID: 1, Weight: 10},
				{Kind: "accrue", ID: 2, Weight: 5},
				{Kind: "accrue", ID: 3, Weight: 7},
				{Kind: "found", ID: 100, Payout: []contrib{{1, 10}, {2, 5}, {4, 0}}},
				{Kind: "finalize", ID: 100, Depth: 5}, // below K -> NotFinal
				{Kind: "finalize", ID: 100, Depth: 6}, // at K -> OwedSettled
			},
			// After settle: owed = {3:7} (1 and 2 fully paid), settled = {1:10,2:5}.
			WantOwed:         []balance{{3, 7}},
			WantSettled:      []balance{{1, 10}, {2, 5}},
			WantOwedTotal:    7,
			WantPendingTotal: 0,
			WantSettledTotal: 15,
		},
		{
			// Reorg safety: accrue, find a block, then orphan it. The found->
			// orphaned round trip must restore the exact pre-found digest. Step
			// indices: 0,1 accrue; 2 found; 3 orphan. digest[3] == digest[1].
			Name:      "reorg_revert_roundtrip",
			FinalityK: 4,
			Events: []event{
				{Kind: "accrue", ID: 7, Weight: 20},
				{Kind: "accrue", ID: 8, Weight: 13},
				{Kind: "found", ID: 200, Payout: []contrib{{7, 20}, {8, 13}}},
				{Kind: "orphan", ID: 200},
			},
			// Orphan reverts everything back to owed; nothing settled.
			WantOwed:          []balance{{7, 20}, {8, 13}},
			WantSettled:       nil,
			WantOwedTotal:     33,
			WantPendingTotal:  0,
			WantSettledTotal:  0,
			AssertDigestEqual: [][2]int{{1, 3}},
		},
		{
			// Two candidate tips pending at once over disjoint identities: both
			// found, then one finalized and one orphaned. Exercises multi-block
			// pending state and partial settlement. Order-independence of the two
			// found events over the disjoint end-state is pinned as a property
			// test, not here.
			Name:      "concurrent_two_blocks_split_outcome",
			FinalityK: 3,
			Events: []event{
				{Kind: "accrue", ID: 1, Weight: 8},
				{Kind: "accrue", ID: 2, Weight: 8},
				{Kind: "accrue", ID: 3, Weight: 8},
				{Kind: "accrue", ID: 4, Weight: 8},
				{Kind: "found", ID: 300, Payout: []contrib{{1, 8}, {2, 8}}},
				{Kind: "found", ID: 301, Payout: []contrib{{3, 8}, {4, 8}}},
				{Kind: "finalize", ID: 300, Depth: 3}, // block 300 settles
				{Kind: "orphan", ID: 301},             // block 301 reverts
			},
			// 300 settles ids 1,2; 301 reverts ids 3,4 back to owed.
			WantOwed:         []balance{{3, 8}, {4, 8}},
			WantSettled:      []balance{{1, 8}, {2, 8}},
			WantOwedTotal:    16,
			WantPendingTotal: 0,
			WantSettledTotal: 16,
		},
	}
}

// resultString applies event e to s and returns the transition disposition as
// the string the golden pins ("accrued" for accrue, else ApplyResult.String()).
func apply(s *mrr.Settlement, e event) string {
	switch e.Kind {
	case "accrue":
		s.Accrue(e.ID, e.Weight)
		return "accrued"
	case "found":
		p := make([]mrr.Contribution, len(e.Payout))
		for i, c := range e.Payout {
			p[i] = mrr.Contribution{ID: c.ID, Weight: c.Weight}
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

func run(sc *scenario) error {
	s := mrr.NewSettlement(sc.FinalityK)
	sc.Trace = make([]step, 0, len(sc.Events))
	var accrued uint64 // total ever accrued, for the I-CONSERVE check
	for i, e := range sc.Events {
		if e.Kind == "accrue" {
			accrued += e.Weight
		}
		res := apply(s, e)
		d := s.Digest()
		st := step{
			Index: i, Result: res,
			OwedTotal: s.OwedTotal(), PendingTotal: s.PendingTotal(),
			SettledTotal: s.SettledTotal(),
			Digest:       hex.EncodeToString(d[:]),
		}
		// I-CONSERVE: nothing is created or destroyed by any transition.
		if got := st.OwedTotal + st.PendingTotal + st.SettledTotal; got != accrued {
			return fmt.Errorf("%s step %d: owed+pending+settled=%d, want accrued=%d",
				sc.Name, i, got, accrued)
		}
		sc.Trace = append(sc.Trace, st)
	}

	// Hand-derived final owed/settled (exact sets, no extras).
	if err := checkSet(sc.Name, "owed", s.Owed, s.OwedTotal(), sc.WantOwed, sc.WantOwedTotal); err != nil {
		return err
	}
	if err := checkSet(sc.Name, "settled", s.Settled, s.SettledTotal(), sc.WantSettled, sc.WantSettledTotal); err != nil {
		return err
	}
	if s.PendingTotal() != sc.WantPendingTotal {
		return fmt.Errorf("%s: pending_total=%d, want %d", sc.Name, s.PendingTotal(), sc.WantPendingTotal)
	}

	// Snapshot-revert obligations: each declared pair of step digests must match.
	for _, pair := range sc.AssertDigestEqual {
		a, b := pair[0], pair[1]
		if a < 0 || b < 0 || a >= len(sc.Trace) || b >= len(sc.Trace) {
			return fmt.Errorf("%s: assert_digest_equal index out of range %v", sc.Name, pair)
		}
		if sc.Trace[a].Digest != sc.Trace[b].Digest {
			return fmt.Errorf("%s: snapshot-revert failed: digest[%d]=%s != digest[%d]=%s",
				sc.Name, a, sc.Trace[a].Digest, b, sc.Trace[b].Digest)
		}
	}

	d := s.Digest()
	sc.FinalDigest = hex.EncodeToString(d[:])
	if n := len(sc.Trace); n > 0 && sc.Trace[n-1].Digest != sc.FinalDigest {
		return fmt.Errorf("%s: last trace digest != final digest", sc.Name)
	}
	return nil
}

// checkSet verifies a ledger accessor against a hand-derived balance set: the
// exact membership (no extra credited ids), each amount, and the total.
func checkSet(name, which string, get func(uint64) uint64, gotTotal uint64, want []balance, wantTotal uint64) error {
	if gotTotal != wantTotal {
		return fmt.Errorf("%s: %s_total=%d, want %d", name, which, gotTotal, wantTotal)
	}
	var sum uint64
	for _, b := range want {
		if g := get(b.ID); g != b.Weight {
			return fmt.Errorf("%s: %s[%d]=%d, want %d", name, which, b.ID, g, b.Weight)
		}
		sum += b.Weight
	}
	if sum != wantTotal {
		return fmt.Errorf("%s: %s want-set sums to %d, want_total=%d", name, which, sum, wantTotal)
	}
	return nil
}

func main() {
	scs := scenarios()
	for i := range scs {
		if err := run(&scs[i]); err != nil {
			fmt.Fprintln(os.Stderr, "genkat4: assertion failed:", err)
			os.Exit(1)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(scs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
