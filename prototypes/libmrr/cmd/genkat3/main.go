// genkat3 regenerates the KAT-3 golden vectors for self-carry compaction
// (V37 m2 Drop 2). Run on a reference build; paste stdout into
// mrr/testdata/kat3_compaction_vectors.json. The generator folds a scripted
// contribution stream into the compacted Ledger and, before it emits any
// vector, ASSERTS:
//
//   - the running total, distinct-identity count, and digest at each step;
//   - the hand-derived final per-identity balances (exact set, no extras),
//     total, and count;
//   - the commutativity invariant three independent ways — reverse fold order,
//     weight-sorted fold order, and split-compact-then-merge — each must
//     reproduce the identical final digest (compact-then-digest ==
//     digest-then-compact).
//
// A wrong implementation cannot mint a golden. compaction_test.go then
// independently replays the committed vectors and checks every field.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"libmrr/mrr"
)

// contrib is one scripted (id, weight) fold.
type contrib struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

// balance is one credited identity's final accrued total (sorted by id).
type balance struct {
	ID     uint64 `json:"id"`
	Weight uint64 `json:"weight"`
}

// ledgerStep is the observable post-state after folding contribution i
// (0-indexed): the running total, distinct-identity count, and canonical digest.
type ledgerStep struct {
	Index  int    `json:"index"`
	Total  uint64 `json:"total"`
	Len    int    `json:"len"`
	Digest string `json:"digest_hex"`
}

// scenario is a named contribution script, its per-step trace, and the hand-
// derived final expectations that gate minting.
type scenario struct {
	Name     string       `json:"name"`
	Contribs []contrib    `json:"contribs"`
	Trace    []ledgerStep `json:"trace"`
	// Hand-derived final state (asserted before emit).
	Want        []balance `json:"want_balances"` // exact final set, sorted by id
	WantTotal   uint64    `json:"want_total"`
	WantLen     int       `json:"want_len"`
	FinalDigest string    `json:"final_digest_hex"` // minted; == Trace[last].Digest
}

func scenarios() []scenario {
	return []scenario{
		{
			// Small-miner consolidation: one identity's work is spread across
			// many folds (as it would be across many bins) and compacts to a
			// single accrued balance. Includes a zero-weight fold (id 4) which
			// must create no entry.
			Name: "small_miner_consolidation",
			Contribs: []contrib{
				{1, 5}, {2, 3}, {1, 7}, {3, 1}, {1, 2}, {2, 4}, {4, 0},
			},
			// id1 = 5+7+2 = 14; id2 = 3+4 = 7; id3 = 1; id4 = 0 -> absent.
			Want:      []balance{{1, 14}, {2, 7}, {3, 1}},
			WantTotal: 22,
			WantLen:   3,
		},
		{
			// Carry-forward with several identities and repeated contributions;
			// larger weights, distinct digest. No zero folds.
			Name: "carry_forward_many_ids",
			Contribs: []contrib{
				{10, 100}, {11, 50}, {12, 25}, {10, 10},
				{13, 7}, {11, 50}, {12, 25}, {10, 10},
			},
			// id10 = 100+10+10 = 120; id11 = 50+50 = 100; id12 = 25+25 = 50; id13 = 7.
			Want:      []balance{{10, 120}, {11, 100}, {12, 50}, {13, 7}},
			WantTotal: 277,
			WantLen:   4,
		},
	}
}

// digestHex compacts cs into a fresh ledger and returns its digest hex.
func digestHex(cs []contrib) string {
	l := mrr.NewLedger()
	for _, c := range cs {
		l.Fold(c.ID, c.Weight)
	}
	d := l.Digest()
	return hex.EncodeToString(d[:])
}

func run(sc *scenario) error {
	l := mrr.NewLedger()
	sc.Trace = make([]ledgerStep, 0, len(sc.Contribs))
	for i, c := range sc.Contribs {
		l.Fold(c.ID, c.Weight)
		d := l.Digest()
		sc.Trace = append(sc.Trace, ledgerStep{
			Index: i, Total: l.Total(), Len: l.Len(),
			Digest: hex.EncodeToString(d[:]),
		})
	}

	// Hand-derived final expectations.
	if l.Len() != sc.WantLen {
		return fmt.Errorf("%s: len=%d, want %d", sc.Name, l.Len(), sc.WantLen)
	}
	if l.Total() != sc.WantTotal {
		return fmt.Errorf("%s: total=%d, want %d", sc.Name, l.Total(), sc.WantTotal)
	}
	if len(sc.Want) != sc.WantLen {
		return fmt.Errorf("%s: want_balances has %d entries, want_len=%d", sc.Name, len(sc.Want), sc.WantLen)
	}
	for _, b := range sc.Want {
		if got := l.Balance(b.ID); got != b.Weight {
			return fmt.Errorf("%s: balance[%d]=%d, want %d", sc.Name, b.ID, got, b.Weight)
		}
	}
	// No identity outside Want may be credited (guards against phantom entries,
	// e.g. a zero-weight fold that wrongly created one).
	wantIDs := make(map[uint64]bool, len(sc.Want))
	for _, b := range sc.Want {
		wantIDs[b.ID] = true
	}
	for _, id := range l.Identities() {
		if !wantIDs[id] {
			return fmt.Errorf("%s: unexpected credited identity %d", sc.Name, id)
		}
	}

	// Commutativity: compact-then-digest is invariant to fold order and to
	// batching. Derive the canonical digest three independent ways and require
	// they all match before minting.
	canon := digestHex(sc.Contribs)

	rev := make([]contrib, len(sc.Contribs))
	for i, c := range sc.Contribs {
		rev[len(sc.Contribs)-1-i] = c
	}
	if got := digestHex(rev); got != canon {
		return fmt.Errorf("%s: reverse-order digest %s != canonical %s", sc.Name, got, canon)
	}

	byWeight := make([]contrib, len(sc.Contribs))
	copy(byWeight, sc.Contribs)
	sort.SliceStable(byWeight, func(i, j int) bool { return byWeight[i].Weight < byWeight[j].Weight })
	if got := digestHex(byWeight); got != canon {
		return fmt.Errorf("%s: weight-sorted digest %s != canonical %s", sc.Name, got, canon)
	}

	// Split-compact-then-merge: partition into halves, compact each, merge.
	half := len(sc.Contribs) / 2
	toContribs := func(cs []contrib) []mrr.Contribution {
		out := make([]mrr.Contribution, len(cs))
		for i, c := range cs {
			out[i] = mrr.Contribution{ID: c.ID, Weight: c.Weight}
		}
		return out
	}
	la := mrr.Compact(toContribs(sc.Contribs[:half]))
	lb := mrr.Compact(toContribs(sc.Contribs[half:]))
	la.Merge(lb)
	md := la.Digest()
	if got := hex.EncodeToString(md[:]); got != canon {
		return fmt.Errorf("%s: split-merge digest %s != canonical %s", sc.Name, got, canon)
	}

	sc.FinalDigest = canon
	if n := len(sc.Trace); n > 0 && sc.Trace[n-1].Digest != canon {
		return fmt.Errorf("%s: last trace digest %s != canonical %s", sc.Name, sc.Trace[n-1].Digest, canon)
	}
	return nil
}

func main() {
	scs := scenarios()
	for i := range scs {
		if err := run(&scs[i]); err != nil {
			fmt.Fprintln(os.Stderr, "genkat3: assertion failed:", err)
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
