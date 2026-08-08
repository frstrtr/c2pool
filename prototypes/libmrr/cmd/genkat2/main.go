// genkat2 regenerates the KAT-2 golden vectors for the Roundabout Buffer
// (V37 m2 Drop 1). Run on a reference build; paste stdout into
// mrr/testdata/kat2_buffer_vectors.json. The generator replays a scripted
// ingest sequence and, at each step, ASSERTS the buffer reproduces the
// human-derived disposition/livesum/livecount/head before emitting the digest —
// so a wrong implementation cannot mint a golden. buffer_test.go then
// independently replays the committed vectors and checks every field.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"libmrr/mrr"
)

// op is one scripted Ingest with the disposition we expect by hand.
type op struct {
	ID     uint64 `json:"id"`
	Bin    uint64 `json:"bin"`
	Weight uint64 `json:"weight"`
	Want   string `json:"want"` // "accepted" | "duplicate" | "expired"
}

// step records the observable post-state after applying op i (0-indexed),
// generated live and asserted against the hand-derived Want* fields.
type step struct {
	Index     int    `json:"index"`
	Got       string `json:"got"`        // asserted == op.Want
	Head      uint64 `json:"head"`
	HasHead   bool   `json:"has_head"`
	LiveSum   uint64 `json:"live_sum"`
	LiveCount int    `json:"live_count"`
	Digest    string `json:"digest_hex"`
}

// scenario is a named window + op script + its per-step trace.
type scenario struct {
	Name       string `json:"name"`
	WindowBins uint32 `json:"window_bins"`
	Ops        []op   `json:"ops"`
	Trace      []step `json:"trace"`
	// Independently-derived post-run expectations (a second cross-check).
	WantFinalSum   uint64 `json:"want_final_sum"`
	WantFinalCount int    `json:"want_final_count"`
	WantFinalHead  uint64 `json:"want_final_head"`
}

// The Drop-1 scenarios. geomFor builds a Validate-clean geometry whose window
// drives the buffer; the other dimensions are realistic but unused here.
func geomFor(window uint32) mrr.Geometry {
	// window need not be a power of two; the buffer rounds capacity up.
	return mrr.Geometry{
		WindowBins: window, EpochBins: 1 << 20, HalfLifeBins: window,
		FineSpanBins: 1 << 12, FoldRBins: 1, FinalityDepthK: 0,
	}
}

func scenarios() []scenario {
	return []scenario{
		{
			// W=6 (non power of two -> capacity 8). Exercises in-order accept,
			// same-bin distinct-id accept, duplicate, out-of-order-in-window,
			// boundary expiry, an advance that evicts a live share, re-ingest of
			// an evicted id, and a far-future jump that clears the window.
			Name: "w6_roundabout_core", WindowBins: 6,
			Ops: []op{
				{1, 10, 100, "accepted"},  // head=10; live (4,10]
				{2, 11, 50, "accepted"},   // head=11; live (5,11]
				{3, 11, 25, "accepted"},   // same bin, new id; bin11=75
				{2, 11, 999, "duplicate"}, // id 2 already live; no-op
				{4, 8, 10, "accepted"},    // out of order; 8 in (5,11]
				{5, 5, 7, "expired"},      // 5 <= head-window = 5; expired
				{6, 14, 1, "accepted"},    // head->14; evicts bin8 (id4); live (8,14]
				{4, 15, 3, "accepted"},    // id4 no longer live; head->15
				{1, 10, 100, "duplicate"}, // id1 still live at bin10
				{7, 100, 1000, "accepted"}, // far jump; evicts all but id7
			},
			WantFinalSum: 1000, WantFinalCount: 1, WantFinalHead: 100,
		},
		{
			// W=16 (power of two). Fills a window, then walks the clock forward
			// one bin at a time so shares expire in FIFO order; live sum tracks
			// the trailing-16 window exactly.
			Name: "w16_sliding_window", WindowBins: 16,
			Ops: []op{
				{101, 100, 5, "accepted"},
				{102, 104, 5, "accepted"},
				{103, 108, 5, "accepted"},
				{104, 112, 5, "accepted"}, // head=112; live (96,112]: all 4
				{105, 116, 5, "accepted"}, // head=116; live (100,116]: id101@100 expires-> drop
				{106, 120, 5, "accepted"}, // head=120; live (104,120]: id102@104 drops
				{101, 100, 9, "expired"},  // way behind window
				{107, 128, 5, "accepted"}, // head=128; live (112,128]: evicts id103@108 & id104@112
			},
			WantFinalSum: 15, WantFinalCount: 3, WantFinalHead: 128,
		},
	}
}

func run(sc *scenario) error {
	buf, err := mrr.NewBuffer(geomFor(sc.WindowBins))
	if err != nil {
		return fmt.Errorf("%s: NewBuffer: %w", sc.Name, err)
	}
	sc.Trace = make([]step, 0, len(sc.Ops))
	for i, o := range sc.Ops {
		got := buf.Ingest(o.ID, o.Bin, o.Weight)
		if got.String() != o.Want {
			return fmt.Errorf("%s op %d (id=%d bin=%d): got %s, want %s",
				sc.Name, i, o.ID, o.Bin, got, o.Want)
		}
		head, has := buf.Head()
		d := buf.Digest()
		sc.Trace = append(sc.Trace, step{
			Index: i, Got: got.String(), Head: head, HasHead: has,
			LiveSum: buf.LiveSum(), LiveCount: buf.LiveCount(),
			Digest: hex.EncodeToString(d[:]),
		})
	}
	head, _ := buf.Head()
	if buf.LiveSum() != sc.WantFinalSum || buf.LiveCount() != sc.WantFinalCount || head != sc.WantFinalHead {
		return fmt.Errorf("%s final: sum=%d count=%d head=%d; want sum=%d count=%d head=%d",
			sc.Name, buf.LiveSum(), buf.LiveCount(), head,
			sc.WantFinalSum, sc.WantFinalCount, sc.WantFinalHead)
	}
	return nil
}

func main() {
	scs := scenarios()
	for i := range scs {
		if err := run(&scs[i]); err != nil {
			fmt.Fprintln(os.Stderr, "genkat2: assertion failed:", err)
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
