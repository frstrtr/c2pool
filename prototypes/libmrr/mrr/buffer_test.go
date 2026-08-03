package mrr

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// --- KAT-2 golden replay ---------------------------------------------------
//
// The buffer must reproduce every pinned Roundabout vector: disposition, head,
// live sum, live count, and the canonical digest at each step. A change to any
// digest here is a change to the consensus-visible buffer commitment and must
// be deliberate (regenerate with cmd/genkat2 and review the diff).

type katStep struct {
	Index     int    `json:"index"`
	Got       string `json:"got"`
	Head      uint64 `json:"head"`
	HasHead   bool   `json:"has_head"`
	LiveSum   uint64 `json:"live_sum"`
	LiveCount int    `json:"live_count"`
	Digest    string `json:"digest_hex"`
}

type katOp struct {
	ID     uint64 `json:"id"`
	Bin    uint64 `json:"bin"`
	Weight uint64 `json:"weight"`
	Want   string `json:"want"`
}

type katScenario struct {
	Name           string    `json:"name"`
	WindowBins     uint32    `json:"window_bins"`
	Ops            []katOp   `json:"ops"`
	Trace          []katStep `json:"trace"`
	WantFinalSum   uint64    `json:"want_final_sum"`
	WantFinalCount int       `json:"want_final_count"`
	WantFinalHead  uint64    `json:"want_final_head"`
}

func loadKAT2(t *testing.T) []katScenario {
	t.Helper()
	b, err := os.ReadFile("testdata/kat2_buffer_vectors.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var scs []katScenario
	if err := json.Unmarshal(b, &scs); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(scs) == 0 {
		t.Fatal("no golden scenarios")
	}
	return scs
}

func geomForWindow(window uint32) Geometry {
	return Geometry{
		WindowBins: window, EpochBins: 1 << 20, HalfLifeBins: window,
		FineSpanBins: 1 << 12, FoldRBins: 1, FinalityDepthK: 0,
	}
}

func TestKAT2_BufferGolden(t *testing.T) {
	for _, sc := range loadKAT2(t) {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			if len(sc.Ops) != len(sc.Trace) {
				t.Fatalf("ops/trace length mismatch: %d vs %d", len(sc.Ops), len(sc.Trace))
			}
			buf, err := NewBuffer(geomForWindow(sc.WindowBins))
			if err != nil {
				t.Fatalf("NewBuffer: %v", err)
			}
			for i, o := range sc.Ops {
				got := buf.Ingest(o.ID, o.Bin, o.Weight)
				w := sc.Trace[i]
				if got.String() != o.Want || got.String() != w.Got {
					t.Fatalf("op %d: disposition=%s, op.want=%s trace.got=%s", i, got, o.Want, w.Got)
				}
				head, has := buf.Head()
				if head != w.Head || has != w.HasHead {
					t.Fatalf("op %d: head=(%d,%v), want (%d,%v)", i, head, has, w.Head, w.HasHead)
				}
				if buf.LiveSum() != w.LiveSum {
					t.Fatalf("op %d: live_sum=%d, want %d", i, buf.LiveSum(), w.LiveSum)
				}
				if buf.LiveCount() != w.LiveCount {
					t.Fatalf("op %d: live_count=%d, want %d", i, buf.LiveCount(), w.LiveCount)
				}
				d := buf.Digest()
				if got := hex.EncodeToString(d[:]); got != w.Digest {
					t.Fatalf("op %d: digest\n got %s\nwant %s", i, got, w.Digest)
				}
			}
			head, _ := buf.Head()
			if buf.LiveSum() != sc.WantFinalSum || buf.LiveCount() != sc.WantFinalCount || head != sc.WantFinalHead {
				t.Fatalf("final: sum=%d count=%d head=%d; want %d/%d/%d",
					buf.LiveSum(), buf.LiveCount(), head, sc.WantFinalSum, sc.WantFinalCount, sc.WantFinalHead)
			}
		})
	}
}

// --- Property tests --------------------------------------------------------

func TestBuffer_ZeroWindowRejected(t *testing.T) {
	if _, err := NewBuffer(Geometry{WindowBins: 0}); err == nil {
		t.Fatal("zero window must be rejected")
	}
}

// Dedup is idempotent over a live identity: re-ingesting a live share reports
// Duplicate and leaves the digest, sum, and count unchanged.
func TestBuffer_DedupIdempotent(t *testing.T) {
	buf, _ := NewBuffer(geomForWindow(16))
	buf.Ingest(1, 100, 10)
	buf.Ingest(2, 101, 20)
	before := buf.Digest()
	sum, cnt := buf.LiveSum(), buf.LiveCount()
	for i := 0; i < 5; i++ {
		if r := buf.Ingest(1, 100, 999); r != Duplicate {
			t.Fatalf("re-ingest %d: got %s, want duplicate", i, r)
		}
	}
	if buf.Digest() != before {
		t.Fatal("duplicate ingest changed the digest")
	}
	if buf.LiveSum() != sum || buf.LiveCount() != cnt {
		t.Fatalf("duplicate changed sum/count: %d/%d vs %d/%d", buf.LiveSum(), buf.LiveCount(), sum, cnt)
	}
}

// The digest is order-independent: two ingest orderings of the same live set
// hash identically (buffer-level commutativity).
func TestBuffer_DigestCommutative(t *testing.T) {
	type sh struct{ id, bin, w uint64 }
	shares := []sh{{1, 100, 5}, {2, 100, 7}, {3, 101, 11}, {4, 108, 3}, {5, 112, 9}}
	fwd, _ := NewBuffer(geomForWindow(16))
	for _, s := range shares {
		fwd.Ingest(s.id, s.bin, s.w)
	}
	rev, _ := NewBuffer(geomForWindow(16))
	for i := len(shares) - 1; i >= 0; i-- {
		s := shares[i]
		rev.Ingest(s.id, s.bin, s.w)
	}
	if fwd.Digest() != rev.Digest() {
		t.Fatal("digest is not order-independent")
	}
	if fwd.LiveSum() != rev.LiveSum() || fwd.LiveCount() != rev.LiveCount() {
		t.Fatal("sum/count differ across ingest order")
	}
}

// The bin-clock is monotone: a share behind the head never lowers it, and a
// share at or below head-window is Expired.
func TestBuffer_BinClockMonotoneAndExpiry(t *testing.T) {
	buf, _ := NewBuffer(geomForWindow(8))
	buf.Ingest(1, 20, 1) // head=20
	if h, _ := buf.Head(); h != 20 {
		t.Fatalf("head=%d, want 20", h)
	}
	if r := buf.Ingest(2, 15, 1); r != Accepted { // 15 in (12,20], in-window
		t.Fatalf("in-window behind-head: got %s, want accepted", r)
	}
	if h, _ := buf.Head(); h != 20 {
		t.Fatalf("head moved backward to %d", h)
	}
	if r := buf.Ingest(3, 12, 1); r != Expired { // 12 <= head-window = 12
		t.Fatalf("boundary bin: got %s, want expired", r)
	}
	if r := buf.Ingest(4, 5, 1); r != Expired { // far behind
		t.Fatalf("far-behind bin: got %s, want expired", r)
	}
}

// Advancing the clock evicts exactly the shares that leave the window, and an
// evicted id may be re-ingested (it is no longer live).
func TestBuffer_EvictionAndReingest(t *testing.T) {
	buf, _ := NewBuffer(geomForWindow(8))
	buf.Ingest(1, 10, 100) // head=10, live (2,10]
	buf.Ingest(2, 11, 50)  // head=11
	if buf.LiveCount() != 2 {
		t.Fatalf("count=%d, want 2", buf.LiveCount())
	}
	buf.Ingest(3, 19, 1) // head=19; live (11,19]; id1@10 and id2@11 both expired
	if buf.LiveCount() != 1 || buf.LiveSum() != 1 {
		t.Fatalf("after advance: count=%d sum=%d, want 1/1", buf.LiveCount(), buf.LiveSum())
	}
	if r := buf.Ingest(1, 18, 7); r != Accepted { // id1 no longer live
		t.Fatalf("re-ingest evicted id: got %s, want accepted", r)
	}
	if buf.LiveCount() != 2 || buf.LiveSum() != 8 {
		t.Fatalf("after re-ingest: count=%d sum=%d, want 2/8", buf.LiveCount(), buf.LiveSum())
	}
}

// Empty buffer has a stable, head-less digest that differs once a share lands.
func TestBuffer_EmptyDigestStable(t *testing.T) {
	a, _ := NewBuffer(geomForWindow(16))
	b, _ := NewBuffer(geomForWindow(16))
	if a.Digest() != b.Digest() {
		t.Fatal("two empty buffers of the same window must hash equal")
	}
	if _, has := a.Head(); has {
		t.Fatal("empty buffer must not have a head")
	}
	a.Ingest(1, 100, 1)
	if a.Digest() == b.Digest() {
		t.Fatal("digest must change after the first accepted share")
	}
}
