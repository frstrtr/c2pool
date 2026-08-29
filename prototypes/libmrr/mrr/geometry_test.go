package mrr

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// KAT-1: the code must reproduce every pinned golden vector byte-for-byte and
// digest-for-digest. These vectors are the consensus gate for the byte layout;
// a change to any hash here is a consensus-breaking change and must be
// deliberate (regenerate with cmd/genkat and review the diff).
type katVector struct {
	Name    string   `json:"name"`
	Geom    Geometry `json:"geom"`
	Encoded string   `json:"encoded_hex"`
	Hash    string   `json:"hash_hex"`
	Valid   bool     `json:"valid"`
}

func loadKAT1(t *testing.T) []katVector {
	t.Helper()
	b, err := os.ReadFile("testdata/kat1_vectors.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var vs []katVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(vs) == 0 {
		t.Fatal("no golden vectors")
	}
	return vs
}

func TestKAT1_EncodeHashGolden(t *testing.T) {
	for _, v := range loadKAT1(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			enc := v.Geom.Encode()
			if len(enc) != EncodedSize {
				t.Fatalf("encoded length = %d, want %d", len(enc), EncodedSize)
			}
			if got := hex.EncodeToString(enc); got != v.Encoded {
				t.Errorf("encode mismatch:\n got %s\nwant %s", got, v.Encoded)
			}
			h := v.Geom.Hash()
			if got := hex.EncodeToString(h[:]); got != v.Hash {
				t.Errorf("hash mismatch:\n got %s\nwant %s", got, v.Hash)
			}
			if got := v.Geom.Validate() == nil; got != v.Valid {
				t.Errorf("Validate() accepted=%v, want %v", got, v.Valid)
			}
		})
	}
}

// Decode(Encode(g)) == g for every golden vector (total roundtrip).
func TestKAT1_DecodeRoundtrip(t *testing.T) {
	for _, v := range loadKAT1(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			got, err := Decode(v.Geom.Encode())
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != v.Geom {
				t.Errorf("roundtrip mismatch:\n got %+v\nwant %+v", got, v.Geom)
			}
		})
	}
}

func TestDecode_WrongLength(t *testing.T) {
	for _, n := range []int{0, 35, 37} {
		if _, err := Decode(make([]byte, n)); err == nil {
			t.Errorf("Decode(%d bytes) = nil error, want error", n)
		}
	}
}

// A realistic genesis geometry passes Validate.
func TestValidate_GenesisAccepted(t *testing.T) {
	g := Geometry{
		WindowBins: 8640, EpochBins: 8640, HalfLifeBins: 2880,
		FineSpanBins: 1152, FoldRBins: 64, FinalityDepthK: 100,
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid genesis rejected: %v", err)
	}
}

// Each §1.1 invariant, violated in isolation, is rejected with its sentinel.
func TestValidate_Invariants(t *testing.T) {
	base := Geometry{
		WindowBins: 8640, EpochBins: 8640, HalfLifeBins: 2880,
		FineSpanBins: 1152, FoldRBins: 64, FinalityDepthK: 100,
	}
	cases := []struct {
		name string
		mut  func(*Geometry)
		want error
	}{
		{"fold_zero", func(g *Geometry) { g.FoldRBins = 0 }, ErrFoldZero},
		{"fold_not_pow2", func(g *Geometry) { g.FoldRBins = 48; g.FineSpanBins = 1152; g.EpochBins = 8640; g.WindowBins = 8640 }, ErrFoldNotPow2},
		{"fold_over_max", func(g *Geometry) { g.FoldRBins = FoldRMax << 1 }, ErrFoldOutOfRange},
		{"window_zero", func(g *Geometry) { g.WindowBins = 0 }, ErrZeroDimension},
		{"epoch_zero", func(g *Geometry) { g.EpochBins = 0 }, ErrZeroDimension},
		{"fine_zero", func(g *Geometry) { g.FineSpanBins = 0 }, ErrZeroDimension},
		{"halflife_zero", func(g *Geometry) { g.HalfLifeBins = 0 }, ErrZeroDimension},
		{"fine_not_multiple", func(g *Geometry) { g.FineSpanBins = 1152 + 1 }, ErrFineNotMultiple},
		{"epoch_not_multiple", func(g *Geometry) { g.EpochBins = 8640 + 1 }, ErrEpochNotMultiple},
		{"window_not_multiple", func(g *Geometry) { g.WindowBins = 8640 + 1 }, ErrWindowNotMultiple},
		{"fine_below_k", func(g *Geometry) { g.FinalityDepthK = g.FineSpanBins }, ErrFineCoversK},
		{"epoch_below_fine", func(g *Geometry) { g.EpochBins = 64; g.FineSpanBins = 1152 }, ErrEpochCoversFine},
		{"window_too_large", func(g *Geometry) { g.WindowBins = WindowAbsMax + g.FoldRBins }, ErrWindowTooLarge},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			g := base
			c.mut(&g)
			err := g.Validate()
			if !errors.Is(err, c.want) {
				t.Errorf("Validate() = %v, want %v", err, c.want)
			}
		})
	}
}

// FineCoversK must not false-positive via uint32 overflow on k+FineMargin.
func TestValidate_FineCoversK_NoOverflow(t *testing.T) {
	g := Geometry{
		WindowBins: 64, EpochBins: 64, HalfLifeBins: 64,
		FineSpanBins: 64, FoldRBins: 64, FinalityDepthK: 0xFFFFFFFF,
	}
	if !errors.Is(g.Validate(), ErrFineCoversK) {
		t.Errorf("k=maxuint32 must be rejected by fine-covers-k, got %v", g.Validate())
	}
}
