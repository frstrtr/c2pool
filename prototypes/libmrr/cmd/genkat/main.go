// genkat regenerates the KAT-1 golden vectors for Geometry encode/hash.
// Run on a reference build; paste stdout into mrr/testdata/kat1_vectors.json.
// The test verifies the code reproduces exactly these bytes+digests.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"libmrr/mrr"
)

type vector struct {
	Name    string       `json:"name"`
	Geom    mrr.Geometry `json:"geom"`
	Encoded string       `json:"encoded_hex"`
	Hash    string       `json:"hash_hex"`
	Valid   bool         `json:"valid"` // does Validate() accept it
}

func kat1() []vector {
	geoms := []struct {
		name string
		g    mrr.Geometry
	}{
		// All-zero: locks the zero byte pattern and the empty-field digest.
		{"all_zero", mrr.Geometry{}},
		// All-max bytes: every field at its uint max. Locks the max byte
		// layout at the extreme; Validate rejects it (fold_r not pow2 etc.).
		{"all_max_bytes", mrr.Geometry{
			Version: 0xFFFFFFFF, ActivationBin: 0xFFFFFFFFFFFFFFFF,
			WindowBins: 0xFFFFFFFF, EpochBins: 0xFFFFFFFF, HalfLifeBins: 0xFFFFFFFF,
			FineSpanBins: 0xFFFFFFFF, FoldRBins: 0xFFFFFFFF, FinalityDepthK: 0xFFFFFFFF,
		}},
		// Field-distinguishing: distinct small value per field so any byte
		// transposition / field-order bug is caught by the digest.
		{"distinct_fields", mrr.Geometry{
			Version: 1, ActivationBin: 2, WindowBins: 3, EpochBins: 4,
			HalfLifeBins: 5, FineSpanBins: 6, FoldRBins: 7, FinalityDepthK: 8,
		}},
		// Realistic valid genesis: passes Validate.
		{"genesis_valid", mrr.Geometry{
			Version: 0, ActivationBin: 0,
			WindowBins: 8640, EpochBins: 8640, HalfLifeBins: 2880,
			FineSpanBins: 1152, FoldRBins: 64, FinalityDepthK: 100,
		}},
		// Minimal valid geometry: dims at the low structural edge.
		{"min_valid", mrr.Geometry{
			Version: 0, ActivationBin: 0,
			WindowBins: 1, EpochBins: 8, HalfLifeBins: 1,
			FineSpanBins: 8, FoldRBins: 1, FinalityDepthK: 0,
		}},
	}
	out := make([]vector, 0, len(geoms))
	for _, e := range geoms {
		enc := e.g.Encode()
		h := e.g.Hash()
		out = append(out, vector{
			Name:    e.name,
			Geom:    e.g,
			Encoded: hex.EncodeToString(enc),
			Hash:    hex.EncodeToString(h[:]),
			Valid:   e.g.Validate() == nil,
		})
	}
	return out
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(kat1()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
