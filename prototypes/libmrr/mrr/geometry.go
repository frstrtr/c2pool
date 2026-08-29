// Package mrr — V37 MRR Roundabout engine, adaptive-dimensioning core.
//
// Phase 0 (Geometry extraction): the versioned dimension record and its
// canonical serialization/commitment. This replaces the six loose init
// numbers with a single hash-committed record that shares attest to and
// that every geometry-dependent quantity is a query-side derivation of.
//
// Determinism is absolute: encode/decode/hash/validate use only fixed-width
// integer serialization and integer comparisons. No floating point, no
// wall-clock, no locale, no map iteration anywhere in this file. The 36-byte
// canonical LE encoding is the consensus-visible form; SHA-256 over it is the
// value shares commit to.
//
// Scope: static geometry only. retarget()/EMA/observables land in Phase 2.
package mrr

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// EncodedSize is the exact byte length of a canonical Geometry encoding:
// version(4) + activation_bin(8) + 6*uint32(24) = 36 bytes.
const EncodedSize = 36

// Digest is the 32-byte SHA-256 commitment over a Geometry's canonical encoding.
type Digest [32]byte

// Geometry is the versioned record of the six MRR dimensions plus the
// anchoring metadata that makes the epoch/window grid derivable by any node
// from this record alone. It is a plain value type (trivially copyable).
//
// Field order here IS the canonical byte order (see Encode). Do not reorder.
type Geometry struct {
	Version       uint32 // monotone geometry-epoch counter, genesis = 0
	ActivationBin uint64 // absolute bin index at which this geometry became active

	WindowBins     uint32 // W — scoring (PPLNS-style) window length
	EpochBins      uint32 // E — bins per epoch; epoch-rebuild cadence
	HalfLifeBins   uint32 // exponential decay half-life for share scoring
	FineSpanBins   uint32 // head region kept at fine (per-bin) resolution
	FoldRBins      uint32 // fold ratio: one coarse leaf = FoldRBins fine bins; power of two
	FinalityDepthK uint32 // depth at which mode-3 (sealed) finality applies
}

// --- Phase-0 frozen structural bounds -------------------------------------
//
// These lock the STRUCTURE of validate(). The numeric magnitudes below are
// Phase-0 frozen defaults; the tight per-dimension min/max come out of the
// Phase-2 offline simulator (SIM parameter-rationale memo) and the §3.4
// bounds table, and will be re-pinned there before any live wiring. The
// invariant SHAPE (power-of-two fold, fold-boundary alignment, fine-covers-k,
// epoch-covers-fine, window ceiling) is frozen now and does not change.
const (
	FoldRMin     = 1        // one coarse leaf = 1 fine bin (no coarsening)
	FoldRMax     = 1 << 16  // 65536; upper fold ratio (power of two)
	FineMargin   = 8        // fine region must cover k plus this margin
	WindowAbsMax = 1 << 26  // 67,108,864 bins — absolute window ceiling
)

var (
	ErrFoldNotPow2      = errors.New("mrr: fold_r_bins is not a power of two")
	ErrFoldOutOfRange   = errors.New("mrr: fold_r_bins outside [FoldRMin, FoldRMax]")
	ErrFoldZero         = errors.New("mrr: fold_r_bins is zero")
	ErrFineNotMultiple  = errors.New("mrr: fine_span_bins not a multiple of fold_r_bins")
	ErrEpochNotMultiple = errors.New("mrr: epoch_bins not a multiple of fold_r_bins")
	ErrWindowNotMultiple = errors.New("mrr: window_bins not a multiple of fold_r_bins")
	ErrFineCoversK      = errors.New("mrr: fine_span_bins < finality_depth_k + FineMargin")
	ErrEpochCoversFine  = errors.New("mrr: epoch_bins < fine_span_bins")
	ErrWindowTooLarge   = errors.New("mrr: window_bins exceeds WindowAbsMax")
	ErrZeroDimension    = errors.New("mrr: a required dimension is zero")
)

// Encode writes the canonical 36-byte little-endian fixed-width encoding.
// No varints, no padding, no ambiguity. The returned slice is exactly
// EncodedSize bytes. This byte layout is consensus-frozen.
func (g Geometry) Encode() []byte {
	out := make([]byte, EncodedSize)
	binary.LittleEndian.PutUint32(out[0:4], g.Version)
	binary.LittleEndian.PutUint64(out[4:12], g.ActivationBin)
	binary.LittleEndian.PutUint32(out[12:16], g.WindowBins)
	binary.LittleEndian.PutUint32(out[16:20], g.EpochBins)
	binary.LittleEndian.PutUint32(out[20:24], g.HalfLifeBins)
	binary.LittleEndian.PutUint32(out[24:28], g.FineSpanBins)
	binary.LittleEndian.PutUint32(out[28:32], g.FoldRBins)
	binary.LittleEndian.PutUint32(out[32:36], g.FinalityDepthK)
	return out
}

// Decode parses a canonical 36-byte encoding. It is total over any 36-byte
// input (the inverse of Encode); it does NOT validate invariants — call
// Validate for that.
func Decode(in []byte) (Geometry, error) {
	if len(in) != EncodedSize {
		return Geometry{}, fmt.Errorf("mrr: Decode expects %d bytes, got %d", EncodedSize, len(in))
	}
	var g Geometry
	g.Version = binary.LittleEndian.Uint32(in[0:4])
	g.ActivationBin = binary.LittleEndian.Uint64(in[4:12])
	g.WindowBins = binary.LittleEndian.Uint32(in[12:16])
	g.EpochBins = binary.LittleEndian.Uint32(in[16:20])
	g.HalfLifeBins = binary.LittleEndian.Uint32(in[20:24])
	g.FineSpanBins = binary.LittleEndian.Uint32(in[24:28])
	g.FoldRBins = binary.LittleEndian.Uint32(in[28:32])
	g.FinalityDepthK = binary.LittleEndian.Uint32(in[32:36])
	return g, nil
}

// Hash returns SHA-256 over the canonical encoding. This is what shares commit
// to and what a divergence (bug, non-determinism, tamper) reveals as an
// immediate hard share-rejection at the first share after activation.
func (g Geometry) Hash() Digest {
	return sha256.Sum256(g.Encode())
}

// Validate enforces the §1.1 structural invariants. A Geometry that fails
// Validate must never be activated. retarget() (Phase 2) is required to be
// clamp-complete so that every geometry it emits passes Validate; a violation
// there is a programming error.
func (g Geometry) Validate() error {
	// fold_r_bins: nonzero power of two within range.
	if g.FoldRBins == 0 {
		return ErrFoldZero
	}
	if bits.OnesCount32(g.FoldRBins) != 1 {
		return ErrFoldNotPow2
	}
	if g.FoldRBins < FoldRMin || g.FoldRBins > FoldRMax {
		return ErrFoldOutOfRange
	}
	// No geometry-relevant dimension may be zero (a zero window/epoch/fine
	// span is a degenerate grid).
	if g.WindowBins == 0 || g.EpochBins == 0 || g.FineSpanBins == 0 || g.HalfLifeBins == 0 {
		return ErrZeroDimension
	}
	// Every geometry boundary lands on a fold boundary, so re-binning at
	// activation never splits a committed coarse leaf.
	if g.FineSpanBins%g.FoldRBins != 0 {
		return ErrFineNotMultiple
	}
	if g.EpochBins%g.FoldRBins != 0 {
		return ErrEpochNotMultiple
	}
	if g.WindowBins%g.FoldRBins != 0 {
		return ErrWindowNotMultiple
	}
	// The fine region always covers the non-final head; mode-0/1 state never
	// lives in coarse leaves. Use uint64 to avoid u32 overflow on the add.
	if uint64(g.FineSpanBins) < uint64(g.FinalityDepthK)+FineMargin {
		return ErrFineCoversK
	}
	// An epoch seal always pushes the previous epoch entirely out of the fine
	// region.
	if g.EpochBins < g.FineSpanBins {
		return ErrEpochCoversFine
	}
	// Absolute window ceiling.
	if g.WindowBins > WindowAbsMax {
		return ErrWindowTooLarge
	}
	return nil
}
