package mrr

// This file introduces the Phase-0 data types that pair with Geometry: the
// retarget parameter set and the per-epoch observable record. In Phase 0 they
// are declared and threaded (replacing loose init numbers) but carry NO
// behavior — retarget(), the EMA, and observable extraction are Phase 2. They
// live here now so the engine constructor signature (genesis Geometry +
// RetargetParams) is stable from the start.

// Bounds is an inclusive absolute [Min, Max] band for one geometry dimension.
type Bounds struct {
	Min uint32
	Max uint32
}

// DimIndex names the six dimensions in the order the bounds table is indexed.
type DimIndex int

const (
	DimWindow DimIndex = iota
	DimEpoch
	DimHalfLife
	DimFineSpan
	DimFoldR
	DimFinalityK
	NumDims
)

// RetargetParams is the frozen configuration of the retarget process itself.
// It is fixed at genesis and committed alongside the genesis geometry; it is
// NOT retargetable (no meta-adaptivity in V37). Concrete magnitudes are
// Phase-2 simulator outputs; Phase 0 only fixes the shape.
type RetargetParams struct {
	// Targets
	TargetSharesPerWindow uint32
	TargetSharesPerEpoch  uint32
	LeafBudgetMin         uint32 // total-leaf band -> fold_r
	LeafBudgetMax         uint32

	// Smoothing / hysteresis
	EMAShift      uint32 // smoothed = old + (raw - old) >> EMAShift
	DeadbandShift uint32 // skip if |delta| < current >> DeadbandShift
	StepClampNum  uint32 // e.g. 4/3 max step per retarget
	StepClampDen  uint32
	CooldownEpochs uint32 // min epochs between geometry changes
	KDecreaseLimit uint32 // finality k may fall by at most this per retarget

	// Absolute per-dimension bounds, indexed by DimIndex.
	DimBounds [NumDims]Bounds
}

// EpochObservables are the consensus-derived integer inputs to retarget, one
// record per sealed epoch. Extraction (Phase 2) is deterministic by
// construction; the record is committed in the epoch-seal leaf so replay ≡ live.
type EpochObservables struct {
	EpochIndex      uint64
	ShareCount      uint64
	WorkSum         uint64
	StaleCount      uint64
	MaxGapBins      uint64 // longest run of empty bins
	SumIntervalBins uint64 // sum of inter-share gaps, bin-quantized
	SumIntervalSq   uint64 // sum of squared gaps
	MaxObservedReorg uint32 // deepest head rollback this epoch, in bins
}
