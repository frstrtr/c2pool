#!/usr/bin/env python3
"""
V37 MRR roundabout-buffer — SLOW REFERENCE implementation (golden-vector source).

Scope (M2 first slice): the scaled-frame per-miner decay accumulator and the OQ-2
epoch exact-rebuild, modelled at consensus precision so the incremental state can be
checked bit-for-bit against the closed-form window computation.

Normative anchors (c2pool-v37-mrr-roundabout-buffer.md):
  - decay is binary-exponential: lambda = 2^(-1/half_life)              (sec.4.2)
  - scaled frame: w_scaled(p) = w * lambda^(-(p-B)) = w * InvD[p-B]     (sec.4.2)
  - decayed value of a set at head H: (sum w_scaled) * lambda^(H-B)     (sec.4.2)
  - fixed point pinned at 62 FRACTIONAL BITS (errata E-1; supersedes the
    sec.8 body "Q*.64" wording, which predates the reference-impl pin)
  - every multiply TRUNCATES toward zero; no float in the consensus path (sec.8.3)
  - OQ-2: at each epoch boundary (p-B == E) the lane does an EXACT REBUILD from the
    durable L0 records, so acc re-converges bit-for-bit to the closed-form reference
    over the window contents (sec.4.2 / sec.8.4).
  - default geometry: W=8640, C0=4096, R=8, C1=568, half_life=W/4=2160, E=C0=4096 (OQ-5)

NOTE ON TABLE GENERATION: sec.8.2 mandates an integer-only generation procedure
"specified in the protocol doc". That exact procedure is not yet reproduced in the
corpus on this bridge, so the table here is built by ONE documented integer routine
(rationals truncated to Q62). It is self-consistent and sufficient for the OQ-2
equivalence property (which holds for ANY fixed table used identically everywhere).
The *canonical* table base is flagged below as a spec-consolidation (M3) follow-up.
"""

FRAC_BITS = 62                      # errata E-1
ONE = 1 << FRAC_BITS                # Q62 fixed-point 1.0

# ---- default BTC/LTC-class lane geometry (OQ-5) ----
HALF_LIFE = 2160
E = 4096                            # epoch length = C0

def _q62(numer, denom):
    """floor(numer/denom * 2^62) via exact integer arithmetic (truncating)."""
    return (numer << FRAC_BITS) // denom

def build_tables(half_life=HALF_LIFE, epoch=E):
    """
    InvD[j] = lambda^(-j) = 2^( j/half_life )   for j in [0, epoch]   (Q62)
    decay[d]= lambda^( d) = 2^(-d/half_life)     for d in [0, epoch]  (Q62)
    Built by iterated truncating multiply from a per-step base, matching the
    V36 'iterated truncating multiplication' lineage (sec.8.2).
    """
    # per-step inverse base  b_inv = 2^(1/half_life) in Q62, via integer nth-root of 2^(2^62*?)
    # Use exact rational pow through repeated squaring on a high-precision rational, then truncate.
    # base_inv = 2 ** (1/half_life); we compute floor(base_inv * 2^62) exactly using integer
    # binary search on x with x^half_life vs 2 * 2^(62*half_life).
    target = 2 * (ONE ** half_life)            # 2 * (2^62)^half_life
    lo, hi = ONE, ONE * 2
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** half_life < target:
            lo = mid + 1
        else:
            hi = mid
    base_inv = lo                               # ~ floor(2^(1/half_life) * 2^62)
    InvD = [ONE]
    for _ in range(1, epoch + 1):
        InvD.append((InvD[-1] * base_inv) >> FRAC_BITS)
    # decay[d] = floor(2^62 / InvD[d] * 2^62)?  -> decay = lambda^d = 1/InvD[d] in Q62
    decay = [ (ONE * ONE) // InvD[d] for d in range(epoch + 1) ]
    return InvD, decay, base_inv

def mul_q62(a, b):
    return (a * b) >> FRAC_BITS                 # truncating

# ---------------------------------------------------------------------------
class Lane:
    """Scaled-frame accumulator with OQ-2 epoch exact-rebuild."""
    def __init__(self, InvD, decay, epoch=E):
        self.InvD = InvD
        self.decay = decay
        self.epoch = epoch
        self.B = 0                  # epoch base position
        self.acc = {}               # miner -> sum w_scaled (Q62-weighted integer)
        self.l0 = []                # durable records this epoch: (pos, miner, w)
        self.H = -1                 # head position

    def push(self, miner, w):
        self.H += 1
        p = self.H
        if p - self.B == self.epoch:
            self._epoch_rebuild()
        j = p - self.B
        w_scaled = mul_q62(w << FRAC_BITS, self.InvD[j]) >> FRAC_BITS  # w * InvD[j], truncating
        # keep w_scaled as a plain integer in "w-units * Q62" -> store integer-scaled
        w_scaled = (w * self.InvD[j]) >> FRAC_BITS
        self.acc[miner] = self.acc.get(miner, 0) + w_scaled
        self.l0.append((p, miner, w))

    def _epoch_rebuild(self):
        """OQ-2: re-derive acc from durable L0 records into the NEW frame (B advances by E)."""
        self.B += self.epoch
        fresh = {}
        for (p, miner, w) in self.l0:
            if p < self.B:          # records older than the new base are evicted from this epoch's frame
                continue
            j = p - self.B
            fresh[miner] = fresh.get(miner, 0) + ((w * self.InvD[j]) >> FRAC_BITS)
        self.acc = fresh
        self.l0 = [r for r in self.l0 if r[0] >= self.B]

    def decayed_payout(self, miner):
        """decayed weight at head H = acc[m] * lambda^(H-B)  (truncating)."""
        d = self.H - self.B
        return (self.acc.get(miner, 0) * self.decay[d]) >> FRAC_BITS

    def closed_form(self, miner, window_start=None):
        """SLOW reference: sum over durable records w * lambda^(H-p), truncating per term."""
        tot = 0
        for (p, m, w) in self.l0:
            if m != miner:
                continue
            if window_start is not None and p < window_start:
                continue
            d = self.H - p
            tot += (w * self.decay[d]) >> FRAC_BITS
        return tot
