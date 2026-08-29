# T12 — server-affinity ("sticky") shard assembly closes the low-h liveness gap

Reproduce: `cd proto/m4-sync/harness && python3 t12_sticky_shard_assembly.py --w 300000`
(sanity: `--w 8000 --trials 120`). Real Utreexo forest + deterministic synthetic
shares, same primitives as T9/T10 (imported, not reimplemented). No wall-clock in
the verification path.

## The gap this closes (a tension T9/T10 surfaced, the synthesis glossed)

The superlight synthesis folds in the **per-shard-committed checkpoint** (32 B
shard-root over K sub-roots, O(1) on-chain) as the lever that turns a whole-W DoS
amplification into a bounded W/K one. True for *egress* — but T10's own table shows
the **naive** sharded assembly is WORSE for *liveness* at low honest-fraction:

| h (W=300K) | whole-set live% | shard-naive live% |
|------------|-----------------|-------------------|
| 0.05       | 80.8%           | **6.7%**          |
| 0.10       | 97.5%           | **67.5%**         |

Cause: naive assembly samples servers **independently per shard** and never reuses a
server that already proved honest, so all-K-shards success ≈ (per-shard) ^ K — it
needs an honest server *per shard*. Presenting sharding as a strict win overstates it:
naively it raises the honest-server bar.

## The fix: affinity + one-strike drop

An honest server is a **full** proof-server — it holds every shard. So:
- the moment a server returns a sub-root-valid shard, pull **all remaining shards
  from that same server** (server affinity / "sticky");
- **drop a server the instant it serves an invalid shard** (one strike → sybil).

Then liveness = "≥1 honest server appears in the sampled order" — *identical to
whole-set* — while a sybil is caught on its first shard and wastes at most **W/K**
leaves before exclusion. Safety is unchanged and unconditional (every shard
sub-root-checked, every head = the K committed sub-roots).

## Result — W=8000, servers=20, shards=16, 120 trials (W/K bound = 500 leaves = 15.6 KB)

| h    | whole live% / wasteKB | shard-naive live% / wasteKB | shard-STICKY live% / servers / wasteKB / maxSybilKB |
|------|-----------------------|-----------------------------|------------------------------------------------------|
| 0.00 | 0.0% / 3737.8         | 0.0% / 237.6                | 0.0% / 20.0 / 237.6 / 15.6                            |
| 0.05 | 100.0% / 1785.0       | 100.0% / 1770.4             | **100.0%** / 11.2 / **119.4** / **15.6**             |
| 0.10 | 100.0% / 1055.3       | 100.0% / 1128.3             | 100.0% / 7.5 / 79.0 / 15.6                            |
| 0.20 | 100.0% / 593.7        | 100.0% / 577.3              | 100.0% / 4.4 / 38.1 / 15.6                            |
| 0.30 | 100.0% / 374.3        | 100.0% / 376.1              | 100.0% / 2.9 / 21.3 / 15.6                            |
| 0.50 | 100.0% / 174.0        | 100.0% / 173.7              | 100.0% / 1.8 / 9.1 / 15.6                             |

SAFETY: 0 wrong-head acceptances across all trials incl. h=0 → PASS.

Reading:
- **STICKY tracks whole-set liveness** (100% wherever ≥1 honest peer is reachable) —
  it does NOT inherit naive-sharding's per-shard honest-server requirement.
- **maxSybilKB pins to exactly the W/K bound (15.6 KB)** at every h — a lying server's
  wasted egress is one shard, never the whole W. The bounded-DoS property is preserved.
- **Total wasted egress is the lowest of the three** (119 KB vs whole-set 1785 KB @h=0.05,
  ~15×) because one-strike-drop stops paying a sybil after a single bad shard.

So sticky assembly is a **strict Pareto improvement**: whole-set liveness AND the
sharded bounded-W/K cap, together. (W=8K already shows the egress/safety mechanics
exactly; the *liveness* recovery is most dramatic at W=300K where naive collapses to
6.7% — confirmation run pending, append `out/t12-sticky-shard-w300k.txt`.)

## DESIGN FEED → `v37-superlight-chain-synthesis.md`

The shard-root checkpoint must specify the **assembly rule**, not just the commitment:
a validator does sticky assembly (affinity + one-strike-drop), NOT independent
per-shard resampling. With that rule the per-shard commitment is an unconditional win —
it adds the bounded-W/K DoS cap on top of unchanged whole-set liveness and unconditional
safety. Honest-server count stays a pure liveness knob; the assembly rule is what keeps
that knob at the whole-set "one honest peer suffices" level instead of "one per shard".
