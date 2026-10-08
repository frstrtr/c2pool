#!/usr/bin/env python3
"""Generate rule_l_sim_vectors.hpp: Rule L cross-check vectors computed with the
surplus-sim-L reference simulator's OWN primitives (sim_l.rule_L_P1 with its
brute-force check=True oracle, sim_l.largest_remainder), composed exactly as
sim_l.run() composes them for rule "L" with the p2x variant:

  hs = max(dust, ceil(R / (M*s)));  E = eo >= hs in (fe ASC, key ASC)
  P1 = sim_l.rule_L_P1(E, eo, s, B, check=True)
  P2 = if B - paid > 0: top up emitted keys by sim_l.largest_remainder(
         min(left, sum cb), cb, keys), cb = credit_b of each emitted key
  P2' (only when genesis=1, and only once slots remain, i.e. E exhausted):
       non-emitted keys with credit_b > 0 in (credit_b DESC, key ASC),
       amt = min(credit_b, left), skipped when amt < dust
  donation = D_min + left

The simulator has no sub-dust fold and no reserve, so every generated vector
is fold-free (the last P1 take is >= dust; draws that would fold are re-drawn)
and uses reserve_ppm = 0. The fold and the reserve are pinned by hand-computed
KATs in v37_payout_rule_l_kat.cpp instead.

Usage (vm905):  ~/surplus-sim-L/venv/bin/python gen_rule_l_sim_vectors.py \
                    ~/surplus-sim-L > rule_l_sim_vectors.hpp
"""
import random
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")
import sim_l  # noqa: E402


def rule_l_sim(R, D_min, s, M, dust, rows, genesis):
    """rows: list of (key, eo, fe, credit_b). Returns (outputs, donation) or None
    when the draw would need the sub-dust fold (not modelled by the sim)."""
    B = R - D_min
    hs = max(dust, -(-R // (M * s)))
    E = sorted([r for r in rows if r[1] >= hs], key=lambda r: (r[2], r[0]))
    El = [r[0] for r in E]
    vals = [r[1] for r in E]
    emitted, paid, T, skipped, s_left, exhausted = sim_l.rule_L_P1(El, vals, s, B, check=True)
    if emitted and emitted[-1][1] < dust:
        return None
    outputs = {k: t for k, t in emitted}
    order = [k for k, _ in emitted]
    left = B - paid
    credit = {r[0]: r[3] for r in rows}
    if left > 0 and emitted:
        ks = [k for k, _ in emitted]
        cb = [credit[k] for k in ks]
        X = min(left, sum(cb))
        shares = sim_l.largest_remainder(X, cb, ks)
        for k, sh, cbk in zip(ks, shares, cb):
            assert sh <= cbk
            outputs[k] += sh
            left -= sh
    if genesis and left > 0 and s_left > 0:
        assert exhausted
        em = set(outputs)
        cand = sorted([r for r in rows if r[3] > 0], key=lambda r: (-r[3], r[0]))
        for r in cand:
            if s_left == 0 or left == 0:
                break
            if r[0] in em:
                continue
            amt = min(r[3], left)
            if amt < dust:
                continue
            outputs[r[0]] = amt
            order.append(r[0])
            left -= amt
            s_left -= 1
    donation = D_min + left
    assert sum(outputs.values()) + donation == R
    return [(k, outputs[k]) for k in order], donation, len(skipped)


def split(B, weights, keys):
    return sim_l.largest_remainder(B, weights, keys)


def main():
    rnd = random.Random(20260923)
    vecs = []

    def add(name, R, D_min, s, M, dust, rows, genesis):
        r = rule_l_sim(R, D_min, s, M, dust, rows, genesis)
        if r is None:
            return False
        vecs.append((name, R, D_min, s, M, dust, genesis, rows, r[0], r[1], r[2]))
        return True

    # (1) small random instances (the P1 skip path is common here)
    i = 0
    while i < 120:
        n = rnd.randint(1, 24)
        s = rnd.randint(1, 12)
        R = rnd.randint(200, 20000)
        D_min = rnd.randint(1, 20)
        M = rnd.choice([1, 2, 5, 50])
        dust = rnd.choice([1, 5, 20, 50])
        keys = rnd.sample(range(1, 10 ** 6), n)
        rows = []
        cw = [rnd.randint(0, 9) for _ in range(n)]
        cred = split(R - D_min, cw, keys) if sum(cw) and rnd.random() < 0.8 else [0] * n
        for k, c in zip(keys, cred):
            eo = rnd.choice([0, rnd.randint(1, 60), rnd.randint(1, 3000), rnd.randint(1, 12000)])
            rows.append((k, eo, rnd.randint(0, 12), c))
        if add(f"small{i}", R, D_min, s, M, dust, rows, rnd.random() < 0.3):
            i += 1

    # (2) realistic BTC / DASH scale: class slot counts from surplus-sim-L
    #     (s = (class_bytes - 62) // S_max), heavy-tailed owed, PPLNS credit
    for coin, R, dust, S_max in (("BTC", 320_000_000, 330, 43), ("DASH", 40_000_000, 546, 34)):
        for cls in ("750", "2250", "6500"):
            s = (int(cls) - sim_l.FIXED_OVERHEAD) // S_max
            done = 0
            while done < 4:
                n = rnd.choice([60, 200, 600])
                keys = rnd.sample(range(1, 10 ** 9), n)
                hw = [int(1e6 * (rnd.paretovariate(1.2))) for _ in range(n)]
                cred = split(R - 1, hw, keys)
                rows = []
                hsum = sum(hw)
                for k, h, c in zip(keys, hw, cred):
                    eo = 0 if rnd.random() < 0.2 else int(R * rnd.paretovariate(1.3) * h / hsum * rnd.choice([0.2, 1, 4]))
                    rows.append((k, eo, rnd.randint(0, 3000), c))
                if add(f"{coin}_c{cls}_{done}", R, 1, s, 50, dust, rows, done == 3):
                    done += 1

    print("#pragma once")
    print("// GENERATED by gen_rule_l_sim_vectors.py from surplus-sim-L sim_l.py")
    print("// primitives (rule_L_P1 check=True + largest_remainder). Do not edit.")
    print("#include <cstdint>")
    print("#include <vector>")
    print("namespace rule_l_simvec {")
    print("struct Row { std::uint64_t key, eo, fe, credit_b; };")
    print("struct Out { std::uint64_t key, amount; };")
    print("struct Vec { const char* name; std::uint64_t R, D_min, s, M, dust; bool genesis;")
    print("             std::vector<Row> rows; std::vector<Out> outs; std::uint64_t donation, skips; };")
    print("inline const std::vector<Vec>& vectors() {")
    print("  static const std::vector<Vec> v = {")
    for (name, R, D_min, s, M, dust, gen, rows, outs, don, sk) in vecs:
        rs = ",".join(f"{{{k}u,{eo}u,{fe}u,{c}u}}" for k, eo, fe, c in rows)
        os_ = ",".join(f"{{{k}u,{a}u}}" for k, a in outs)
        print(f'    {{"{name}",{R}u,{D_min}u,{s}u,{M}u,{dust}u,{"true" if gen else "false"},{{{rs}}},{{{os_}}},{don}u,{sk}u}},')
    print("  };")
    print("  return v;")
    print("}")
    print("}  // namespace rule_l_simvec")
    sys.stderr.write(f"{len(vecs)} vectors, {sum(v[10] for v in vecs)} P1 skips, "
                     f"{sum(1 for v in vecs if v[6])} genesis\n")


if __name__ == "__main__":
    main()
