# RandomX MSR-boost measurement (XMR lane) — method & result

**Status:** measured 2026-09-22 on a Zen 3 host. Result: **no boost observed above noise on this machine, in a degraded regime** — NOT a conclusion that the MSR mod is useless. The question stays open for a dedicated rig.

## What the MSR mod is
RandomX miners (xmrig, and our built-in CPU miner) can tune a few Model-Specific Registers on
Ryzen/Intel (disable HW prefetchers etc.) for a documented ~5–15 % hashrate gain. Writing MSRs
needs root **and** an un-locked-down kernel: Secure Boot → kernel lockdown `[integrity]` refuses
`/dev/cpu/*/msr` writes even for root; a KVM guest does not expose the Intel MSR (`0x1a4`) at all,
so **build/VM rigs cannot serve this track by architecture**. Measure only on bare metal with
Secure Boot off.

## Result (AMD Ryzen 7 5800H, bare metal, Secure Boot off, threads=16, hugepages=1280×2 MiB)
Gate-proven A/B, 2 rounds, each arm's MSR state verified by mid-run `rdmsr` (off must read baseline,
on must read the `ryzen_19h` tuned values) — all four arms passed the gate:

| arm | MSR | 60 s avg H/s |
|-----|-----|--------------|
| A1  | off | 3588.7 |
| A2  | off | 3573.3 |
| B1  | on  | 3571.0 |
| B2  | on  | 3604.4 |

- off avg **3581.0 H/s**, on avg **3587.7 H/s** → delta **+6.7 H/s (+0.19 %)**.
- within-condition spread **±15–33 H/s** ≫ the +6.7 H/s delta → the difference is **not
  distinguishable from zero**.

**Honest framing (do not shorten to "MSR gives nothing"):** the `ryzen_19h` MSR mod *applies
cleanly* on our Zen 3 (`msr … set successfully` + tuned mid-`rdmsr` every "on" arm), but produced
**no measurable boost above noise on this host**, where the absolute ~3.58 kH/s is only ~60–70 % of
the ~5–6 kH/s nominal for a 5800H (thermal/power-limited laptop) **and** a resident `ollama` shared
the CPU. A dedicated, idle, desktop-class rig may show the documented gain — that was not tested
here.

## Method — the four things that go wrong (learn from them before re-measuring)
1. **xmrig block-buffers stdout to a plain file** → 0-byte logs. Run it under a pty:
   `script -qec "sudo xmrig …" arm.log` so the periodic `miner speed …` lines flush live.
2. **`--no-rdmsr` does NOT disable the MSR write** — it only disables the read-back; the mod still
   applies. The only reliable "off" is a config with `{"randomx":{"wrmsr":false}}`.
3. **A CLI `--randomx-mode=fast` clobbers the whole `randomx` config block**, resetting
   `wrmsr` back to its default (apply). Put `mode:"fast"` in the config and pass **no**
   `--randomx-mode` on the command line.
4. **The offline `--bench` hangs at the end** on the api2.xmrig.com verification and never flushes.
   Don't wait for it — read the 60 s speed average, then kill the process.

Plus: make the mid-run `rdmsr` a **hard per-arm gate** (off≠baseline or on==baseline ⇒ cancel the
arm, record nothing) so a mis-assembled command line can't slip a false-negative through. Keep the
hugepage config and the baseline MSR values logged in the run header for reproducibility. Always
revert MSRs to baseline and verify the revert at the end; never stop a resident model to free CPU.
