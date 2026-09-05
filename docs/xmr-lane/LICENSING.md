# LICENSING — XMR lane combined-work rationale

**One-line answer.** c2pool is **AGPL-3.0**. RandomX and Monero-core crypto are
**BSD-3-Clause** (permissive → combine freely). p2pool is **GPL-3.0-only**, and
its code is legally combinable into c2pool because **AGPLv3 §13** (mirrored by
**GPLv3 §13**) explicitly permits combining an AGPLv3 work with a GPLv3 work into
a single conveyable work. The whole distributable is conveyed as **AGPL-3.0**;
p2pool-derived files keep their GPLv3 license; BSD files keep their notice.

---

## 1. The AGPLv3 §13 mechanism (the load-bearing clause)

AGPLv3 §13, first paragraph ("Remote Network Interaction; Use with the GNU General
Public License"):

> Notwithstanding any other provision of this License, you have permission to link
> or combine any covered work with a work licensed under version 3 of the GNU
> General Public License into a single combined work, and to convey the resulting
> work. The terms of this License will continue to apply to the part which is the
> covered work, but the work with which it is combined will remain governed by
> version 3 of the GNU General Public License.

GPLv3 §13 is the symmetric grant on the other side:

> Notwithstanding any other provision of this License, you have permission to link
> or combine any covered work with a work licensed under version 3 of the GNU
> Affero General Public License into a single combined work, and to convey the
> resulting work. The terms of this License will continue to apply to the part
> which is the covered work, but the special requirements of the GNU Affero
> General Public License, section 13, concerning interaction through a network
> will apply to the combination as such.

**What this gives c2pool, precisely:**

1. **Permission to combine.** We may take GPLv3 p2pool code into the AGPLv3
   c2pool tree and convey the result. No separate permission from SChernykh is
   needed — the licenses grant it. (This is the normal, intended AGPL↔GPL bridge;
   it is *not* an incompatibility workaround.)
2. **Each part keeps its own license.** The p2pool-derived files remain
   **GPL-3.0-only**; the rest of c2pool remains **AGPL-3.0**. We therefore keep
   p2pool's GPLv3 header on every ported/adapted file (see `PROVENANCE.md` §0 rule
   1) — stripping it would be a license violation.
3. **The network clause reaches the whole combination.** Per GPLv3 §13's second
   sentence, AGPL §13's network-source-offer requirement "will apply to the
   combination as such." So operating a c2pool node that talks to users over a
   network triggers the obligation to offer Corresponding Source for the whole
   combined work — which c2pool, as an AGPL project, already does. The XMR lane
   adds no new obligation; it inherits the existing one.

**Net license of the distributable:** conveyed as **AGPL-3.0** (the strongest /
outermost terms), with GPL-3.0-only islands that are individually so-licensed and
BSD-3 islands that carry their notices.

## 2. Why BSD-3 (RandomX, Monero-core, epee) is trivial

BSD-3-Clause is permissive and imposes no copyleft reach-through. The only
obligations are: (clause 1) retain the copyright notice, condition list, and
disclaimer in source; (clause 2) reproduce them in binary distributions; (clause
3) no use of the holder's name to endorse. We satisfy all three by (a) keeping
each vendored file's header verbatim, (b) the aggregated `NOTICE`, and (c)
shipping the full texts under `third_party/licenses/`. BSD-3 code drops into an
AGPL work with no friction, and it does **not** relicense to AGPL — it stays BSD
under its own header, inside the AGPL whole.

*Keccak special case.* Monero's `keccak.c/.h` is the Saarinen baseline Keccak,
carrying an author line (`Markku-Juhani O. Saarinen`) rather than an embedded BSD
body; Monero ships it under the project BSD-3 umbrella. Saarinen's original is
public-domain-class. Either reading (public-domain or BSD-3) is AGPL-compatible;
we retain the Saarinen author line **and** treat the file under the Monero BSD-3
notice. No copyleft, no conflict.

## 3. Why the pool-model exclusion is also a licensing hygiene win

We deliberately do **not** port p2pool's sidechain / PPLNS / uncle code
(`PROVENANCE.md` §3.1). Beyond the design reason (v37 has its own RDWR /
work-receipts model), this keeps the GPL-3.0-only surface in c2pool as small as
possible — limited to genuine Monero-plumbing that has real reuse value and no
clean-room substitute. Smaller copyleft surface = fewer files whose GPLv3 header
must be tracked and whose relicensing consent would be needed for any future AGPL
version change of the combined work (see §4).

## 4. Version-compatibility caveats (recorded, not blocking)

- p2pool is **GPL-3.0-only** ("version 3", no "or later"). The AGPLv3 §13 bridge
  is specific to *version 3* of each license. If c2pool ever moves the combined
  work to a hypothetical AGPL-4, the GPL-3.0-only parts could **not** be carried
  along without SChernykh relicensing. Track this if an AGPL version bump is ever
  contemplated. (OQ-X6c.)
- If c2pool's own license is AGPL-3.0-**or-later**, the *fresh* c2pool files may
  use "or later"; the combined *conveyed* work is still bounded by the GPL-3.0-only
  islands to AGPL-3.0 terms for those islands. The fresh-file header template uses
  "or (at your option) any later version" — align it with the repo-root license if
  that differs (OQ-X6b).

## 5. Compliance checklist (what "done" looks like)

- [ ] Root `COPYING`/`LICENSE` = AGPL-3.0 (unchanged by the XMR lane).
- [ ] `third_party/licenses/` ships `RandomX.LICENSE`, `Monero.LICENSE`,
      `p2pool.LICENSE` (full GPLv3 text) — staged in `upstream-licenses/`.
- [ ] Root/`third_party` `NOTICE` present (staged here) and kept in sync with
      `xmr_provenance.hpp`.
- [ ] Every `vendor/**` (BSD) file: upstream header verbatim + provenance comment.
- [ ] Every p2pool-derived file under `src/impl/xmr/`: p2pool GPLv3 header verbatim
      + provenance comment marking exactly what was adapted and that the pool-model
      was excluded.
- [ ] Every fresh file: AGPL header, **attribution-clean** (no AI/Co-Authored lines).
- [ ] CI provenance gate (`xmr_provenance.hpp` static_asserts + a drift/grep check)
      green.
- [ ] Coinbase-derivation code fenced pre-CARROT per Monero `major_version`.

---

*Sources for the quoted clauses: GNU AGPLv3 (2007) §13 and GNU GPLv3 (2007) §13,
as published by the Free Software Foundation. The full GPLv3 text is shipped at
`third_party/licenses/p2pool.LICENSE`.*
