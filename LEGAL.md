# LEGAL.md — Legal Posture and Acceptable Use

**Status: operator-authored posture, for maintainer/counsel review. This is NOT
legal advice.** This document records the c2pool project's own declared position
and its community/contribution policy. It has no independent legal effect beyond
the licenses named below, it may be incomplete or imprecise, and it should be
reviewed by qualified counsel before being relied upon. Nothing here creates a
warranty, waiver, or contract.

---

## 1. Disclaimer of Warranty / Limitation of Liability (AS IS)

c2pool is free, open-source software distributed under the following terms:

- **c2pool daemon (this repository):** GNU Affero General Public License, version
  3 or later (**AGPL-3.0-or-later**). The full text is in [`LICENSE`](LICENSE) at
  the repository root. Network use triggers the AGPL's source-provision
  obligation (AGPLv3 §13).
- **c2pool-core-engine (extracted primitive layer):** **Apache-2.0**, maintained
  in the separate repository `github.com/frstrtr/c2pool-core-engine`.
- **Bundled `src/btclibs/` and third-party cryptography:** retain their original
  **MIT** (and, for vendored components, BSD-3-Clause / GPL-3.0) licenses, with
  notices preserved in-file. Third-party notices are catalogued in
  [`NOTICE`](NOTICE), and the XMR-lane combining analysis in
  [`docs/xmr-lane/LICENSING.md`](docs/xmr-lane/LICENSING.md).

Consistent with those licenses, the software is provided **"AS IS", WITHOUT
WARRANTY OF ANY KIND**, express or implied, including but not limited to the
implied warranties of merchantability, fitness for a particular purpose, and
non-infringement. See the "Disclaimer of Warranty" and "Limitation of Liability"
sections of the AGPL-3.0 (§§15–17) and the corresponding sections of Apache-2.0
(§§7–8) for the controlling terms.

To the maximum extent permitted by applicable law, the authors and copyright
holders are **not liable** for any claim, damages, or other liability — including
damage caused by **third parties** who obtain, modify, or deploy the software —
whether in an action of contract, tort, or otherwise, arising from, out of, or in
connection with the software or its use. The license text controls; this summary
does not modify it.

---

## 2. Dual-Use & Academic Research Notice

c2pool is a **decentralized-mining / distributed-consensus research protocol**.
Its purpose is consensus research, the defense of mining decentralization against
centralized-pool capture, and the **voluntary** pooling of compute by consenting
operators.

Like most systems software, it is **dual-use**: the same primitives that serve
legitimate research and voluntary pooling could, in principle, be misused. The
project is developed, published, and maintained for legitimate purposes, and the
following artifacts in this repository are evidence of that research intent:

- **TLA+ formal specifications and model-checking results:**
  [`proto/tla/Settlement.tla`](proto/tla/Settlement.tla),
  [`proto/tla/Lanes.tla`](proto/tla/Lanes.tla), and
  [`proto/tla/MODELCHECK-RESULTS.md`](proto/tla/MODELCHECK-RESULTS.md).
- **The V37 "Purple Paper"** protocol write-up:
  [`src/sharechain/v37/PURPLE-PAPER.md`](src/sharechain/v37/PURPLE-PAPER.md).
- **Merged-mining and settlement specifications**, e.g.
  [`src/impl/btc/coin/merged_spec.hpp`](src/impl/btc/coin/merged_spec.hpp), and
  the falsifier/refimpl harnesses under [`proto/`](proto/).

These are published openly precisely because the project's aims are academic,
transparent, and defensive, not covert.

---

## 3. Explicit Warning on Unauthorized Deployment

**Deploying c2pool on, or mining with, computing hardware WITHOUT the informed
consent of that hardware's lawful owner or operator is illegal.** Such conduct
may constitute a serious criminal offense, including but not limited to:

- **United States** — the Computer Fraud and Abuse Act, **18 U.S.C. § 1030**
  (unauthorized access to, and unauthorized use of, protected computers).
- **Russian Federation** — Уголовный кодекс РФ, **ст. 272** (неправомерный доступ
  к компьютерной информации) and **ст. 273** (создание, использование и
  распространение вредоносных компьютерных программ).
- **Equivalents in other jurisdictions** (e.g. computer-misuse and unauthorized-
  access statutes worldwide).

The authors **categorically condemn and prohibit** any unauthorized, covert, or
non-consensual deployment of this software — including "cryptojacking" and any
installation that hides itself from, or lacks the consent of, the system's owner.
Running c2pool is legitimate **only** on hardware you own or are expressly
authorized to use for this purpose.

---

## 4. Acceptable Use Policy (AUP)

To keep this project on the correct side of the line drawn in Section 3, the
maintainers apply the following contribution policy:

The project will **not accept** contributions whose purpose or effect is to make
deployment covert or forensically evasive. Rejected on sight are pull requests
that add or facilitate:

- stealth or hiding of the running process from the system owner;
- process-name masking, disguise, or impersonation of unrelated software;
- suppression, tampering, or deletion of logs, journals, or audit trails;
- evasion or disabling of endpoint protection (EDR), anti-virus, or other
  security tooling; or
- any other anti-forensics / detection-evasion capability.

Such changes are treated as violations of this AUP and are declined regardless of
stated rationale.

**This AUP is a community and contribution policy, not a license restriction.**
The project deliberately does **not** add any field-of-use or "ethical-use"
clause to its licenses: such clauses would break the software's OSI-approved /
FSF-free open-source status, and field-of-use restrictions of that kind are
widely regarded as unenforceable in practice. The open-source licenses in
Section 1 remain unmodified. This AUP governs what the maintainers will merge and
how the community operates — nothing more.

---

## 5. Voluntary Developer Donation (dev-fee)

c2pool includes a small, built-in **author/developer donation** ("dev-fee"). The
project's position, and the verifiable state of the source, is:

- **It is a voluntary donation, not a mandatory or protocol-enforced fee.** It is
  expressed as an ordinary committed payout split, never as a consensus rule that
  punishes, rejects, or penalizes work that omits it.
- **The default is small: 0.1%.** This is defined as a single, plain, editable
  source constant — `constexpr double kAuthorFeeDefaultPct = 0.1;` in
  [`src/core/author_fee.hpp`](src/core/author_fee.hpp) (the single source of
  truth shared by every coin lane).
- **It is trivially removable or adjustable.** An operator can change or zero it
  by any of:
  - the command-line flag **`--give-author PCT`** (alias `--dev-donation`), where
    `PCT = 0` removes the donation entirely (a value of `0` is explicitly
    supported and produces no donation output);
  - the config-file key **`money.give_author_pct`**; or
  - editing the plain source constant above and recompiling.
- **It is not hardcoded behind obfuscation, anti-debug, or tamper protection, and
  it is not protocol-punished.** The value is stored and computed in the clear.

The maintainers commit that the dev-fee will **remain** voluntary, small by
default, transparent, and trivially removable, and will **never** be hardcoded
without an override, obfuscated, anti-debug-protected, or enforced by consensus.

---

*This document states the project's declared posture and its Acceptable Use
Policy. It is operator-authored, offered for maintainer and counsel review, and
is **not legal advice**. Where this summary and the actual license texts differ,
the license texts control.*
