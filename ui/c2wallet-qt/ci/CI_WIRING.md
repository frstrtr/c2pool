# CI wiring for the network-incapable link-guard

The M0 phase adds a CI job, **`c2wallet-signer-guard`** ("c2wallet-qt
network-incapable link-guard"), to the repo's existing
`.github/workflows/build.yml`. It builds only the `c2wallet-qt-signer` target
(Qt6 Core/Gui/Widgets) and runs [`check_no_network.sh`](check_no_network.sh)
over the produced binary, so the network-incapable guarantee is enforced on
every PR that touches this tree (the `qt` path filter already covers `ui/**`).

## Why it is delivered as a patch here

The change to `build.yml` is **prepared and validated** but is applied
separately from the code commit because pushing a file under
`.github/workflows/` requires the `workflow` OAuth scope, which the pushing
token did not carry. The exact diff lives beside this note as
[`ci-wiring.build-yml.patch`](ci-wiring.build-yml.patch); it was generated from
the same commit that built and ran green on the build host.

## Applying it

From the repo root, with a token/login that has the `workflow` scope:

```sh
git apply ui/c2wallet-qt/ci/ci-wiring.build-yml.patch
git add .github/workflows/build.yml
git commit -m "c2wallet-qt M0: wire the network-incapable link-guard into CI"
git push
```

The patch inserts the job immediately after the existing `qt-webengine` job.
`python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build.yml'))"`
confirms the result parses.

## The job (for reference)

- Gated on `needs.changes.outputs.qt` (i.e. any `ui/**` change) or a non-PR event.
- Installs `qt6-base-dev` only — no webengine, no webchannel.
- `cmake -S ui/c2wallet-qt -B build-c2wallet -DC2WALLET_QT_BUILD_TESTS=ON`
- `cmake --build build-c2wallet --target c2wallet-qt-signer`
- `./ui/c2wallet-qt/ci/check_no_network.sh build-c2wallet/c2wallet-qt-signer`

Until the patch is applied, the guard still runs locally via
`ctest` (the `no_network_link_guard` test registered by the CMake
`C2WALLET_QT_BUILD_TESTS` option).

## The companion and the headless scheduler (not yet in CI)

`cmake -S ui/c2wallet-qt -B build-c2wallet -DC2WALLET_QT_BUILD_TESTS=ON` also
builds the online companion (needs `qt6-base-dev` and `nlohmann-json3-dev`):
the key-free `c2wallet-companion` library, the Qt Network transport library
`c2wallet-companion-qtnet`, and the headless inject scheduler
`c2wallet-qt-schedd`. `ctest --test-dir build-c2wallet` then runs, besides the
signer's `no_network_link_guard`:

- `companion_kats`, `companion_sched_kats` (Qt-free core, runner merge and
  every daemon subcommand against a fake node) and `companion_key_free_guard`
  (`check_key_free.sh` over `libc2wallet-companion.a`);
- `schedd_qt_kats` (`QtNodeApi` against a local `QTcpServer` fake node; the
  daemon binary end to end through `QProcess`; loopback only);
- `schedd_key_free_guard` (`check_key_free.sh` over the linked daemon) and
  `schedd_no_gui_link_guard` ([`check_no_gui_link.sh`](check_no_gui_link.sh):
  the daemon's NEEDED entries carry Qt6Core + Qt6Network and no Gui, Widgets,
  GL, X11 or Wayland library).

The key-free DASH plan library `c2wallet-dash-plan` (address decode, UTXO
intake, the sweep planner, the manifest, the gobject hash; split out of
`c2wallet-dash-common` so the companion can plan without key code) adds:

- `dash_plan_kats` (`c2wallet-dash-plan-test`, linked against the plan library
  only);
- `dash_plan_key_free_guard` and `dash_plan_test_key_free_guard`
  (`check_key_free.sh` over `libc2wallet-dash-plan.a` and over that test
  binary);
- `dash_key_scan_probe_key_free_guard_negative_control`: the same guard over
  `c2wallet-dash-key-scan-probe`, a binary that links only the funding-key
  scan (`KeyScan.cpp`, BIP32 derivation) of the key layer. It must FAIL
  (`WILL_FAIL`): it proves the guard sees the key code the split keeps out of
  the plan library (the token list before the split passed it).

The companion's Scan & Plan core (`src/companion/scan/`, inside
`c2wallet-companion`, which now also links `c2wallet-dash-plan`) adds:

- `companion_scan_kats` (K1-K16: scripted fake dashd and fake c2pool node over
  the real getaddressutxos fixture, a replayed real dashd scantxoutset session,
  synthesised scantxoutset / `/api/utxo/scan` shapes);
- `companion_scan_key_free_guard` (`check_key_free.sh` over the LINKED scan
  test binary: the companion objects plus every plan-library and hdkeys object
  the scan code pulls in);
- `companion_scan_export_parity` (the scan's `<name>.utxos.json` is
  byte-identical to `tools/export_utxos.py` against `mock_dash_cli.py`);
- `scan_signer_roundtrip` (full `ui/c2wallet-qt` build only: the export and
  sidecar through the signer's own `DashInjectModel` import, screen, plan, key
  and sign; a test binary that links the key libraries, so no key-free guard
  runs over it).

Slice S-C (the scan / plan / preflight / watch commands, the dashd Qt
transport, the GUI tab) adds:

- `companion_scan_cli_kats` (C1-C9 through `sched::cli::run` with scripted
  fakes) and `companion_scan_cli_key_free_guard` over that binary;
- `scan_qt_kats` (`QtRpcApi` and `QtNodeApi` against local fake servers:
  Basic auth from the 0600 file, 401, `scantxoutset "abort"` on cancel, a
  dropped node scan; the daemon's `scan` end to end);
- `companion_gui_key_free_guard` (`check_key_free.sh` over the linked
  `c2wallet-qt-companion`, which now carries the Scan & Plan tab).
  `schedd_key_free_guard` now also covers the scan code the daemon links.

The same targets build standalone from `ui/c2wallet-qt/src/companion` when Qt6
Core + Network are installed. A CI job for them would extend the patch above
with `nlohmann-json3-dev` and run the full `ctest`; it is not part of the
prepared `build.yml` patch yet.
