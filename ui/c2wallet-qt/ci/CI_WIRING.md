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
