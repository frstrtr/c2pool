# DASH embedded daemonless coinbase: DIP4 CbTx special-transaction byte-parity with Dash Core (dated proof)

## Summary

The c2pool-dash embedded (daemonless) block-template assembler produces a DIP4 coinbase
special transaction (CbTx) whose consensus-bearing fields are byte-identical to those
produced by Dash Core (dashd). The result is reproducible from a named commit and a named
test target, and the same assertions run in continuous integration. This covers the CbTx
leg of deliverable D2. The superblock-coinbase leg is reported separately below with its
current factual status.

## 1. CbTx byte-parity (verified)

### Scope

The DIP4 coinbase special transaction carries the following consensus fields, all checked:

- version (special-transaction type and version)
- merkleRootMNList (the deterministic masternode-list root)
- merkleRootQuorums (the active quorum-commitment root)
- best ChainLock reference (bestCLHeightDiff and bestCLSig)
- creditPoolBalance (the asset-lock credit-pool accrual)

### Method

The embedded assembler builds the CbTx from its own derived state: the masternode list
folded from the P2P Simplified Masternode List and the node's own PoW-validated header
chain, the quorum set obtained via getqrinfo, and the credit-pool accrual computed from
block history. The assembled bytes and the per-field decoded values are compared against
real Dash Core output captured in the test fixtures. A wrong byte in any covered field
fails the corresponding test.

### Result

Eight tests pass, zero fail, across two suites.

DashEmbeddedCbtxByteParity:
- RealDashdCbTxRoundTripsByteIdentical
- RealDashdCbTxFieldsDecodeAsExpected
- AssemblyReproducesDashdNonRootFields
- CreditPoolAccrualMatchesRealDashd

DashMnlistdiffRootParity:
- MerkleRootMNListFromWireMatchesDashd
- MerkleRootQuorumsFromWireMatchesDashd
- QuorumSetAndLeavesAreByteExactFromWire
- DiffCbTxCarriesSeedForItsOwnBlock

### Reproduction

- Repository: github.com/frstrtr/c2pool
- Commit: d7b4aed33 (master)
- Build: cmake --build build --target test_dash_embedded_gbt
- Run: DASH_FIXTURE_DIR=<repo>/test/fixtures ./build/test/test_dash_embedded_gbt --gtest_filter='DashEmbeddedCbtxByteParity.*:DashMnlistdiffRootParity.*'
- Expected: 8 passed, 0 failed.

The target test_dash_embedded_gbt is in the CI "Build tests" set, so these assertions also
run in continuous integration rather than only on a developer machine.

Recorded run date: 2026-09-10.

## 2. Superblock coinbase (pending an external precondition)

The second leg of D2, byte-parity of the embedded superblock coinbase at the next mainnet
superblock height, depends on a precondition the network has not yet met.

As of 2026-09-10, at chain tip 2536334, Dash Core reports nextsuperblock=2542248 and
lastsuperblock=2525632. A superblock coinbase can be assembled only once the network
produces a funded superblock trigger for height 2542248 with yes-votes at or above the
governance funding threshold. At the time of writing the network holds zero valid
governance triggers, and no governance object references height 2542248. The next
superblock is approximately 5900 blocks away.

The superblock-coinbase byte-parity proof is therefore not yet producible. It is blocked by
the absence of a network-funded trigger, not by the embedded assembler. When a funded
trigger appears, the embedded superblock coinbase can be captured and compared at that
height using the same byte-parity method as the CbTx leg in section 1.
