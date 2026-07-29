// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH masternode-set checkpoint — mainnet — *** UNPINNED ***
//
// THIS BUILD SHIPS NO mainnet MASTERNODE-SET TRUST ANCHOR.
//
// Consequence: `--embedded-mainnet` cannot cold-start the payout-bearing
// masternode set without a dashd RPC. The node FAILS CLOSED — it logs the
// refusal at ERROR and keeps routing templates to the dashd fallback arm
// rather than guessing a masternode payee. A guessed payee is a coinbase the
// network rejects (bad-cb-payee), i.e. a lost block.
//
// To pin an anchor (release step — see
// src/impl/dash/coin/checkpoints/README.md):
//
//     tools/dash/gen_mn_checkpoint.py pin --network mainnet \
//         --rpc-url http://127.0.0.1:PORT --rpc-user U --rpc-password P
//
// which OVERWRITES this file and prints the provenance block for the release
// notes. Anything below this comment block is the generated payload; an empty
// payload is the UNPINNED state the parser reports distinctly.
//
""
