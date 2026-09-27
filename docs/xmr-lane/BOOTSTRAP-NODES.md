# XMR pool: relay bootstrap nodes

A c2pool v37 XMR node finds the other nodes of its pool through the receipt
relay. So that a new node does not need a peer address from anyone, the
binary carries a built-in bootstrap list, the same way the v36 nodes carry
`DEFAULT_BOOTSTRAP_HOSTS`. This file lists the same nodes.

## Mainnet

| Node | IP | Relay port | Stratum port | Dashboard port |
|---|---|---|---|---|
| pool node 1 | `109.123.238.32` | 59321 | 3334 | 8097 |
| pool node 2 | `158.220.92.171` | 59321 | 3334 | 8097 |

Stagenet, testnet and regtest have no built-in list. Get a relay peer from
your pool's operator and pass it with `--relay-peer`.

## How the node uses the list

- The list is used only when the relay is on (`--relay-listen` or
  `--relay-peer`). The node dials the built-in peers in addition to every
  `--relay-peer`.
- `--no-relay-bootstrap` turns the built-in list off. Then the node dials
  only its `--relay-peer` values.
- A node does not dial itself: a built-in entry whose port is the
  `--relay-listen` port, on the listen host or on one of the machine's own
  addresses, is skipped. An entry that is also a `--relay-peer` is dialled
  once.
- An unreachable peer is redialled with the relay's normal backoff
  (1 to 60 seconds). It never stops the node.
- At start the node logs one line with the peers it uses:
  `relay: bootstrap ON: dial=... self_skipped=... already_peer=...`.

## Add a node

1. Run a mainnet node with the pool's settings and the relay listening on a
   public address (`--relay-listen 0.0.0.0:59321`). Keep it up.
2. Open a pull request against `frstrtr/c2pool` that adds the node to both:
   - the table above (IP, relay port, stratum port, dashboard port), and
   - `DEFAULT_BOOTSTRAP_HOSTS_MAINNET` in
     `src/c2pool/v37/xmr/relay/xmr_relay_bootstrap.hpp`, as `IP:PORT`.
3. Update the expected list in `v37_xmr_cli_strict_kat`
   (`src/c2pool/v37/test/v37_xmr_cli_strict_kat.cpp`, the R rows) so the
   test pins the new list.

The list changes only which peers a node dials first. It is not part of the
wire or of consensus.
