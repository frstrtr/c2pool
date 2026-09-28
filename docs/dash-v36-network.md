# DASH v36 network: protocol version and the bump rule

The DASH v36 network is the p2pool v36 sharechain for DASH. Nodes on it mint and accept only share type 36.

## Protocol version

| | public DASH sharechain (v16) | DASH v36 network |
|---|---|---|
| advertised protocol version | 3600 | 3601 (`ISOLATED_V36_PROTOCOL_VERSION`) |
| minimum accepted peer version | 1700 | 3601 |

A peer that advertises less than 3601 is refused at the version handshake. The node logs `peer protocol below min-protocol floor: peer build lacks v36 isolated support — upgrade (...)`, closes the connection and does **not** ban the peer. Peers refused this way include p2pool-dash (1700) and any c2pool-dash build without v36 support (3600). Otherwise such a build would stay connected but could not parse a single type-36 share.

## Bump rule

The number is the only signal that a peer speaks the current v36 wire format. So:

- **Any change to the DASH v36 share, ref-stream or gentx wire format MUST bump `ISOLATED_V36_PROTOCOL_VERSION`** (3601 → 3602 → …) in the same PR.
- The PR must add a KAT: the new build refuses a peer advertising the previous number and admits one advertising the new number.
- The public v16 values (advert 3600, floor 1700) are pinned by `static_assert` in `src/impl/dash/config_pool.hpp` and never change because of a v36 bump.
- The number is not a ratchet target. Every protocol comparison in the code is an ordering (`>=`, `<`, `max`), never an equality.

## Joining the network

```
c2pool-dash --run --net dash-v36 --addnode HOST:PORT ...
```

`--net dash-v36` selects the DASH v36 network. It sets exactly:

| | value |
|---|---|
| identifier | `ac2785363c0180b8` (`V36_NETWORK_IDENTIFIER_HEX`) |
| prefix | `8d8516bac9edd280` (`V36_NETWORK_PREFIX_HEX`) |
| share version minted and accepted | 36 |
| protocol advert and accept floor | 3601 |
| state directory | `<data-dir>/dash_ac2785363c0180b8_v36` |

The settings-file form is `network = "v36"` under `[dash.sharechain]`. It is a money-class key, so the file needs `[gate].money_ack_hash` (`--ack-money-settings`). The CLI wins over the file.

Rules:

- `--net dash-v36` cannot be combined with `--network-id` or `--prefix` (from either the CLI or the settings file). The node exits with an error that names the conflicting flag.
- `--net dash-v36` is a mainnet network and cannot be combined with `--testnet` / `--regtest`. A test network uses `--testnet --network-id HEX --prefix HEX`, which runs the same v36 profile under its own identity.
- Without `--net` (and without `--network-id`) the node stays on the default v16 sharechain, `7242ef345e1bed6b` / `3b3e1286f446b891`, unchanged.
- Built-in seeds: when `--net dash-v36` is set and no `--addnode` / `--connect` is given, the node dials only the network's own seed list (`dash::v36_network_seed_hosts`). The operator-approved seeds are `158.220.92.171:8999` (dash.voidbind.com) and `109.123.238.32:8999`, on the sharechain port. An explicit `--addnode` / `--connect` replaces the list.
