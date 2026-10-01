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
