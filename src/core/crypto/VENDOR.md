# Vendored code: Dash Core v23.1.7

Upstream: https://github.com/dashpay/dash
Tag: `v23.1.7` (annotated), commit `01fc719f9088c7ec3d14cfb04a1a8bd296537934`
(2026-06-30). This is the dashd release that wrote the reference
`dumptxoutset` file and answered `gettxoutsetinfo muhash` for the pin.

License: MIT (the Bitcoin Core / Dash Core copyright headers are kept in
every ported file).

| c2pool file | upstream file(s) | changes |
|---|---|---|
| `src/core/crypto/chacha20.hpp`, `chacha20.cpp` | `src/crypto/chacha20.h`, `src/crypto/chacha20.cpp`, `memory_cleanse` from `src/support/cleanse.cpp` | namespace `core::crypto`; `std::span` in place of `Span`; `FSChaCha20` (BIP324) not ported; `ChaCha20Aligned::Keystream`/`Crypt` lose the `inline` specifier upstream puts on the out-of-line definitions (muhash.cpp calls `Keystream` from another translation unit); copy operations declared `= default` |
| `src/core/crypto/muhash.hpp`, `muhash.cpp` | `src/crypto/muhash.h`, `src/crypto/muhash.cpp` | namespace `core::crypto`; `std::span`; `Finalize` writes c2pool's `uint256`; `SERIALIZE_METHODS` spelled out as `Serialize()` / `Deserialize()` over the same 768 bytes; SHA256 through btclibs `CSHA256` (upstream `HashWriter{} << span` is one SHA256 round over the raw bytes) |
| `src/core/coin/coin_compressor.hpp`, `coin_compressor.cpp` | `src/compressor.h`, `src/compressor.cpp`; `Coin::Serialize`/`Unserialize` of `src/coins.h`; `WriteVarInt`/`ReadVarInt`/`WriteCompactSize` of `src/serialize.h` | free functions in `core::coin` over `std::vector<unsigned char>` scripts; `CPubKey::IsFullyValid`/`Decompress` replaced by the same two libsecp256k1 calls; readers return a status instead of throwing; the two cases upstream `ScriptCompression::Unser` swallows (a 0x04/0x05 point that does not decompress, a raw script over `MAX_SCRIPT_SIZE`) are reported to the caller |

Not vendored but transcribed (no code copied verbatim beyond single lines):
`src/kernel/coinstats.cpp` `TxOutSer` and `ApplyHash` (muhash and
hash_serialized_2 streams) in `src/core/coin/utxo_set_hash.cpp`;
`src/node/utxo_snapshot.h` `SnapshotMetadata` and the `dumptxoutset` file
layout in `src/core/coin/utxo_snapshot.{hpp,cpp}`.

KATs: `src/core/test/muhash_chacha20_test.cpp` (crypto_tests.cpp
`chacha20_testvector`, `chacha20_midblock`, `muhash_tests`),
`src/core/test/coin_compressor_test.cpp` (compress_tests.cpp
`compress_amounts` and the script cases).

To update: diff the upstream files above between the recorded tag and the
new one, carry the changes over, update this note, and rerun the KATs.
