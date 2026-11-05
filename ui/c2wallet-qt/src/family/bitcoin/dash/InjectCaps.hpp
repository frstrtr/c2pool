// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Node-side admission caps for a zero-fee INJECT transaction, mirrored here as
// std-only constants so the offline builders (CollateralTx in inject mode and
// SweepTx) refuse or split BEFORE anything is signed, instead of leaving the
// discovery to a refused submit or a dropped template entry. The values are the
// c2pool DASH node's own:
//
//   kMaxInjectTxBytes      Mempool::kMaxInjectTxBytes == TxInjectPool::kMaxInjectTxBytes
//                          == Mempool::kMaxPinnedTxBytes (Dash bad-txns-oversize)
//   kMaxInjectInputs       InjectSandbox::kMaxInputs
//   kMaxInjectOutputs      InjectSandbox::kMaxOutputs
//   kMaxInjectTotalBytes   TxInjectPool::kMaxInjectTotalBytes == Mempool::kMaxPinnedTotalBytes
//   kMaxInjectPoolEntries  TxInjectPool::INJECT_POOL_MAX_ENTRIES
//   kSequenceFinal         every input we build. Mempool::add_inject refuses a
//                          version>=2 tx with any input whose nSequence leaves
//                          bit 31 (SEQUENCE_LOCKTIME_DISABLE_FLAG) clear (BIP68).
//
// The node side is pinned by static_asserts in test/test_dash_tx_inject.cpp, so
// a change on either side breaks that build until both agree again.
//
// std-only header: both DASH closures and the main-repo test can include it.

#include <cstddef>
#include <cstdint>

namespace c2w::dash {

namespace caps {

inline constexpr size_t kMaxInjectTxBytes = 100000;
inline constexpr size_t kMaxInjectInputs = 1000;
inline constexpr size_t kMaxInjectOutputs = 1000;
inline constexpr size_t kMaxInjectTotalBytes = 400000;
inline constexpr size_t kMaxInjectPoolEntries = 1024;
inline constexpr uint32_t kSequenceFinal = 0xffffffffu;
inline constexpr uint32_t kSequenceLocktimeDisableFlag = 0x80000000u;

// Worst-case size of one signed P2PKH input: 32 txid + 4 vout + 1 script length
// + 4 sequence + scriptSig, where the scriptSig is push(73-byte DER sig incl. the
// hashtype) + push(pubkey). 41 + 1+73 + 1+33 = 149 (compressed) and
// 41 + 1+73 + 1+65 = 181 (uncompressed). The unsigned input is the 41 bytes.
struct P2pkhInSignedBytes {
    size_t compressed;
    size_t uncompressed;
};
inline constexpr P2pkhInSignedBytes kP2pkhInSignedBytes{149, 181};
inline constexpr size_t kUnsignedInputBytes = 41;

// How many full-size inject txs one node's pool holds at once (400 kB / 100 kB).
inline constexpr size_t kFullBatchesPerPool = kMaxInjectTotalBytes / kMaxInjectTxBytes;

} // namespace caps

// The pubkey encoding the signing key will use. It only feeds the signed-size
// estimate: until the key is found, plan with the worst case (Unknown => 181 B
// per input) so a plan never under-estimates.
enum class PubkeyEncoding : uint8_t { Unknown, Compressed, Uncompressed };

inline constexpr size_t signed_input_bytes(PubkeyEncoding e)
{
    return e == PubkeyEncoding::Compressed ? caps::kP2pkhInSignedBytes.compressed
                                           : caps::kP2pkhInSignedBytes.uncompressed;
}

} // namespace c2w::dash
