#pragma once

/// c2pool-utxo: the coin-neutral UTXO snapshot tool.
///
///   --utxo-inspect FILE[,PART...]                     decode + hash a snapshot, write nothing
///       [--expect-coins N] [--expect-base HEX] [--expect-muhash HEX]
///       [--expect-hash-serialized-2 HEX] [--expect-sha256 HEX] [--no-muhash] [--no-serialized]
///   --utxo-import FILE[,PART...] --utxo-db DIR        import into an empty UTXOViewDB
///       (--utxo-snapshot-pin PINFILE |
///        --expect-height H --expect-base HEX --expect-coins N --expect-muhash HEX
///        [--expect-hash-serialized-2 HEX] [--expect-sha256 HEX])
///   --utxo-hash DIR [--muhash | --serialized]          set hashes of a UTXOViewDB at its best block
///   --utxo-dump DIR FILE --utxo-dump-at-best           write a UTXOViewDB as a snapshot file
///   --dump-utxo-snapshot-pin FILE[,PART...] --coin C --network N --height H
///       [--url U] [--sources S] [--generated ISO8601] [--inc]
///
/// Every command that opens a DB refuses one held by another process
/// (utxo-snapshot-db-held) and never creates one it was asked to read.
/// Exit code: 0 = done and every expectation met, 1 = refused or mismatch,
/// 2 = usage.

#include <ostream>
#include <string>
#include <vector>

namespace core {

int run_utxo_tool(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

} // namespace core
