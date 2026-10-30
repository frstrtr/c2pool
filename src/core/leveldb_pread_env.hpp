// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

namespace leveldb {
class Env;
}

namespace core {

/// LevelDB's default Env with table files read through pread, never mmap
/// (LevelDBOptions::mmap_reads = false): a page read is not kept in the
/// process's RSS while its table is open. The fd stays open while the table
/// is in LevelDB's table cache (max_open_files). nullptr where it is not
/// available (Windows: LevelDB's own Env, which does not mmap there).
leveldb::Env* leveldb_pread_env();

} // namespace core
