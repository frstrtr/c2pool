#pragma once

#include <string>
#include <filesystem>
#include <cstdlib>

namespace core
{

namespace filesystem
{

// Process-wide data-dir override. Empty = unset.
// Populated once at startup from the `--data-dir PATH` CLI flag (via
// set_data_dir()). When set, it becomes the root of ALL per-instance
// on-disk state (sharechain LevelDB, addr store, whitelist, logs, ratchet,
// found-blocks db, etc.) so co-located c2pool instances can each own an
// isolated namespace and never contend the same LevelDB LOCK. See issue #722.
inline std::filesystem::path& data_dir_override()
{
    static std::filesystem::path s_override;
    return s_override;
}

// Set the per-instance data directory. Call once, before any code opens
// LevelDB or writes state (i.e. during CLI arg parsing). An empty path
// leaves the platform default in force.
inline void set_data_dir(const std::filesystem::path& p)
{
    data_dir_override() = p;
}

inline std::filesystem::path config_path()
{
    // 1. Explicit --data-dir override (highest priority). This is the ONLY
    //    override input: it is set solely from the operator-supplied CLI flag,
    //    never from an environment variable, so config_path()'s only env reads
    //    remain the historical HOME/APPDATA below (unchanged taint surface).
    const std::filesystem::path& ov = data_dir_override();
    if (!ov.empty())
        return ov;

    // 2. Historical default — byte-for-byte identical to prior releases so
    //    single-instance behavior is unchanged.
    // getenv may return nullptr if the var is unset; std::filesystem::path(nullptr)
    // is UB. Fall back to the current directory so an unset HOME/APPDATA degrades
    // gracefully instead of crashing.
    #ifdef _WIN32
        const char* base = std::getenv("APPDATA");
        return std::filesystem::path(base ? base : ".") / "c2pool";
    #else  // Linux + macOS
        const char* base = std::getenv("HOME");
        return std::filesystem::path(base ? base : ".") / ".c2pool";
    #endif
}

inline std::filesystem::path current_path()
{
    return std::filesystem::canonical(".");
}

} // namespace filesystem

} // namespace core