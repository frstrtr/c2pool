#pragma once

#include <string>
#include <filesystem>
#include <cstdlib>

namespace core
{

namespace filesystem
{

inline std::filesystem::path config_path()
{
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