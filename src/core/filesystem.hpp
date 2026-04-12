#pragma once

#include <string>
#include <filesystem>

namespace core
{

namespace filesystem
{

inline std::filesystem::path config_path()
{
    #ifdef _WIN32
        return std::filesystem::path(std::getenv("APPDATA")) / "c2pool";
    #else  // Linux + macOS
        return std::filesystem::path(std::getenv("HOME")) / ".c2pool";
    #endif
}

inline std::filesystem::path current_path()
{
    return std::filesystem::canonical(".");
}

} // namespace filesystem

} // namespace core