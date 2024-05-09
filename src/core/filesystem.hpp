#pragma once

#include <string>
#include <filesystem>

namespace c2pool
{

namespace filesystem
{

inline std::filesystem::path config_path()
{
    #ifdef _WIN32
        return std::filesystem::path(std::getenv("APPDATA")) + "/c2pool";
    #elif __linux__
        return std::filesystem::path(std::getenv("HOME")) / ".c2pool";
    #else
        return c2pool::filesystem::current_path();
    #endif
}

inline std::filesystem::path current_path()
{
    return std::filesystem::canonical(".");
}

} // namespace filesystem

} // namespace c2pool