//
// Created by sl33n on 03.06.23.
//

#include "webnode.h"
#include <filesystem>

bool isDirectory(const std::string &path)
{
    const std::filesystem::path _path(path); // Constructing the path from a string is possible.
    std::error_code ec; // For using the non-throwing overloads of functions below.
    if (std::filesystem::is_directory(path, ec))
        return true;
    else
        return false;
}
