//
// Created by sl33n on 03.06.23.
//

#include "webnode.h"

bool isDirectory(const std::string &path)
{
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return (info.st_mode & S_IFDIR) != 0;
}
