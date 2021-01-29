#pragma once
#include <string>
namespace c2pool::filesystem
{

    //full path to main project folder
    std::string getProjectDir();

    const char *getProjectDir_c();

    //full subdirection path.
    std::string getSubDir(std::string path);

    const char *getSubDir_c(std::string path);

} // namespace c2pool::filesystem