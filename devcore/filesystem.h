#pragma once
#include <string>

#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

using namespace boost::dll;
using namespace boost::filesystem;

namespace c2pool::filesystem
{

    //full path to main project folder
    std::string getProjectDir();

    path getProjectPath();
    auto createDirectory(std::string directoryName);
    auto createFile(std::string fileName);
    auto findFile(std::string fileName);
    auto getPath();
    

    const char *getProjectDir_c();

    //full subdirection path.
    std::string getSubDir(std::string path);

    const char *getSubDir_c(std::string path);

} // namespace c2pool::filesystem