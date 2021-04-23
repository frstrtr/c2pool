#pragma once
#include <string>
#include <iostream>
#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

using namespace boost::dll;
using namespace boost::filesystem;

namespace c2pool::filesystem
{

    //full path to main project folder
    std::string getProjectDir();
    const char *getProjectDir_c();

    path getProjectPath();
    auto createDirectory(std::string directoryName);
    path findFile(std::string fileName);
    std::fstream getFile(std::string fileName, std::ios_base::openmode openMode = std::ios_base::out);
    std::fstream closeFile(std::fstream file);

    //full subdirection path.
    std::string getSubDir(std::string path);

    const char *getSubDir_c(std::string path);

} // namespace c2pool::filesystem