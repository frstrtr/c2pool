#include "filesystem.h"
#include <string>
#include <cstring>
#include <boost/dll.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <fstream>

using namespace boost::dll;
using namespace boost::filesystem;

namespace c2pool::filesystem
{
    //full path to main project folder
    std::string getProjectDir()
    {
        path full_path(program_location().parent_path());
        return full_path.string();
    }

    path getProjectPath()
    {
        path full_path(program_location().parent_path());
        return full_path;
    }

    const char *getProjectDir_c()
    {
        return getProjectDir().c_str();
        //return RESOURCES_DIR; //TODO: boost::filesystem
    }

    auto createDirectory(std::string directoryName)
    {
        path full_path = getProjectPath();
        full_path /= directoryName;
        if (!exists(full_path))
        {
            create_directory(full_path);
        }
    }

    std::fstream getFile(std::string filePath, std::ios_base::openmode openMode)
    {
        path _filePath = filePath;
        path _path = getSubDir(_filePath.parent_path().string());
        path fullPath = _path / _filePath.filename();
        std::fstream file(fullPath.string(), openMode);
        return file;
    }

    path findFile(std::string filePath)
    {
        path full_path = getProjectPath();
        full_path /= filePath;
        if (exists(full_path))
        {
            return full_path;
        }
        full_path.clear();
        return full_path;
    }
    //full subdirection path.
    std::string getSubDir(std::string path)
    {
        auto _path = getProjectPath();
        _path /= path;
        if (!exists(_path))
        {
            create_directories(_path);
        }
        return _path.string();
    }

    const char *getSubDir_c(std::string path)
    {
        auto subdir = getSubDir(path);
        char* result = new char[subdir.length()];
        strcpy(result, subdir.c_str());
        return result;
    }

} // namespace c2pool::filesystem