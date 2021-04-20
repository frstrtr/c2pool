#include "filesystem.h"
#include <string>
#include <cstring>
#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

using namespace boost::dll;
using namespace boost::filesystem;

namespace c2pool::filesystem
{
    //full path to main project folder
    std::string getProjectDir()
    {
        path full_path(program_location().parent_path());
        return full_path.string();
        //return RESOURCES_DIR; //TODO: boost::filesystem
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

    //full subdirection path.
    std::string getSubDir(std::string path)
    {
        auto _path = getProjectPath();
        _path /= path;
        if (exists(_path))
        {
            return _path.string();
        }
        else
        {
            return "";
        }
    }

    auto getPath()
    {
        path full_path(program_location().parent_path());
        return full_path;
    }

    auto createDirectory(std::string directoryName)
    {
        path full_path = getPath();
        full_path /= directoryName;
        if (!exists(full_path))
        {
            create_directory(full_path);
        }
    }

    auto createFile(std::string fileName)
    {
        path full_path = getPath();
        full_path /= fileName;
        if (!exists(full_path))
        {
            std::ofstream file{full_path.string()};
        }
    }

    auto findFile(std::string fileName)
    {
        path full_path = getPath();
        full_path /= fileName;
        if (exists(full_path))
        {
            return full_path;
        }
    }

    const char *getSubDir_c(std::string path)
    {
        /*std::string str = getSubDir(path);
        char *cstr = new char[str.length() + 1];
        std::strcpy(cstr, str.c_str());
        return cstr;*/
        auto _path = getProjectPath();
        _path /= path;
        if (exists(_path))
        {
            return _path.string().c_str();
        }
        else
        {
            return "";
        }
    }

} // namespace c2pool::filesystem