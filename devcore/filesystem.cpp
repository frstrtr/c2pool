#include "filesystem.h"
#include <string>
#include <cstring>

namespace c2pool::filesystem
{
    //full path to main project folder
    std::string getProjectDir()
    {
        return RESOURCES_DIR; //TODO: boost::filesystem
    }

    const char *getProjectDir_c()
    {
        return RESOURCES_DIR; //TODO: boost::filesystem
    }

    //full subdirection path.
    std::string getSubDir(std::string path)
    {
        return getProjectDir() + path;
    }

    const char *getSubDir_c(std::string path)
    {
        std::string str = getSubDir(path);
        char *cstr = new char[str.length() + 1];
        std::strcpy(cstr, str.c_str());
        return cstr;
    }

} // namespace c2pool::filesystem