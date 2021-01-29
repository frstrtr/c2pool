#include "common.h"
#include <cstring>
#include <sstream>
namespace c2pool::dev
{
    void substr(char *dest, char *source, int from, unsigned int length)
    {
        memcpy(dest, source + from, length);
        dest[length] = 0;
    }

    char *from_bytes_to_strChar(char *source)
    {
        std::stringstream ss;
        ss << source;
        int buff;
        std::string str_result = "";
        while (ss >> buff)
        {
            unsigned char bbuff = buff;
            str_result += bbuff;
        }
        // std::cout << "lentgth ss: " << str_result.length() << std::endl;
        // std::cout << "str_result: " << str_result << std::endl;
        // std::cout << "str_result.c_str(): " << str_result.c_str() << std::endl;
        unsigned char *result = new unsigned char[str_result.length() + 1];
        memcpy(result, str_result.c_str(), str_result.length());

        return (char *)result;
    }

    bool compare_str(const void *first_str, const void *second_str, unsigned int length)
    {
        if (memcmp(first_str, second_str, length) == 0)
            return true;
        return false;
    }
} // namespace c2pool::time