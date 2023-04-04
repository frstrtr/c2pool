#include "common.h"
namespace c2pool::dev
{
    std::function<int()> count_generator()
    {
        int i = 0;
        return [=]() mutable {
            i++;
            return i;
        };
    }

    std::string swap4(std::string s)
    {
        if (s.size() % 4)
            throw std::invalid_argument("swap4 -- s.size() % 4 != 0");

        for (int i = 0; i+4 <= s.size(); i+=4)
        {
            std::reverse(s.begin()+i, s.begin()+i+4);
        }
        return s;
    }

    std::vector<unsigned char> swap4(std::vector<unsigned char> s)
    {
        if (s.size() % 4)
            throw std::invalid_argument("swap4 -- s.size() % 4 != 0");

        for (int i = 0; i+4 <= s.size(); i+=4)
        {
            std::reverse(s.begin()+i, s.begin()+i+4);
        }
        return s;
    }

    uint32_t timestamp()
    {
        return std::time(nullptr);
    }

    std::vector<unsigned char> bytes_from_uint8(std::vector<uint8_t> data)
    {
        std::vector<unsigned char> result;
        for (auto v : data)
        {
            result.push_back((unsigned char) v);
        }
        return result;
    }

    bool ExitSignalHandler::work_status = true;
} // namespace c2pool::time