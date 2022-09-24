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

    time_t timestamp()
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