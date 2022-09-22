#pragma once

#include <ctime>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

namespace c2pool::dev
{
    auto count_generator()
    {
        int i = 0;
        return [=]() mutable {
            i++;
            return i;
        };
    }

    template <typename int_type>
    int_type str_to_int(std::string value)
    {
        std::stringstream ss;
        int_type result;
        ss<< value;
        ss >> result;
        return result;
    }

    //int64_t/IntType(64)
    time_t timestamp();

    std::vector<unsigned char> bytes_from_uint8(std::vector<uint8_t> data);

    template <typename Derived, typename Base, typename Del>
    std::unique_ptr<Derived, Del>
    static_unique_ptr_cast(std::unique_ptr<Base, Del> &&p)
    {
        auto d = static_cast<Derived *>(p.release());
        return std::unique_ptr<Derived, Del>(d, std::move(p.get_deleter()));
    }

    class ExitSignalHandler
    {
    public:
        static void handler(int) { work_status = false; }
        bool working() const { return work_status; }

    private:
        static bool work_status; //true = working, false = exit.
    };

    //errors in main
    enum C2PoolErrors
    {
        success = 0
    };
} // namespace c2pool::dev