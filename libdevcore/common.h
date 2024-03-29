#pragma once

#include <ctime>
#include <chrono>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include <functional>
#include <boost/date_time.hpp>

namespace c2pool::dev
{
    std::function<int()> count_generator();

    std::string swap4(std::string s);
    std::vector<unsigned char> swap4(std::vector<unsigned char> s);

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
    uint32_t timestamp();

    inline std::string format_date(uint32_t _timestamp)
    {
        auto t = boost::posix_time::seconds(_timestamp);
        return boost::posix_time::to_simple_string(t);
    }

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

    struct debug_timestamp
    {
        std::chrono::duration<double> t;

        debug_timestamp() : t(std::chrono::high_resolution_clock::now().time_since_epoch()) { }
        debug_timestamp(std::chrono::duration<double> _t) : t(_t) {}

        debug_timestamp operator-(const debug_timestamp& v) const
        {
            return {t - v.t};
        }

        debug_timestamp operator+(const debug_timestamp& v) const
        {
            return {t + v.t};
        }

        friend std::ostream& operator<<(std::ostream &stream, const debug_timestamp& v)
        {
            stream << std::fixed << std::setprecision(10) << v.t.count() << "s";
            stream.unsetf(std::ios_base::fixed);
            return stream;
        }
    };
} // namespace c2pool::dev