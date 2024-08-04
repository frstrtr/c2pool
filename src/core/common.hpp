#pragma once

#include <ctime>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <functional>

namespace core
{

class Counter
{
private:
    int m_count = 0;

public:
    int operator()()
    {
        m_count++;
        return m_count;
    }
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

uint32_t timestamp();

} // namespace core