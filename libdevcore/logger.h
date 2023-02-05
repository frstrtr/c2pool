#pragma once

#include <iostream>
#include <memory>
#include <map>
using std::shared_ptr;

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

namespace c2pool::dev
{
    class c2pool_config;
}

namespace c2pool::console
{
    #define LOG_TRACE BOOST_LOG_TRIVIAL(trace)
    #define LOG_ERROR BOOST_LOG_TRIVIAL(error)
    #define LOG_DEBUG BOOST_LOG_TRIVIAL(debug)
    #define LOG_INFO BOOST_LOG_TRIVIAL(info)
    #define LOG_WARNING BOOST_LOG_TRIVIAL(warning)
    #define LOG_FATAL BOOST_LOG_TRIVIAL(fatal)

    class Logger
    {
    private:
        inline static Logger *instance;

        Logger();
    public:
        static void Init();

        static Logger* log();
    };
} // namespace c2pool::console

template<typename T>
std::ostream &operator<<(std::ostream &stream, std::vector<T> &data)
{
    stream << "[ ";
    for (auto v : data)
    {
        stream << v << " ";
    }
    stream << "\b ]";
    return stream;
}

template <>
inline std::ostream &operator<<<unsigned char>(std::ostream &stream, std::vector<unsigned char> &data)
{
    stream << "[ ";
    for (auto v : data)
    {
        stream << (unsigned int) v << " ";
    }
    stream << "\b ]";
    return stream;
}

template <typename T, typename K>
inline std::ostream &operator<<(std::ostream &stream, std::map<T, K> &data)
{
    stream << "[ ";
    for (auto [k, v] : data)
    {
        stream << "(" << k << ": " << v << ");";
    }
    stream << "\b ]";
    return stream;
}
