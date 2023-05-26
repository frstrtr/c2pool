#pragma once

#include <iostream>
#include <memory>
#include <map>
#include <atomic>
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

namespace C2Log
{
    enum Flags : uint32_t
    {
        NONE = 0,
        POOL = (1 << 0),
        COIND = (1 << 2),
        COIND_JSONRPC = (1 << 3),
        SHARETRACKER = (1 << 4),
        DB = (1 << 5),
        OTHER = (1 << 6),
        P2P = (1 << 7),
        STRATUM = (1 << 8),
        ALL = ~(uint32_t)0,
    };


    #define LOG_TRACE BOOST_LOG_TRIVIAL(trace)
    #define LOG_ERROR BOOST_LOG_TRIVIAL(error)
    #define LOG_INFO BOOST_LOG_TRIVIAL(info)
    #define LOG_WARNING BOOST_LOG_TRIVIAL(warning)
    #define LOG_FATAL BOOST_LOG_TRIVIAL(fatal)

    // For Debug
    #define LOG_DEBUG(nmsp, ctg) \
        if (check_category(nmsp::ctg))                   \
            BOOST_LOG_TRIVIAL(debug).stream() << "[" << #ctg << "]\t"

    #define LOG_DEBUG_POOL LOG_DEBUG(C2Log, POOL)
    #define LOG_DEBUG_COIND LOG_DEBUG(C2Log, COIND)
    #define LOG_DEBUG_COIND_JSONRPC LOG_DEBUG(C2Log, COIND_JSONRPC)
    #define LOG_DEBUG_SHARETRACKER LOG_DEBUG(C2Log, SHARETRACKER)
    #define LOG_DEBUG_DB LOG_DEBUG(C2Log, DB)
    #define LOG_DEBUG_OTHER LOG_DEBUG(C2Log, OTHER)
    #define LOG_DEBUG_P2P LOG_DEBUG(C2Log, P2P)
    #define LOG_DEBUG_STRATUM LOG_DEBUG(C2Log, STRATUM)

    class Logger
    {
    private:
        inline static Logger *instance;
        Logger();
    public:
        std::atomic<uint32_t> categories{0};

        static void Init();
        static Logger* log();

        static void add_category(const std::string &);
        static void remove_category(const std::string &);

        static void enable_trace();
        static void disable_trace();
    };

    static inline bool check_category(C2Log::Flags flag)
    {
        return (Logger::log()->categories & flag) != 0;
    }
} // namespace C2Log

template<typename T>
std::ostream &operator<<(std::ostream &stream, const std::optional<T> &data)
{
    stream << "({Opt}: ";
    if (data.has_value())
    {
        stream << data.value();
    } else
    {
        stream << "nullopt";
    }
    stream << ")";
    return stream;
}

template<typename T>
std::ostream &operator<<(std::ostream &stream, std::vector<T> &data)
{
    stream << "[ ";
    for (auto v : data)
    {
        stream << v << ", ";
    }
    stream << "\b ]";
    return stream;
}

template<typename T>
std::ostream &operator<<(std::ostream &stream, const std::vector<T> &data)
{
    stream << "[ ";
    for (auto v : data)
    {
        stream << v << ", ";
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
        stream << (unsigned int) v << ", ";
    }
    stream << "\b ]";
    return stream;
}

template <>
inline std::ostream &operator<<<unsigned char>(std::ostream &stream, const std::vector<unsigned char> &data)
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