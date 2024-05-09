#pragma once

#include <cstdint>
#include <atomic>
#include <string>

#include <boost/log/trivial.hpp>
#include <boost/log/attributes/named_scope.hpp>

namespace c2pool
{

namespace log
{

enum flags : uint32_t
{
    NONE = 0,
    POOL = (1 << 0),
    COIND = (1 << 2),
    COIND_RPC = (1 << 3),
    SHARETRACKER = (1 << 4),
    DB = (1 << 5),
    OTHER = (1 << 6),
    P2P = (1 << 7),
    STRATUM = (1 << 8),
    ALL = ~(uint32_t)0,
};

class Logger
{
private:
    static uint32_t m_categories;
public:

    static void init();

    static void add_category(const std::string& category);
    static void remove_category(const std::string& category);

    static void enable_trace();
    static void disable_trace();

    static inline bool check_category(c2pool::log::flags&& flag)
    {
        return (m_categories & flag) != 0;
    }
};

#define LOG_TRACE BOOST_LOG_TRIVIAL(trace)
#define LOG_ERROR BOOST_LOG_TRIVIAL(error)
#define LOG_INFO BOOST_LOG_TRIVIAL(info)
#define LOG_WARNING BOOST_LOG_TRIVIAL(warning)
#define LOG_FATAL BOOST_LOG_TRIVIAL(fatal)

// For Debug
#define LOG_DEBUG(ctg) \
    if (c2pool::log::Logger::check_category(c2pool::log::flags::ctg))                   \
        BOOST_LOG_TRIVIAL(debug).stream() << "(" << #ctg << ") "

#define LOG_DEBUG_POOL LOG_DEBUG(POOL)
#define LOG_DEBUG_COIND LOG_DEBUG(COIND)
#define LOG_DEBUG_COIND_RPC LOG_DEBUG(COIND_RPC)
#define LOG_DEBUG_SHARETRACKER LOG_DEBUG(SHARETRACKER)
#define LOG_DEBUG_DB LOG_DEBUG(DB)
#define LOG_DEBUG_OTHER LOG_DEBUG(OTHER)
#define LOG_DEBUG_P2P LOG_DEBUG(P2P)
#define LOG_DEBUG_STRATUM LOG_DEBUG(STRATUM)

} //namespace logger

} //namespace c2pool