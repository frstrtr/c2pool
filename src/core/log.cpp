#include "log.hpp"

#include <map> 

#include <core/filesystem.hpp>

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/attributes/named_scope.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

namespace core
{
namespace log
{

uint32_t Logger::m_categories = 0;

const std::map<std::string, core::log::flags> categories =
{
        {"0", NONE},
        {"none", NONE},
        {"pool", POOL},
        {"coind", COIND},
        {"coindrpc", COIND_RPC},
        {"sharetracker", SHARETRACKER},
        {"db", DB},
        {"other", OTHER},
        {"p2p", P2P},
        {"stratum", STRATUM},
        {"1", ALL},
        {"all", ALL},
};

void Logger::init()
{
    // Console-only at startup — file sink is added after config is loaded
    // (avoids hanging on a bloated debug.log with tight rotation limits)
    boost::log::add_common_attributes();
    boost::log::core::get()->add_global_attribute(
        "Scope", boost::log::attributes::named_scope()
    );

    auto fmtTimeStamp = boost::log::expressions::
        format_date_time<boost::posix_time::ptime>("TimeStamp", "%H:%M:%S.%f");
    auto fmtSeverity = boost::log::expressions::
        attr<boost::log::trivial::severity_level>("Severity");
    boost::log::formatter logFmt =
        boost::log::expressions::format("[%1%][%2%] %3%")
        % fmtTimeStamp % fmtSeverity % boost::log::expressions::smessage;

    auto consoleSink = boost::log::add_console_log(std::clog);
    consoleSink->set_formatter(logFmt);
}

void Logger::init(const std::string& log_file_name, int rotation_size_mb, int max_total_mb, const std::string& level)
{
    // common attributes
    boost::log::add_common_attributes();
    boost::log::core::get()->add_global_attribute(
        "Scope", boost::log::attributes::named_scope()
    );

    // set log level filter
    auto severity = logging::trivial::trace;
    if (level == "debug")        severity = logging::trivial::debug;
    else if (level == "info" || level == "INFO")
                                 severity = logging::trivial::info;
    else if (level == "warning" || level == "WARNING" || level == "warn")
                                 severity = logging::trivial::warning;
    else if (level == "error" || level == "ERROR")
                                 severity = logging::trivial::error;
    boost::log::core::get()->set_filter(
        boost::log::trivial::severity >= severity
    );
    
    /* log formatter:
     * [TimeStamp] [ThreadId] [Severity Level] [Scope] Log message
     */
    auto fmtTimeStamp = boost::log::expressions::
        format_date_time<boost::posix_time::ptime>("TimeStamp", "%H:%M:%S.%f");
    /*auto fmtThreadId = boost::log::expressions::
        attr<boost::log::attributes::current_thread_id::value_type>("ThreadID"); */
    auto fmtSeverity = boost::log::expressions::
        attr<boost::log::trivial::severity_level>("Severity");
    /* example: BOOST_LOG_NAMED_SCOPE("main"); -> [main(/home/sl33n/c2pool/src/c2pool/c2pool.cpp:12)] 
    auto fmtScope = boost::log::expressions::format_named_scope("Scope",
        boost::log::keywords::format = "%n(%f:%l)",
        boost::log::keywords::iteration = boost::log::expressions::reverse,
        boost::log::keywords::depth = 2); */
    boost::log::formatter logFmt =
        boost::log::expressions::format("[%1%][%2%] %3%")
        % fmtTimeStamp /*% fmtThreadId*/ % fmtSeverity % boost::log::expressions::smessage;

    /* console sink */
    auto consoleSink = boost::log::add_console_log(std::clog);
    consoleSink->set_formatter(logFmt);

    /* file sink — data directory (Bitcoin-style)
     * tail -f ~/.c2pool/debug.log
     */
    auto log_dir = core::filesystem::config_path();
    std::filesystem::create_directories(log_dir);
    auto debug_log = log_dir / (log_file_name.empty() ? "debug.log" : log_file_name);

    auto fsSink = boost::log::add_file_log(
        boost::log::keywords::file_name = debug_log.string(),
        boost::log::keywords::rotation_size = rotation_size_mb * 1024 * 1024,
        boost::log::keywords::open_mode = std::ios_base::app,
        boost::log::keywords::min_free_space = 30 * 1024 * 1024,
        boost::log::keywords::target = log_dir.string(),
        boost::log::keywords::max_size = max_total_mb * 1024 * 1024
    );
    fsSink->set_formatter(logFmt);
    fsSink->locked_backend()->auto_flush(true);
}

void Logger::add_category(const std::string& category)
{
    if (!categories.count(category))
        return;

    m_categories |= categories.at(category);
}

void Logger::remove_category(const std::string& category)
{
    if (!categories.count(category))
        return;

    m_categories &= ~categories.at(category);
}

void Logger::set_severity_level(boost::log::trivial::severity_level lvl)
{
    logging::core::get()->set_filter(
        logging::trivial::severity >= lvl);
}

std::optional<boost::log::trivial::severity_level>
Logger::severity_level_from_string(const std::string& name)
{
    // Case-insensitive lookup
    std::string lower = name;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (lower == "trace")    return logging::trivial::trace;
    if (lower == "debug")    return logging::trivial::debug;
    if (lower == "info")     return logging::trivial::info;
    if (lower == "warning" || lower == "warn")
                             return logging::trivial::warning;
    if (lower == "error")    return logging::trivial::error;
    if (lower == "fatal" || lower == "critical")
                             return logging::trivial::fatal;
    return std::nullopt;
}

void Logger::enable_trace()
{
    set_severity_level(logging::trivial::trace);
}

void Logger::disable_trace()
{
    set_severity_level(logging::trivial::debug);
}

} // namespace logger

} // namespace core