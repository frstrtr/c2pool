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
    // common attributes
    boost::log::add_common_attributes();
    boost::log::core::get()->add_global_attribute(
        "Scope", boost::log::attributes::named_scope()
    );
    // set trace log filter
    boost::log::core::get()->set_filter(
        boost::log::trivial::severity >= logging::trivial::debug
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

    /* file sink */
    auto fsSink = boost::log::add_file_log(
        boost::log::keywords::file_name = "%d-%m-%Y_%Hh%Mm%Ss.log",
        boost::log::keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0), /* rotation at midnight */
        boost::log::keywords::rotation_size = 10 * 1024 * 1024,
        boost::log::keywords::min_free_space = 30 * 1024 * 1024,
        boost::log::keywords::open_mode = std::ios_base::app,
        keywords::target = core::filesystem::config_path() / "logs"
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

void Logger::enable_trace()
{
    logging::core::get()->set_filter(
            logging::trivial::severity >= logging::trivial::trace);
}

void Logger::disable_trace()
{
    logging::core::get()->set_filter(
            logging::trivial::severity >= logging::trivial::debug);
}

} // namespace logger

} // namespace core