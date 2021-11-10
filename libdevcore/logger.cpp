#include "logger.h"
#include "config.h"
using c2pool::dev::c2pool_config;

#include <memory>
using std::shared_ptr;

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/setup/console.hpp>

#include "filesystem.h"

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

namespace c2pool::console
{
    Logger::Logger()
    {
        logging::add_file_log(
            keywords::file_name = "log_%N.log", /*< file name pattern >*/
            keywords::target = c2pool::filesystem::getSubDir("logs"),
            keywords::rotation_size = 10 * 1024 * 1024,                                   /*< rotate files every 10 MiB... >*/
            keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0), /*< ...or at midnight >*/
            keywords::format = "[%TimeStamp%]<%Severity%>: %Message%"                     /*< log record format >*/
        );
        if (c2pool_config::get()->debug == c2pool::dev::trace)
        {
            logging::core::get()->set_filter(
                logging::trivial::severity >= logging::trivial::trace);
        }
        if (c2pool_config::get()->debug == c2pool::dev::debug)
        {
            logging::core::get()->set_filter(
                logging::trivial::severity >= logging::trivial::debug);
        }
        if (c2pool_config::get()->debug == c2pool::dev::normal)
        {

            logging::core::get()->set_filter(
                logging::trivial::severity >= logging::trivial::info);
        }
        logging::add_console_log(std::cout, boost::log::keywords::format = "[%TimeStamp%]<%Severity%>: %Message%");

        logging::add_common_attributes();
    }

    void Logger::Init()
    {
        if (!instance)
            instance = new Logger();
        else
            std::cout << "SECOND CONSOLE!" << std::endl; //TODO: out to file
    }

    Logger *Logger::log()
    {
        return instance;
    }
}; // namespace c2pool::console