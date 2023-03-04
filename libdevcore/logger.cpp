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

namespace C2Log
{
    Logger::Logger()
    {
        logging::add_file_log(
            keywords::file_name = "log_%N.log", /*< file name pattern >*/
            keywords::target = c2pool::filesystem::getSubDir("logs"),
            keywords::rotation_size = 10 * 1024 * 1024,                                   /*< rotate files every 10 MiB... >*/
            keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0), /*< ...or at midnight >*/
            keywords::format = "[%TimeStamp%]<%Severity%>:\t%Message%"                     /*< log record format >*/
        );
        logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::debug);
        logging::add_console_log(std::cout, boost::log::keywords::format = "[%TimeStamp%][%Severity%]%Message%");

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

    struct C2LogCategoryDesc{
        C2Log::Flags flag;
        std::string category;
    };

    const std::map<std::string, C2Log::Flags> LogCategories =
    {
            {"0", C2Log::NONE},
            {"none", C2Log::NONE},
            {"pool", C2Log::POOL},
            {"coind", C2Log::COIND},
            {"coind_jsonrpc", C2Log::COIND_JSONRPC},
            {"sharetracker", C2Log::SHARETRACKER},
            {"db", C2Log::DB},
            {"other", C2Log::OTHER},
            {"p2p", C2Log::P2P},
            {"stratum", C2Log::STRATUM},
            {"1", C2Log::ALL},
            {"all", C2Log::ALL},
    };

    void Logger::add_category(const std::string &str)
    {
        if (str.empty())
        {
            instance->categories = C2Log::ALL;
            return;
        }

        if (LogCategories.find(str) == LogCategories.end())
            return;

        instance->categories |= LogCategories.at(str);
    }

    void Logger::remove_category(const std::string &str)
    {
        if (str.empty())
        {
            instance->categories = C2Log::NONE;
            return;
        }

        if (LogCategories.find(str) == LogCategories.end())
            return;

        instance->categories &= ~LogCategories.at(str);
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
}; // namespace C2Log
//std::ostream &operator<<(std::ostream &stream, std::vector<unsigned char> &data)