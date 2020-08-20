#include <iostream>
#include <console.h>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/setup/console.hpp>

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
            keywords::target = "logs",
            keywords::rotation_size = 10 * 1024 * 1024,                                   /*< rotate files every 10 MiB... >*/
            keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0), /*< ...or at midnight >*/
            keywords::format = "[%TimeStamp%]<%Severity%>: %Message%"                     /*< log record format >*/
        );
#ifdef DEBUG
        logging::core::get()->set_filter(
            logging::trivial::severity >= logging::trivial::trace);
#else
        logging::core::get()->set_filter(
            logging::trivial::severity >= logging::trivial::info);
#endif
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

// #include <iostream>

// #include <boost/log/core.hpp>
// #include <boost/log/trivial.hpp>
// #include <boost/log/expressions.hpp>
// #include <boost/log/sinks/text_file_backend.hpp>
// #include <boost/log/utility/setup/file.hpp>
// #include <boost/log/utility/setup/common_attributes.hpp>
// #include <boost/log/sources/severity_logger.hpp>
// #include <boost/log/sources/record_ostream.hpp>

// namespace c2pool::console
// {
//     class Logger
//     {
//     private:
//         static Logger *instance;

//         boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg;

//         Logger()
//         {
//             boost::log::add_file_log(
//                 /*< file name pattern >*/
//                 boost::log::keywords::file_name = "log_%N.log",
//                 /*< rotate files every 10 MiB... >*/
//                 boost::log::keywords::rotation_size = 10 * 1024 * 1024,
//                 /*< ...or at midnight >*/
//                 boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
//                 /*< log record format >*/
//                 boost::log::keywords::format = "[%TimeStamp%]: %Message%"
//             );

//             boost::log::core::get()->set_filter(
//                 boost::log::trivial::severity >= boost::log::trivial::info
//             );
//         }

//     public:
//         static void Init()
//         {
//             if (!instance)
//                 instance = new Logger();
//             else
//                 std::cout << "SECOND CONSOLE!" << std::endl; //TODO: out to file
//         }

//         static Logger* log(){
//             return instance;
//         }

//         template <typename T>
//         static Logger &Trace(T &var){
//             BOOST_LOG_SEV(lg, trace) << "TEST" << "TEST" << 1 << "TEST" << var;
//             return instance;
//         }

//     };
// } // namespace c2pool::console

//