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

namespace c2pool::console
{
    Logger::Logger()
    {
        boost::log::add_file_log(
            /*< file name pattern >*/
            boost::log::keywords::file_name = "log_%N.log",
            /*< rotate files every 10 MiB... >*/
            boost::log::keywords::rotation_size = 10 * 1024 * 1024,
            /*< ...or at midnight >*/
            //boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(boost::date_time::weekdays::Monday),
            /*< log record format >*/
            boost::log::keywords::format = "[%TimeStamp%]: %Message%"
        );
        boost::log::core::get()->set_filter(
            boost::log::trivial::severity >= boost::log::trivial::info
        );
    }
    void Logger::Init()
    {
        if (!instance)
            instance = new Logger();
        else
            std::cout << "SECOND CONSOLE!" << std::endl; //TODO: out to file
    }

    Logger* Logger::log(){
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