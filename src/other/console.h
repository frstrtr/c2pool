#include <iostream>

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