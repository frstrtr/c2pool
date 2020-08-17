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
    class Logger
    {
    private:
        static Logger *instance;

        static boost::log::sources::severity_logger<boost::log::trivial::severity_level> lg;


        Logger();

    public:
        static void Init();

        static Logger* log();

        template <typename T>
        static Logger &Trace(T var){
            BOOST_LOG_SEV(lg, boost::log::trivial::trace) << "TEST" << "TEST" << 1 << "TEST" << var;
            return *instance;
        }
        
    };
} // namespace c2pool::console