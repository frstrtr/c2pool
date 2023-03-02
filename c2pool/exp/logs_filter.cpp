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
namespace expr = boost::log::expressions;
namespace sinks = boost::log::sinks;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

// We define our own severity levels
enum severity_level
{
    normal,
    notification,
    warning,
    error,
    critical
};

enum Flag
{
    AA,
    BB,
    CC
};

bool is_true_tag(Flag flag)
{
    if (flag == Flag::AA)
        return true;
    if (flag == Flag::BB)
        return false;
    if (flag == Flag::CC)
        return true;

    return false;
}

#define LOG_DEBUG(TAG) \
            if (is_true_tag(TAG))           \
            BOOST_LOG_TRIVIAL(debug).stream() << "[" << #TAG << "]"                        \

#define LOG_DEBUG_AA \
    LOG_DEBUG(AA)

int main()
{
    src::severity_logger<severity_level> slg;
    logging::add_console_log(std::cout, boost::log::keywords::format = "[%TimeStamp%]<%Severity%>:\t%Message%");
    BOOST_LOG_TRIVIAL(debug) << "\033[31m" <<  "HELLO\033[0m"; // Yellow color
    BOOST_LOG_TRIVIAL(debug) << "HI2";
    LOG_DEBUG(Flag::AA) << " ASD";
    LOG_DEBUG_AA << "test AA";
}