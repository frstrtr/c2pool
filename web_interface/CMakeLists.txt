
set (METRICS metrics/metric.h metrics/metric_macro_scope.h metrics/metric_sum.h metrics/metric.h metrics/metric_value.h metrics/metric_rate.h metrics/metric_getter.h metrics/metric_param_getter.h metrics.hpp)
set (WEBLIB netdatafield.h webroot.cpp webroot.h#[[web_interface.h]] webnode.cpp webnode.h response_sender.h webserver.h webexcept.h session_interface.h response_sender.cpp)

add_library(web_interface STATIC ${METRICS} ${WEBLIB})
target_link_libraries(web_interface PRIVATE nlohmann_json::nlohmann_json)