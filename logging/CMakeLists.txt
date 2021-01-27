set(SOURCE console.cpp console.h)

add_library(logging STATIC ${SOURCE})
target_link_libraries(logging Boost::log)