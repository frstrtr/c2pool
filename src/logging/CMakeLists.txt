project(logging)

set(SOURCE console.cpp console.h)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.71.0 REQUIRED COMPONENTS log log_setup)

add_library(other STATIC ${SOURCE})
target_link_libraries(other Boost::log_setup Boost::log)

if(WIN32)
    target_link_libraries(other ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(other wsock32) #возник баг, без этого не компилится boost код.
endif()
