project(other)

set(HEADER_FILES other.h console.h)
set(SOURCE_FILES converter.cpp other.cpp console.cpp)


set(Boost_USE_STATIC_LIBS ON)

find_package(Boost 1.74.0 REQUIRED COMPONENTS log log_setup)

add_library(other STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(other Boost::log_setup Boost::log)
# set(PROJECT_LIB ${PROJECT_LIB} ${Boost_LOG_LIBRARY} ${Boost_LOG_SETUP_LIBRARY})
# target_link_libraries(other -Wl,--start-group  ${PROJECT_LIB} -Wl,--end-group)

if(WIN32)
    target_link_libraries(other ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(other wsock32) #возник баг, без этого не компилится boost код.
endif()
