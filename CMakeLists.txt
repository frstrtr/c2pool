cmake_minimum_required(VERSION 3.15)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

#c2pool variables
set(SOURCE_FILE src/main.cpp)
#c2pool LIBS
set(CPOOL_P2P src/p2p/factory.cpp src/p2p/factory.h src/p2p/protocol.cpp src/p2p/protocol.h src/p2p/node.cpp src/p2p/node.h)
set(CPOOL_CONFIGS src/networks/config.cpp)
add_library(SOURCE_LIBS ${CPOOL_P2P} ${CPOOL_CONFIGS})
set(UTILS src/util)
#BOOST
FIND_PACKAGE(Boost 1.72.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
#PYTHON
find_package(Python3 #[[Libs]] REQUIRED Development)

add_executable(cpool ${SOURCE_FILE})
target_link_libraries(cpool ${SOURCE_LIBS})


include_directories(${UTILS})

add_subdirectory(${UTILS})
add_subdirectory(lib/googletest)
add_subdirectory(test)

if(WIN32)
    target_link_libraries(cpool ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(cpool wsock32) #возник баг, без этого не компилится boost код.
endif()

target_compile_definitions(cpool PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(cpool LINK_PUBLIC ${Boost_LIBRARIES} )
#target_link_libraries(cpool ${UTILS})