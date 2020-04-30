cmake_minimum_required(VERSION 3.15)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

#c2pool variables
set(SOURCE_FILE src/main.cpp)
#c2pool LIBS

set(UTILS src/util)
set(P2P src/p2p)
set(NETWORKS src/networks)
set(OTHER src/other)
#set(CRYPTO src/crypto)  #todo
set(c2pool_dirs ${UTILS} ${P2P} ${NETWORKS} ${OTHER})
set(c2pool_libs util p2p networks other)

#BOOST
FIND_PACKAGE(Boost 1.72.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})
#PYTHON


add_executable(cpool ${SOURCE_FILE})

include_directories(${c2pool_dirs})
foreach(subdir ${c2pool_dirs})
    add_subdirectory(${subdir})
endforeach()

add_subdirectory(lib/googletest)
add_subdirectory(test)

if(WIN32)
    target_link_libraries(cpool ws2_32) #возник баг, без этого не компилится boost код.
    target_link_libraries(cpool wsock32) #возник баг, без этого не компилится boost код.
endif()

target_compile_definitions(cpool PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")
target_link_libraries(cpool LINK_PUBLIC ${Boost_LIBRARIES})
target_link_libraries(cpool ${c2pool_libs})
#target_link_libraries(cpool ${UTILS})