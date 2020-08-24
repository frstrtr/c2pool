cmake_minimum_required(VERSION 3.18.1)
project(cpool)

set(CMAKE_CXX_STANDARD 20)

#c2pool variables
set(SOURCE_FILE src/main.cpp)
#c2pool LIBS

set(UTILS src/util)
set(P2P src/p2p)
set(NETWORKS src/networks)
set(OTHER src/other)
set(UNIVALUE src/univalue)
#set(CRYPTO src/crypto)  #todo
set(c2pool_dirs ${UTILS} ${P2P} ${NETWORKS} ${OTHER})
set(c2pool_libs util p2p networks other univalue)

#BOOST
# ADD_DEFINITIONS(-DBoost_NO_BOOST_CMAKE=ON)

#set(BOOST_LOG_DYN_LINK ON)
set(Boost_USE_STATIC_LIBS ON)

set(Boost_DEBUG ON)
set(Boost_VERBOSE ON)
set(Boost_USE_DEBUG_LIBS         ON) # ignore debug libs and
# set(Boost_USE_RELEASE_LIBS       ON)  # only find release libs
# set(Boost_USE_MULTITHREADED      ON)
# set(Boost_USE_STATIC_RUNTIME    OFF)
find_package(Boost 1.74.0 COMPONENTS log log_setup REQUIRED)
set(PROJECT_LIB ${PROJECT_LIB} ${Boost_LOG_LIBRARY} ${Boost_LOG_SETUP_LIBRARY})
#find_package(Boost 1.74.0 REQUIRED)
# find_package(Boost 1.74.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

if(Boost_FOUND)
	MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()
    

# find_library(loglib libboost_log.a C:\Program Files\boost\boost_1_72_0)
# target_link_libraries(Boost::log INTERFACE ${loglib})

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
target_link_libraries(cpool -Wl,--start-group  ${PROJECT_LIB} -Wl,--end-group)
# target_link_libraries(cpool ${Boost_LIBRARIES})
target_link_libraries(cpool Boost::log_setup Boost::log)
target_link_libraries(cpool ${c2pool_libs})