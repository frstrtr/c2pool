cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 20)
if (NOT WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fconcepts")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 ")
endif ()

if (WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_WIN32_WINNT=0x0601 /EHsc")
endif ()
#add_compile_definitions(PUBLIC DEBUG=0)

#include("cmake/HunterGate.cmake")
#HunterGate(
#        URL "https://github.com/cpp-pm/hunter/archive/v0.24.18.tar.gz"
#        SHA1 "1292e4d661e1770d6d6ca08c12c07cf34a0bf718"
##        LOCAL
#)
#SET(HUNTER_STATUS_DEBUG ON)

project(c2pool)

#Version system BEGIN
file(READ "version.cfg" ver)

string(REGEX MATCH "C2POOL_MAJOR ([0-9]*)" _ ${ver})
set(ver_major ${CMAKE_MATCH_1})

string(REGEX MATCH "C2POOL_MINOR ([0-9]*)" _ ${ver})
set(ver_minor ${CMAKE_MATCH_1})

string(REGEX MATCH "C2POOL_PATCH ([0-9]*)" _ ${ver})
set(ver_patch ${CMAKE_MATCH_1})

message("version: ${ver_major}.${ver_minor}.${ver_patch}")
#Version system END

include_directories (${PROJECT_SOURCE_DIR})
include_directories (${PROJECT_BINARY_DIR})

#check lib's
find_package(Git QUIET)
if(GIT_FOUND) #AND EXISTS "${PROJECT_SOURCE_DIR}/.git/modules")
    # Update submodules as needed
    OPTION(GIT_SUBMODULE "Check submodules during build" ON)

    if(GIT_SUBMODULE)
        message(STATUS "Git submodules found - updating")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                RESULT_VARIABLE GIT_SUBMOD_RESULT
        )

        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "The command 'git submodule update --init --recursive' failed with ${GIT_SUBMOD_RESULT}, please checkout any existing submodules")
        endif()
    endif()
endif()


#init packages
set(Boost_DEBUG on)
set(Boost_USE_STATIC_LIBS ON)

find_package(Boost 1.78.0 COMPONENTS program_options log log_setup coroutine REQUIRED)
if(Boost_FOUND)
	MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()
include_directories(${Boost_INCLUDE_DIRS})

set (CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Qt6 CONFIG REQUIRED Core Network)
find_package(Qt6 CONFIG COMPONENTS Widgets Gui)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
#qt_standard_project_setup()

##hunter_add_package(crc32c)
#hunter_add_package(leveldb)
#find_package(leveldb REQUIRED)

# If you only include this third party in PRIVATE source files, you do not need to install it
# when your main project gets installed.
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(include/json)

add_subdirectory(libs)
#---------------
include_directories(include)
include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(btclibs)
add_subdirectory(web_interface)
add_subdirectory(networks)
add_subdirectory(libcoind)
add_subdirectory(sharechains) #ver. 2
add_subdirectory(libdevcore)
#add_subdirectory(libnet)
add_subdirectory(libnet2)
add_subdirectory(libp2p)

add_subdirectory(c2pool)

#TESTS
add_subdirectory(test)