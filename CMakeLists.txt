cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fconcepts")

include("cmake/HunterGate.cmake")
HunterGate(
        URL "https://github.com/cpp-pm/hunter/archive/v0.23.297.tar.gz"
        SHA1 "3319fe6a3b08090df7df98dee75134d68e2ef5a3"
        #        LOCAL
)
SET(HUNTER_STATUS_DEBUG ON)

project(c2pool)

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
set(Boost_USE_STATIC_LIBS ON)

find_package(Boost 1.71.0 COMPONENTS program_options log log_setup coroutine REQUIRED)
if(Boost_FOUND)
	MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()
include_directories(${Boost_INCLUDE_DIRS})

set (CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_subdirectory(libs)
#---------------
include_directories(include/jsonrpccxx)
include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(btclibs)
add_subdirectory(networks)
add_subdirectory(libcoind)
add_subdirectory(sharechains) #ver. 2
add_subdirectory(libdevcore)
add_subdirectory(libnet)
add_subdirectory(libnet2)
add_subdirectory(libp2p)

add_subdirectory(c2pool)

#TESTS
add_subdirectory(test)