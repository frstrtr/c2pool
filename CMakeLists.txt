cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 17)
set(Boost_COMPILER mgw11)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -fconcepts -pthread -Wa,-mbig-obj")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
#add_compile_definitions(PUBLIC DEBUG=0)

if (WIN32)
    message("Windows FOUNDED")
    link_libraries(ws2_32 wsock32)
endif ()

option(HUNTER_STATUS_DEBUG ON)
include("cmake/Hunter/init.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.18.tar.gz"
    SHA1 "1292e4d661e1770d6d6ca08c12c07cf34a0bf718"
    LOCAL
)


project(c2pool)
message("START PROJECT")

message("BEFORE BOOST")
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
#hunter_add_package(Boost COMPONENTS program_options log coroutine)

#find_package(Boost 1.78.0 COMPONENTS program_options log coroutine REQUIRED)
find_package(Boost 1.78.0 COMPONENTS system program_options log coroutine REQUIRED)
if(Boost_FOUND)
    MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()
include_directories(${Boost_INCLUDE_DIRS})
message("AFTER BOOST")

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

hunter_add_package(leveldb)
find_package(leveldb CONFIG REQUIRED)

set (CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# If you only include this third party in PRIVATE source files, you do not need to install it
# when your main project gets installed.
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(include/json)
find_package(Threads REQUIRED)

add_subdirectory(libs)
#---------------
include_directories(libs/jsonrpccxx)
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