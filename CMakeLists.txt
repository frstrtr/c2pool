cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)
project(c2pool)

#check lib's
if (NOT EXISTS ${CMAKE_SOURCE_DIR}/lib/googletest/.git OR NOT EXISTS ${CMAKE_SOURCE_DIR}/lib/leveldb/.git OR NOT EXISTS ${CMAKE_SOURCE_DIR}/lib/univalue/.git)
    message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init")
endif()

#init packages
set(Boost_USE_STATIC_LIBS ON)

find_package(Boost 1.71.0 COMPONENTS program_options log REQUIRED)
#set(PROJECT_LIB ${PROJECT_LIB} ${Boost_LOG_LIBRARY})
if(Boost_FOUND)
	MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()
include_directories(${Boost_INCLUDE_DIRS})

find_package(Python3 REQUIRED Development) #cmake --help-module FindPython
message("
    PyLibs:
    Python3_INCLUDE_DIRS=${Python3_INCLUDE_DIRS}
    Python3_LIBRARIES=${Python3_LIBRARIES}
")
include_directories(${Python3_INCLUDE_DIRS})


add_subdirectory(lib)
#---------------

include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(btclibs)
add_subdirectory(coind)
add_subdirectory(dbshell)
add_subdirectory(logging)
add_subdirectory(networks)
add_subdirectory(other)
add_subdirectory(p2p)
add_subdirectory(pylib)
add_subdirectory(sharechain)
add_subdirectory(util)

add_subdirectory(c2pool)

#add_subdirectory(lib/googletest)
#add_subdirectory(test)