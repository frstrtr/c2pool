cmake_minimum_required(VERSION 3.16.1)
set(CMAKE_CXX_STANDARD 20)

add_definitions(-DSOME_IMPORTANT_DEFINITION)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")


set(PROJ_NAME c2pool)
project(${PROJ_NAME})

#c2pool variables
set(MAIN_FILE src/${PROJ_NAME}.cpp)
set(SOURCE_FILES 
    src/config.h src/config.cpp
    src/network.h src/network.cpp
)

set(Boost_USE_STATIC_LIBS ON)

find_package(Boost 1.71.0 COMPONENTS program_options REQUIRED)
set(PROJECT_LIB ${PROJECT_LIB} ${Boost_LOG_LIBRARY} ${Boost_LOG_SETUP_LIBRARY})
include_directories(${Boost_INCLUDE_DIRS})

if(Boost_FOUND)
	MESSAGE( STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}.")
    MESSAGE( STATUS "Boost_LIBRARIES = ${BOOST_LIBRARYDIR}.")
    MESSAGE( STATUS "Boost_LIB_VERSION = ${Boost_LIB_VERSION}.")
endif()

include_directories(src)
add_subdirectory(src)
link_directories(src)

add_executable(${PROJ_NAME} ${MAIN_FILE})
target_sources(${PROJ_NAME} PUBLIC ${SOURCE_FILES})

add_subdirectory(lib/googletest)

target_link_libraries(${PROJ_NAME} Boost::program_options)
