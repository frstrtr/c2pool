file(GLOB sources "*.h" "*.cpp")

find_library(dl NAMES dl)

add_library(devcore ${sources})
target_link_libraries(devcore Boost::log Boost::log_setup ${Python3_LIBRARIES} univalue ${dl} util)

target_compile_definitions(devcore PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")