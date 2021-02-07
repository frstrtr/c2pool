file(GLOB sources "*.h" "*.cpp")

add_library(devcore ${sources})
target_link_libraries(devcore Boost::log Boost::log_setup ${Python3_LIBRARIES} univalue)

target_compile_definitions(devcore PRIVATE RESOURCES_DIR=\"${CMAKE_SOURCE_DIR}\")