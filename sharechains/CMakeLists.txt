file(GLOB sources "*.h" "*.cpp")

add_library(sharechains ${sources})
target_link_libraries(sharechains PRIVATE devcore univalue)
#target_link_libraries(sharechains PRIVATE univalue networks devcore util)