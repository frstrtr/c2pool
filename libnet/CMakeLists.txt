file(GLOB sources "*.h" "*.cpp")

add_library(libnet ${sources})

target_link_libraries(libnet PRIVATE univalue networks devcore util sharechains coind_jsonrpc)