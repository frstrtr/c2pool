file(GLOB sources "*.h" "*.cpp")

add_library(sharechains ${sources} share_store.cpp share_store.h)
target_link_libraries(sharechains PRIVATE libdevcore networks univalue libcoind btclibs)
#target_link_libraries(sharechains PRIVATE univalue  devcore util)