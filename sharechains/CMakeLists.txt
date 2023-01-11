file(GLOB sources "*.h" "*.cpp")

add_library(sharechains ${sources} share_store.cpp share_store.h prefsum_share2.h generate_tx.h generate_tx.cpp)
target_link_libraries(sharechains PRIVATE libdevcore networks univalue libcoind btclibs)
#target_link_libraries(sharechains PRIVATE univalue  devcore util)