file(GLOB sources "*.h" "*.cpp")

add_library(sharechains ${sources} share_store.cpp share_store.h prefsum_share2.h generate_tx.h generate_tx.cpp
        tree_tracker/cluster.h tree_tracker/fork.h tree_tracker/tracker.h base_share_tracker.h tree_tracker/rules.h)
target_link_libraries(sharechains PRIVATE libdevcore networks univalue libcoind btclibs)
#target_link_libraries(sharechains PRIVATE univalue  devcore util)