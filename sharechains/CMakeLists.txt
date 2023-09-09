#file(GLOB sources "*.h" "*.cpp")

set(sources base_share_tracker.h data.h data.cpp generate_tx.h generate_tx.cpp prefsum_weights.h prefsum_weights.cpp share.h share.cpp share_adapters.h share_adapters.cpp share_builder.h share_builder.cpp share_store.h share_store.cpp share_streams.h share_streams.cpp share_tracker.h share_tracker.cpp share_types.h share_types.cpp)
#set(sources ${sources} tracker.h tracker.cpp prefsum_share2.h)
MESSAGE(${sources})

add_library(sharechains STATIC ${sources}
        tree_tracker/cluster.h tree_tracker/fork.h tree_tracker/tracker.h base_share_tracker.h tree_tracker/rules.h)
target_link_libraries(sharechains PRIVATE libdevcore networks univalue libcoind btclibs)
#target_link_libraries(sharechains PRIVATE univalue  devcore util)