#file(GLOB sources "*.h" "*.cpp")

set(sources 
        base_share_tracker.h 
        data.h data.cpp 
        generate_tx.h generate_tx.cpp 
        prefsum_weights.h 
        share.h share.cpp 
        share_adapters.h 
        share_builder.h 
        share_store.h 
        share_streams.h 
        share_tracker.h share_tracker.cpp 
        share_types.h

        base_share_tracker.h 
        tree_tracker/cluster.h 
        tree_tracker/fork.h 
        tree_tracker/tracker.h 
        tree_tracker/rules.h
)

add_library(sharechains STATIC ${sources})
target_link_libraries(sharechains PRIVATE libdevcore networks libcoind btclibs)