# dgb_coin -- DGB coin-layer library (Path A minimal-stub surface).
# Mirrors src/impl/btc/coin/CMakeLists.txt, listing only the files that exist
# at this milestone. NOT yet referenced by any add_subdirectory(): top-level
# registration of src/impl/dgb follows the ci-steward OBJECT-lib convention
# (see ../CMakeLists.txt); staged here so that wiring is a one-line flip.

set(dgb_coin_impl
    rpc_data.hpp
    rpc.hpp
    node.hpp
    coin_node.hpp coin_node.cpp
)

set(dgb_coin_interface
    node_interface.hpp
    header_chain.hpp
    template_builder.hpp
)

add_library(dgb_coin ${dgb_coin_interface} ${dgb_coin_impl})

target_link_libraries(dgb_coin core nlohmann_json::nlohmann_json)
