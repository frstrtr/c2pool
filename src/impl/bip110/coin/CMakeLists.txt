
set(bip110_coin_impl
    rpc_data.hpp
    rpc.hpp rpc.cpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp
    p2p_messages.hpp
    node.hpp
    coin_node.hpp coin_node.cpp
    broadcaster.hpp          # M3 PR-C2 NODE_BLAKE2B fan-out pool (header-only leaf)
    broadcaster_full.hpp     # M3 PR-C2 found-block keystone (header-only leaf)
)

set(bip110_coin_interface
    txidcache.hpp
    node_interface.hpp
    block.hpp
    transaction.hpp transaction.cpp
    header_chain.hpp
    mempool.hpp
    block_assembler.hpp
    sigops.hpp
    utxo_reorg.hpp
    template_builder.hpp
)


add_library(bip110_coin ${bip110_coin_interface} ${bip110_coin_impl})

target_link_libraries(bip110_coin core nlohmann_json::nlohmann_json)

# bip110_peer_discovery_kat: the Knots getaddr/addr-crawl peer-discovery port
# gate (M3). Exercises the zero-socket surface of the fix — the NODE_BLAKE2B addr
# fork filter + future-poison drop (filter_fork_addr_records), the NodeP2P getaddr
# flag + lifecycle seams, the Bip110Broadcaster fan-out target (> 1) + primary
# exclusion, addr -> bucketed addrman -> tried promotion, and the end-to-end
# "one oracle gossip bootstraps many fork dial targets" claim. Links bip110_coin
# (parse_net_error / Connection / the coin p2p symbols) + core (CoinAddrMan,
# netaddress, dns_seeder). Header-template code compiles in the TU.
add_executable(bip110_peer_discovery_kat
    test/bip110_peer_discovery_kat.cpp
)
target_compile_definitions(bip110_peer_discovery_kat PRIVATE __C2POOL_COIN_BIP110__=1)
# Same link closure as the sibling bip110 KATs: `core` transitively references
# c2pool_hashrate (stratum_server) / payout / storage, so link the proven set.
target_link_libraries(bip110_peer_discovery_kat
    bip110_coin
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    core
    ltc
    ltc_coin
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    Threads::Threads
)
add_test(NAME bip110_peer_discovery_kat COMMAND bip110_peer_discovery_kat)

# bip110_dial_lifetime_realnode_kat: the REAL-TYPE dial-teardown UAF gate
# (successor to the e527abfe guard whose StubNode KAT passed while the fix
# no-opped live). Drives the REAL bip110::coin::p2p::NodeP2P (the dominant
# crasher) through make_shared + set_lifetime, asserts the explicit strong-ref
# guard is genuinely ARMED on the real type, reproduces the unmanaged-skip
# failure mode, and simulates a start_p2p() redial to prove make_socket's
# dynamic_cast runs on a strong-ref-pinned (never freed) node. Same link
# closure as the sibling coin KAT.
add_executable(bip110_dial_lifetime_realnode_kat
    test/bip110_dial_lifetime_realnode_kat.cpp
)
target_compile_definitions(bip110_dial_lifetime_realnode_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_dial_lifetime_realnode_kat
    bip110_coin
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    core
    ltc
    ltc_coin
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    Threads::Threads
)
add_test(NAME bip110_dial_lifetime_realnode_kat COMMAND bip110_dial_lifetime_realnode_kat)
