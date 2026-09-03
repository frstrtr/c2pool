
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

# bip110_broadcaster_slot_lifetime_kat: the REAL fan-out SLOT dial-teardown UAF
# gate. v2 (the coin::Node::m_p2p fix) passed its realnode KAT yet the flag-ON
# canary STILL crash-looped via the Bip110Broadcaster fan-out pool, whose slots
# were unmanaged unique_ptr<NodeP2P> dialed WITHOUT set_lifetime and freed by the
# 30s prune_dead() tick under a still-pending dial. This KAT drives the REAL
# broadcaster: the default factory arming (make_shared + set_lifetime BEFORE
# connect), and a prune_dead() during a pending dial completion — asserting the
# slot survives the owner drop and make_socket's dynamic_cast runs on a live
# node. Same link closure as the sibling coin KAT.
add_executable(bip110_broadcaster_slot_lifetime_kat
    test/bip110_broadcaster_slot_lifetime_kat.cpp
)
target_compile_definitions(bip110_broadcaster_slot_lifetime_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_broadcaster_slot_lifetime_kat
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
add_test(NAME bip110_broadcaster_slot_lifetime_kat COMMAND bip110_broadcaster_slot_lifetime_kat)

# bip110_coin_subver_brand_kat: the outgoing coin-p2p user-agent BRAND gate.
# Pins that NodeP2P's outgoing version subver is the single named constant
# BIP110_COIN_SUBVER (branded BIP14 "/c2pool:0.1/bip110/"), that a serialized
# message_version embeds it as a length-prefixed var-string at the subver
# offset (the exact bytes a Knots/Core fork peer + crawler read as our UA), and
# that the version still advertises NODE_BLAKE2B — proving the identity change
# is display-only and cannot break the service-bit-gated handshake. Same link
# closure as the sibling coin KATs.
add_executable(bip110_coin_subver_brand_kat
    test/bip110_coin_subver_brand_kat.cpp
)
target_compile_definitions(bip110_coin_subver_brand_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_coin_subver_brand_kat
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
add_test(NAME bip110_coin_subver_brand_kat COMMAND bip110_coin_subver_brand_kat)

# bip110_inbound_listener_kat: the coin-p2p INBOUND accept path (:8333) gate.
# Drives the REAL InboundListener over a REAL loopback socket (reusing
# core::Server's accept + eb60bf4c strong-ref UAF guard, armed by set_lifetime
# BEFORE listen(), plus core::Socket framing on both sides). Proves: [A] loopback
# accept + full accepting-side handshake (peer version FIRST -> our branded
# version subver==BIP110_COIN_SUBVER + NODE_BLAKE2B + verack -> getaddr->addr),
# crash-free; [B] a non-fork dialer (no NODE_BLAKE2B) dropped pre-verack at the
# same gate as the outbound arm; [C] the MAX_INBOUND cap with drop-on-overflow.
# Same link closure as the sibling coin KATs.
add_executable(bip110_inbound_listener_kat
    test/bip110_inbound_listener_kat.cpp
)
target_compile_definitions(bip110_inbound_listener_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_inbound_listener_kat
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
add_test(NAME bip110_inbound_listener_kat COMMAND bip110_inbound_listener_kat)
