
set(bip110_coin_impl
    rpc_data.hpp
    rpc.hpp rpc.cpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp
    p2p_messages.hpp
    local_addr.hpp           # self-address advertise + self-connect nonce (Knots net.cpp)
    inbound_listener.hpp     # coin-p2p INBOUND accept path (:8333)
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

# bip110_coin_reachability_kat: the SELF-ADDRESS ADVERTISEMENT gate (Knots net.cpp
# GetLocalAddress / SeenLocal / MaybeSendAddr + CConnman self-connect nonce). Pins
# the reachability fix that closes the live "listener up, zero inbound" defect:
# LocalAddrTable peer-echo scoring (routable-only, listen-port substitution) +
# --coin-externalip override; SelfNonceRegistry self-connect guard + bounded
# eviction; the outgoing version addr_from carrying OUR reachable addr (never the
# old 192.168.0.1); the self-addr push record (NODE_BLAKE2B+NODE_WITNESS); the
# getaddr reply now including our own address FIRST with the full service set; the
# addr-relay fresh-batch selection; and a compile-proof that both arms accept the
# shared tables. Zero-socket / deterministic. Same link closure as the siblings.
add_executable(bip110_coin_reachability_kat
    test/bip110_coin_reachability_kat.cpp
)
target_compile_definitions(bip110_coin_reachability_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_coin_reachability_kat
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
add_test(NAME bip110_coin_reachability_kat COMMAND bip110_coin_reachability_kat)

# bip110_explorer_getblock_kat: the explorer raw-block RETENTION + full-then-
# partial getblock SERVE gate (DASH #1460/#99 parity). Binds the SHIPPED
# primitives directly: core::coin::UTXOViewDB put/get/prune_raw_block (the
# bounded 288-body window the full_block subscriber writes) and bip110::coin::
# explorer_getblock_body / explorer_header_partial (hoisted verbatim out of the
# main_bip110 set_explorer_getblock_fn closure). Proves: [A] a retained in-window
# block serves the FULL body (tx array + size, no partial/unavailable/error);
# [B] a block below the window degrades to an honest HEADER PARTIAL (partial:true
# + named unavailable {tx,nTx,size,strippedsize,weight}, never a faked tx:[],
# never an "error" key that would drop the row, confirmations exact); [C] an
# in-window body-miss degrades identically; [D] prune keeps the window bounded to
# ~288 recent bodies (daemonless storage bound). Pure decode/store, network-free,
# reward-safe. Same link closure as the sibling coin KATs.
add_executable(bip110_explorer_getblock_kat
    test/bip110_explorer_getblock_kat.cpp
)
target_compile_definitions(bip110_explorer_getblock_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_explorer_getblock_kat
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
add_test(NAME bip110_explorer_getblock_kat COMMAND bip110_explorer_getblock_kat)

# bip110_explorer_retention_kat: drives the SHIPPED bip110::coin::retain_full_block
# seam (explorer_retention.hpp) — the exact function the live full_block subscriber
# calls to persist EVERY received full block into the bounded 288-body store.
# Locks down the live root cause: retention resolves the height by the BIP-110
# block IDENTITY (BLAKE2b at/after the v2 fork), NOT by SHA256d(header); a real v2
# post-fork block WRITES its body (put_raw_block, round-trips) and then serves a
# FULL getblock, while a SHA256d-keyed resolver (the pre-fix Hash() lookup) stores
# nothing. Also proves the prune window stays bounded to ~288. Pure store/decode,
# network-free, reward-safe. Same link closure as the sibling coin KATs.
add_executable(bip110_explorer_retention_kat
    test/bip110_explorer_retention_kat.cpp
    # The retention KAT drives a REAL v2 post-fork block, whose identity is the
    # BLAKE2b commitment hash — compile the lane-local primitive directly (same
    # pattern as the pool-lane BLAKE2b KATs).
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_explorer_retention_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_explorer_retention_kat
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
add_test(NAME bip110_explorer_retention_kat COMMAND bip110_explorer_retention_kat)
