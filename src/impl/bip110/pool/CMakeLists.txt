# BIP-110 (Bitcoin Knots BLAKE2b hard fork) — M3 v36 SHARECHAIN lane, PR-A.
#
# The v36 (decayed-PPLNS + P2SH donation + MergedMiningShare-family) sharechain
# lane. PR-A ships the FOUNDATION — the wire types, the ONE consensus delta
# (Bip110SmallBlockHeaderType + BLAKE2b share-hash identity), the fresh-identity
# constants + BTC-verbatim diff, the p2p message set, peer state, and the pure
# donation validators — as a header lane, plus the KILLER identity KAT. PR-B
# wires create_share_fn + pool::SharechainNode into main_bip110; the large
# mechanical namespace-copies (share_check / share_tracker / node / protocol)
# land in PR-A-continuation (see the PR's remaining-work map). Header-only lane:
# nothing to compile into a library yet (matches the coin lane's blake2b note),
# so the KAT is the compile+correctness gate.

# INTERFACE target so PR-B can `target_link_libraries(... bip110_pool)` to pick up
# the include surface + the shared/coin/sharechain deps the pool lane rides on.
add_library(bip110_pool INTERFACE)
target_include_directories(bip110_pool INTERFACE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(bip110_pool INTERFACE core sharechain pool bip110_coin btclibs)

# bip110_pool_identity_kat: proves the pool-lane header set COMPILES (forces the
# v36 share templates to instantiate) AND that the share-hash == block-identity
# path reproduces REAL BIP-110 block 961640's canonical hash byte-for-byte.
# Lean, isolated link set (blake2b.c compiled directly, like the M2 KATs).
# Lean, isolated link set (like the M2 bip110_blake2b_kat): compile only the
# minimal core sources the identity path needs (uint256 + the lane BLAKE2b
# primitive) rather than linking the full `core` OBJECT lib, which would drag in
# web_server/stratum and the whole pool/payout/merged runtime. The pool-lane
# headers (share_types/share_identity/share/config_pool) + coin/block.hpp are
# header-only template code, so no library link is required to prove they compile.
add_executable(bip110_pool_identity_kat
    test/bip110_pool_identity_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
    ${CMAKE_SOURCE_DIR}/src/core/uint256.cpp
)
target_compile_definitions(bip110_pool_identity_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_pool_identity_kat
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    Threads::Threads
)
add_test(NAME bip110_pool_identity_kat COMMAND bip110_pool_identity_kat)

# bip110_pool_sharechain_compile: the COMPILE + INSTANTIATION gate for the M3
# PR-A-continuation sharechain lane (share_check.hpp / share_tracker.hpp /
# share_messages.hpp + the tracker-coupled donation build_expected_payouts). It
# #includes share_tracker.hpp (which transitively pulls the whole verify surface)
# and ODR-uses verify_share<MergedMiningShare, ShareTracker> so every verify-path
# template — including the BLAKE2b header-hash consensus delta (compute_share_hash
# / check_header_fail_closed) and the v36 decayed-PPLNS walk — is fully compiled
# and linked. Unlike the identity KAT (deliberately lean), this target rides the
# same heavy shared/core/pool/sharechain link closure as c2pool-bip110, because
# the verify path uses core LOG / target_utils / address_utils, sharechain, the
# coin block/transaction types, and (via share_identity.hpp -> pow.hpp) BLAKE2b.
add_executable(bip110_pool_sharechain_compile
    test/bip110_pool_sharechain_compile.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_pool_sharechain_compile PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_pool_sharechain_compile
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
add_test(NAME bip110_pool_sharechain_compile COMMAND bip110_pool_sharechain_compile)

# bip110_pool_node_compile: the COMPILE + INSTANTIATION + LINK gate for the M3
# PR-A-cont2 sharechain NODE layer + MINT path. It builds node.cpp +
# protocol_actual.cpp (the namespace-copied sharechain node, the v36-genesis
# single-protocol bridge, and the c2pool protocol handler) AS SOURCES, and the
# test TU ODR-uses bip110::pool::Node / Actual::handle_message, constructs the
# config-seam adapter (bip110::pool::Config), and instantiates the MINT template
# create_local_share<ShareTracker> (from_full split + fail-closed + abswork %2^64
# + BLAKE2b compute_share_hash header-identity). Same heavy shared/core/pool/
# sharechain/storage link closure as bip110_pool_sharechain_compile because the
# node reaches SharechainStorage, ReplyMatcher, the tx-advertiser, the coin seed
# bootstrapper / template_other_txs, and (via share_identity.hpp -> pow.hpp)
# BLAKE2b. NO protocol_legacy.cpp and NO config_*.cpp — the v36-genesis lane has a
# single protocol and a header-only config adapter (no Fileconfig).
add_executable(bip110_pool_node_compile
    test/bip110_pool_node_compile.cpp
    node.cpp
    protocol_actual.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_pool_node_compile PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_pool_node_compile
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
add_test(NAME bip110_pool_node_compile COMMAND bip110_pool_node_compile)

# bip110_pool_mint_kat: the END-TO-END MINT known-answer test (PR-B). Unlike the
# node_compile KAT (which only takes create_local_share's address), this RUNS the
# mint against a ShareTracker, pulls the minted share back out, and asserts field
# round-trip (donation=66, abswork %2^64 wrap, segwit none-sentinel 2^256-1,
# coinbase last_txout_nonce) AND mint/verify BLAKE2b hash symmetry
# (compute_share_hash on the minted small-header reproduces the stored share hash).
# Same heavy shared/core/pool/sharechain/storage link closure as
# bip110_pool_sharechain_compile (the mint reaches the whole verify surface +
# BLAKE2b via share_identity.hpp -> pow.hpp). blake2b.c compiled directly.
add_executable(bip110_pool_mint_kat
    test/bip110_pool_mint_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_pool_mint_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_pool_mint_kat
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
add_test(NAME bip110_pool_mint_kat COMMAND bip110_pool_mint_kat)

# bip110_extend_mint_kat: the F2 EXTEND-OFF-REAL-TIP + PEER ref/coinbase-consistency
# KAT (M3 PR-C). Where the genesis mint_kat proves mint/verify SYMMETRY with a fake
# coinbase, THIS KAT seeds a real tip, mints a share EXTENDING it (has_frozen=TRUE,
# absheight==2), and proves the coinbase carries a REAL ref commitment that a PEER
# recomputes off the STORED share fields byte-for-byte (compute_ref_hash_for_work)
# and then reconstructs the exact share hash via the share_check verify path
# (check_hash_link -> check_merkle_link -> compute_share_hash) — i.e. peers ACCEPT
# the minted share (the F1 wire failure is closed). Same heavy link closure as the
# mint_kat (create_local_share + assemble_gentx_coinbase + the verify surface +
# BLAKE2b via share_identity.hpp -> pow.hpp). blake2b.c compiled directly.
add_executable(bip110_extend_mint_kat
    test/bip110_extend_mint_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_extend_mint_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_extend_mint_kat
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
add_test(NAME bip110_extend_mint_kat COMMAND bip110_extend_mint_kat)

# bip110_multiminer_pplns_kat: the F1b PPLNS-DISTRIBUTED-COINBASE KAT (M3 PR-C).
# Where the extend_mint_kat proved the ref/hash_link half of peer acceptance with a
# SINGLE-MINER coinbase (and its create_local_share log SHOWS the remaining gap:
# "Cross-check FAILED! mined_gentx=<single-miner> verify_gentx=<PPLNS>"), THIS KAT
# seeds a real 2-share window (miner A <- miner B), builds the FLAG-ON coinbase the
# way build_connection_coinbase now does (get_expected_payouts -> sorted/capped
# outputs + P2POOL witness commitment + donation second-to-last + OP_RETURN ref),
# mints the extend share, and asserts generate_share_transaction == that coinbase
# byte-for-byte — i.e. the Cross-check now PASSES and peers ACCEPT the share. Same
# heavy link closure as the extend_mint_kat. blake2b.c compiled directly.
add_executable(bip110_multiminer_pplns_kat
    test/bip110_multiminer_pplns_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_multiminer_pplns_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_multiminer_pplns_kat
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
add_test(NAME bip110_multiminer_pplns_kat COMMAND bip110_multiminer_pplns_kat)

# bip110_serve_xcheck_kat: the SERVE-PATH pre-serve reward-safety XCHECK KAT (M3).
# The other bip110 KATs exercise the MINT / consensus math; NONE exercised the live
# SERVE template + the [BIP110-WS] pre-serve reward-safety XCHECK that build_
# connection_coinbase runs before serving a job. That gap hid a flag-ON regression
# caught LIVE on contabo (every notify: "XCHECK FAILED — refusing to serve populated
# template ... job suppressed" => NO work served with --bip110-sharechain ON). Root
# cause: XCHECK sub-check (e) recomputed the coinbase witness commitment with a
# HARDCODED 32-zero reserved value, so it rejected the flag-ON coinbase whose
# commitment is over the P2Pool reserved value '[P2Pool]'*4 (a valid, consensus-
# required construction). THIS KAT drives the production SSOT bip110::stratum::
# xcheck_witness_commitment (serve_xcheck.hpp) against the production mint-side
# compute_p2pool_witness_commitment (share_check.hpp) and asserts the flag-ON serve
# template PASSES, the OFF/M2 path is unchanged, and the check is NOT weakened
# (wrong-reserved / tampered commitments still fail). Same link set as the pplns KAT.
add_executable(bip110_serve_xcheck_kat
    test/bip110_serve_xcheck_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_serve_xcheck_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_serve_xcheck_kat
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
add_test(NAME bip110_serve_xcheck_kat COMMAND bip110_serve_xcheck_kat)

# bip110_local_mint_verify_kat: FINDING A / #941 red->green. Mints a share against
# a ShareTracker and asserts the pre-fix bug (create_local_share alone leaves
# verified_size==0 and never fires the persist callback) then the fix
# (mark_own_share_verified marks it verified + fires persist, idempotently). Same
# lean ShareTracker link closure as bip110_pool_mint_kat (no node.cpp needed).
add_executable(bip110_local_mint_verify_kat
    test/bip110_local_mint_verify_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_local_mint_verify_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_local_mint_verify_kat
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
add_test(NAME bip110_local_mint_verify_kat COMMAND bip110_local_mint_verify_kat)

# bip110_persistence_roundtrip_kat: FINDING C round-trip. Drives a REAL NodeImpl
# over an isolated LevelDB dir: mint N (<50) shares -> verify_and_persist each ->
# shutdown() -> destroy -> reopen -> load_persisted_shares must reload them
# (chain_size>0). Same heavy node.cpp + protocol_actual.cpp + storage link
# closure as bip110_pool_node_compile.
add_executable(bip110_persistence_roundtrip_kat
    test/bip110_persistence_roundtrip_kat.cpp
    node.cpp
    protocol_actual.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
target_compile_definitions(bip110_persistence_roundtrip_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_persistence_roundtrip_kat
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
add_test(NAME bip110_persistence_roundtrip_kat COMMAND bip110_persistence_roundtrip_kat)

# bip110_dial_lifetime_guard_kat: CORE dial/accept-teardown UAF guard mechanism
# (successor to the e527abfe esft-primitive KAT that passed while the fix
# no-opped). Drives REAL core::Factory-derived nodes in BOTH shapes that broke
# esft — single inheritance (coin NodeP2P) and a virtual-inheritance diamond
# (pool Node) — and asserts set_lifetime ARMS the explicit strong-ref guard,
# that the pre-fix skip is reproducible, and that a redial-freed node stays alive
# for make_socket's dynamic_cast. Links against core for factory/socket/INetwork.
add_executable(bip110_dial_lifetime_guard_kat
    test/bip110_dial_lifetime_guard_kat.cpp
)
target_compile_definitions(bip110_dial_lifetime_guard_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_dial_lifetime_guard_kat
    core
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    Threads::Threads
)
add_test(NAME bip110_dial_lifetime_guard_kat COMMAND bip110_dial_lifetime_guard_kat)
