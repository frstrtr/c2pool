
# bch::coin library — c2pool-bch coin module (V36). Mirrors src/impl/btc/coin.
# Built when -DCOIN_BCH=ON via the parent add_subdirectory(coin).
# BCH-specific: SHA256d (BTC PoW family), NO SegWit, CashTokens transparent,
# ABLA dynamic block-size, ASERT DAA. Embedded BCHN daemon body lives here.

set(bch_coin_impl
    rpc_data.hpp
    rpc.hpp rpc.cpp
    p2p_connection.hpp p2p_connection.cpp
    p2p_node.cpp p2p_node.hpp
    p2p_messages.hpp
    node.hpp
    coin_node.hpp coin_node.cpp
)

set(bch_coin_interface
    txidcache.hpp
    node_interface.hpp
    block.hpp
    transaction.hpp transaction.cpp
    header_chain.hpp
    mempool.hpp
    template_builder.hpp
)

# BCH-specific consensus + embedded-daemon headers (header-only at this slice).
set(bch_coin_bchn
    abla.hpp abla_block_feed.hpp abla_runtime.hpp abla_tracker.hpp
    asert.hpp softfork_check.hpp
    merkle.hpp cashaddr.hpp regtest_block.hpp
    header_sync.hpp block_download.hpp block_connector.hpp
    compact_blocks.hpp block_broadcast_guard.hpp
    bchn_anchor_record.hpp chain_seeds.hpp
    embedded_daemon.hpp
)

add_library(bch_coin ${bch_coin_interface} ${bch_coin_impl} ${bch_coin_bchn})

target_link_libraries(bch_coin core nlohmann_json::nlohmann_json)
