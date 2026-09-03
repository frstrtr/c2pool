// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_pool_node_compile — COMPILE + INSTANTIATION + LINK gate for the M3
// PR-A-cont2 sharechain NODE layer + the MINT path.
//
// This target compiles node.cpp + protocol_actual.cpp (as sources) so the
// namespace-copied sharechain node + the single-protocol v36-genesis bridge
// (bip110::pool::Node) and the c2pool protocol handler (Actual::handle_message)
// are fully built and linked. main() then:
//   (1) ODR-uses create_local_share<ShareTracker> — the MINT template — forcing
//       the whole mint body (Bip110SmallBlockHeaderType::from_full,
//       check_header_fail_closed, the abswork %2^64 wrap, SegwitDataDefault
//       populate, and the BLAKE2b compute_share_hash header-identity delta) to
//       instantiate.
//   (2) constructs the config-seam adapter (bip110::pool::Config), exercising the
//       PoolConfigRuntime prefix-from-SSOT derivation and confirming the empty-seed
//       bootstrap ladder (no PublicDefault arm).
//   (3) ODR-uses Node::handle + Actual::handle_message so the single-protocol
//       bridge + protocol bodies link.
// If this binary links, the PR-A-cont2 node + mint lane compiles end to end.

#include "../node.hpp"          // Node / Actual / NodeImpl / Config
#include "../share_check.hpp"   // create_local_share (mint path)

#include <boost/asio/io_context.hpp>
#include <cstdio>

using namespace bip110::pool;

int main()
{
    // (1) MINT: instantiate create_local_share against the ShareTracker. Taking its
    //     address instantiates the full template body — the from_full split, the
    //     fail-closed guard, the abswork %2^64 wrap, the SegwitDataDefault populate,
    //     and the compute_share_hash BLAKE2b block-identity delta.
    volatile auto mint = &create_local_share<ShareTracker>;
    (void)mint;

    // (2) Config seam: construct the runtime adapter. PoolConfigRuntime() derives
    //     m_prefix from the static PoolConfig SSOT (params.hpp SHARECHAIN_PREFIX_HEX)
    //     and leaves m_bootstrap_addrs EMPTY — the cross-pollution guard (decision
    //     #2: no PublicDefault arm, cannot dial 9333 / the live BTC sharechain).
    Config cfg;
    (void)&cfg;
    if (cfg.pool()->m_prefix.empty()) {
        std::fprintf(stderr, "bip110_pool_node_compile: FAIL — empty sharechain prefix\n");
        return 1;
    }
    if (!cfg.pool()->m_bootstrap_addrs.empty()) {
        std::fprintf(stderr, "bip110_pool_node_compile: FAIL — non-empty bootstrap seeds "
                             "(the empty-seed ladder / decision #2 guard is broken)\n");
        return 1;
    }
    (void)sharechain_net_name(cfg.m_regtest, cfg.m_testnet);

    // (3) Node + protocol: ODR-use the single-protocol bridge handle() and the
    //     c2pool protocol handler so their bodies compile and link.
    volatile auto node_handle = &Node::handle;
    (void)node_handle;
    volatile auto actual_handle = &Actual::handle_message;
    (void)actual_handle;

    std::printf("bip110_pool_node_compile: node + single-protocol bridge + Actual "
                "protocol + config adapter + create_local_share mint instantiated + "
                "linked OK\n");
    return 0;
}
