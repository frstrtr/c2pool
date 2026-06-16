#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::Node -- per-coin node owner (Path A minimal-stub). TRIMMED mirror
// of src/impl/btc/coin/node.hpp: owns the NodeRPC client and inherits the
// dgb::interfaces::Node shared-state surface (work variable + new_block
// event) that NodeRPC and the seam-side CoinNode bind against.
//
// Deliberately ABSENT until M3 (each needs a port dgb does not have yet):
//   - NodeP2P / p2p_connection (coin P2P block relay; btc's p2p_node.hpp)
//   - init_rpc() transport connect (NodeRPC is a stub with no transport)
//   - submit_block_p2p / send_getheaders / handshake surface
// The ctor keeps btc's (context, config) shape via auto params (no boost
// include needed in the stub) so M3 restores the body without re-typing
// construction sites.
//
// AuxPoW / merged-mining seam (V36 reality): DGB-Scrypt is a STANDALONE parent in
// the default build and validates Scrypt blocks ONLY -- there is no AuxPoW path in
// the default c2pool-dgb. Merged-mining is the DOGE-only stretch, compiled solely
// under -DAUX_DOGE=ON, where the shared src/impl/doge/coin/aux_* module (owned by
// ltc-doge; dgb CONSUMES, never modifies) supplies the AuxPoW header / raw-block
// parsers that the M3 NodeP2P will bind. The other four DGB algos (SHA256d, Skein,
// Qubit, Odocrypt) are accept-by-continuity / ignored in V36 -- never validated
// here. p2pool-merged-v36 parity preserved. Signature only below; body lands with
// NodeP2P at M3.
// ---------------------------------------------------------------------------

#include <memory>

#include "node_interface.hpp"
#include "rpc.hpp"

#ifdef AUX_DOGE
// DOGE merged-mining aux module (STRETCH; -DAUX_DOGE=ON only). dgb CONSUMES the
// shared aux types; ltc-doge owns and is the sole modifier of src/impl/doge/coin/aux_*.
// Forward declaration only at slice #3 -- the real
// <impl/doge/coin/aux_chain_embedded.hpp> include lands with the
// bind_aux_doge_parsers() body at M3.
namespace doge { namespace coin { class AuxChainEmbedded; } }
#endif

namespace dgb
{

namespace coin
{

#ifdef AUX_DOGE
// ---------------------------------------------------------------------------
// DOGE merged-mining aux seam -- header-only type alias (slice #3, option b per
// integrator UID-904). Names the shared src/impl/doge aux-module backend that
// bind_aux_doge_parsers() wires onto the (M3) coin P2P layer. No new TU; no
// effect on the default Scrypt-only standalone build (which never defines
// AUX_DOGE). The structured parsers consumed at M3 bind time are the free
// functions doge::coin::parse_doge_header / parse_doge_headers_message /
// parse_doge_block (auxpow_header.hpp). Parity: p2pool-merged-v36.
using AuxChainBackend = ::doge::coin::AuxChainEmbedded;   // IAuxChainBackend impl
#endif

template <typename ConfigType>
class Node : public dgb::interfaces::Node
{
    using config_t = ConfigType;

    config_t* m_config = nullptr;

    std::unique_ptr<NodeRPC> m_rpc;

public:
    Node(auto* /*context*/, auto* config) : m_config(config)
    {
    }

    void run()
    {
        // Stub NodeRPC: constructed so has-rpc presence wiring can be
        // exercised, but no transport connect until M3.
        m_rpc = std::make_unique<NodeRPC>(this);
    }

    NodeRPC* rpc() { return m_rpc.get(); }

#ifdef AUX_DOGE
    // DOGE merged-mining aux seam (STRETCH; -DAUX_DOGE=ON only). Binds the shared
    // src/impl/doge aux module's parsers onto the (M3) coin P2P layer. Declaration
    // only -- no body until NodeP2P is ported. Parity: p2pool-merged-v36.
    void bind_aux_doge_parsers();
#endif
};

} // namespace coin

} // namespace dgb
