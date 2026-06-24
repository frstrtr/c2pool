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
// M3: the REAL shared-module includes that let bind_aux_doge_parsers() instantiate
// the structured AuxPoW parser with the DGB parent coinbase type. Pulling these in
// here (under AUX_DOGE only) is what ODR-USES the DGB-parent template emissions
// (parse_aux_header<dgb::coin::MutableTransaction> / CAuxPow<dgb::coin::Mutable-
// Transaction>) inside the PRODUCTION dgb object library, not merely in fixtures.
#include <functional>

#include <core/pack.hpp>                            // PackStream (the byte stream the parser reads)
#include <impl/doge/coin/auxpow.hpp>                // shared SSOT: CAuxPow<>, parse_aux_header<>, CPureBlockHeader
#include <impl/dgb/coin/transaction.hpp>            // dgb::coin::MutableTransaction (the DGB parent coinbase type)
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // doge::coin::parent_coinbase_no_witness<dgb::coin::MutableTransaction>
#endif

namespace dgb
{

namespace coin
{

#ifdef AUX_DOGE
// ---------------------------------------------------------------------------
// DOGE merged-mining aux seam (M3 body; -DAUX_DOGE=ON only). The DGB-as-parent
// structured AuxPoW parse contract, bound onto the production dgb object lib by
// bind_aux_doge_parsers(). The shared module's parser is templated on the parent
// coinbase type; here we pin it to dgb::coin::MutableTransaction so the DGB-parent
// CAuxPow<> / parse_aux_header<> template instantiations are emitted and ODR-used
// in production (not only in test fixtures). Parity: p2pool-merged-v36.
//
// AuxDogeParse: the result of feeding a (possibly AuxPoW-extended) DOGE header
// blob through the DGB-parent parser -- the 80-byte child header, the structured
// CAuxPow<dgb> proof, and whether an aux proof was present.
struct AuxDogeParse
{
    ::doge::coin::CPureBlockHeader                       m_header;    // 80-byte child header
    ::doge::coin::CAuxPow<dgb::coin::MutableTransaction> m_aux;       // structured DGB-parent proof
    bool                                                 m_has_aux{}; // AuxPoW version-bit present
};

// The bound parser callable: consumes bytes from a PackStream and yields the
// DGB-parent parse. std::function so bind_aux_doge_parsers() can ASSIGN it (real,
// callable binding -- never a no-op), forcing ODR-use of the templated parser.
using AuxDogeParserFn = std::function<AuxDogeParse(PackStream&)>;
#endif

template <typename ConfigType>
class Node : public dgb::interfaces::Node
{
    using config_t = ConfigType;

    config_t* m_config = nullptr;

    // Real io_context for the M3 NodeRPC transport (mirrors btc node.hpp).
    // rpc.hpp brings boost::asio in transitively; no extra include needed.
    boost::asio::io_context* m_context = nullptr;

    std::unique_ptr<NodeRPC> m_rpc;

public:
    Node(auto* context, auto* config) : m_config(config), m_context(context)
    {
    }

    void run()
    {
        // M3: real NodeRPC transport (external-daemon FALLBACK path that V36
        // mandates persist alongside the embedded daemon). Mirrors btc
        // node.hpp; testnet drives the chain-identity genesis probe in
        // NodeRPC::check(). connect() (transport bring-up) is driven by the
        // pool-layer seam once an RPC endpoint is configured.
        m_rpc = std::make_unique<NodeRPC>(m_context, this, m_config->m_testnet);
    }

    NodeRPC* rpc() { return m_rpc.get(); }

#ifdef AUX_DOGE
    // DOGE merged-mining aux seam (STRETCH; -DAUX_DOGE=ON only). The DGB-parent
    // structured AuxPoW parser, bound by bind_aux_doge_parsers(). Unbound until
    // bind is called. Parity: p2pool-merged-v36.
    AuxDogeParserFn m_aux_doge_parser;

    // Binds the shared src/impl/doge aux module's structured parser onto the dgb
    // node, pinned to the DGB parent coinbase type. The body is a genuine callable
    // binding (NOT a no-op): it assigns m_aux_doge_parser to a lambda that drives
    // bytes through doge::coin::parse_aux_header<dgb::coin::MutableTransaction>().
    // Inline (the class is templated; an out-of-line def would need explicit
    // instantiation) -- matches the existing inline run(). This is what ODR-USES /
    // emits the DGB-parent CAuxPow<> + parse_aux_header<> instantiations in the
    // production dgb object library. NodeP2P (not yet ported) will route relayed
    // DOGE headers through m_aux_doge_parser at M3 live-dispatch time.
    void bind_aux_doge_parsers()
    {
        m_aux_doge_parser = [](PackStream& s) -> AuxDogeParse {
            AuxDogeParse out;
            out.m_header = ::doge::coin::parse_aux_header<PackStream, dgb::coin::MutableTransaction>(
                s, out.m_aux, out.m_has_aux);
            return out;
        };
    }

    // Accessor for the bound parser (test surface + future NodeP2P dispatch).
    const AuxDogeParserFn& aux_doge_parser() const { return m_aux_doge_parser; }
#endif
};

} // namespace coin

} // namespace dgb
