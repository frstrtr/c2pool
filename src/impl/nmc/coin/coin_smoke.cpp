// NMC coin P0 structural-leaf smoke translation unit.
//
// Header-only NMC coin types (block.hpp, header_chain.hpp) are otherwise never
// instantiated in a .cpp, so they would not be compile-checked by the build.
// This TU forces instantiation of the P0 structural leaf so CMake's nmc_coin
// target actually compiles header_chain.hpp (and its AuxPow / HeaderChain
// skeleton). It does NOT perform any validation — consistent with the P0 fence.

#include "header_chain.hpp"
#include "block.hpp"
#include "mempool.hpp"
#include "rpc_data.hpp"
#include "template_builder.hpp"
#include "chain_seeds.hpp"

namespace nmc {
namespace coin {

// Force template/inline instantiation of the structural leaf.
void nmc_coin_p0_smoke()
{
    NMCChainParams params = NMCChainParams::mainnet();
    HeaderChain chain(params);
    (void)chain.init();
    (void)chain.height();
    (void)chain.size();
    (void)chain.add_headers(std::vector<BlockHeaderType>{});

    BlockHeaderType header;
    header.SetNull();
    (void)block_hash(header);
    (void)pow_hash(header);

    AuxPow auxpow;
    auxpow.SetNull();
    // P0-DEFER stub must report NOT_IMPLEMENTED_P0.
    (void)auxpow.check_proof(uint256{}, params.aux_chain_id);

    AuxChain aux_slot;
    std::vector<AuxChain> aux_chains; // nmc-local list (fence #4)
    aux_chains.push_back(aux_slot);
    (void)aux_chains;

    // P1 PC: force-compile the embedded template builder + work-data types.
    Mempool pool;
    (void)pool.size();
    (void)get_block_subsidy(0u);
    (void)compute_merkle_root(std::vector<uint256>{});
    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/false);
    (void)wd;  // nullopt on an empty chain -- structural compile-check only
    EmbeddedCoinNode node(chain, pool, /*testnet=*/false);
    (void)node.getblockchaininfo();
    (void)node.is_synced();

    // P1 PE 2a: force-compile embedded NMC seed tables (DNS + fixed).
    (void)nmc_dns_seeds(false);
    (void)nmc_fixed_seeds(false);
    (void)nmc_dns_seeds(true);
    (void)nmc_fixed_seeds(true);
}

} // namespace coin
} // namespace nmc
