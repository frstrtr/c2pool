// NMC coin P0 structural-leaf smoke translation unit.
//
// Header-only NMC coin types (block.hpp, header_chain.hpp) are otherwise never
// instantiated in a .cpp, so they would not be compile-checked by the build.
// This TU forces instantiation of the P0 structural leaf so CMake's nmc_coin
// target actually compiles header_chain.hpp (and its AuxPow / HeaderChain
// skeleton). It does NOT perform any validation — consistent with the P0 fence.

#include "header_chain.hpp"
#include "block.hpp"

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
}

} // namespace coin
} // namespace nmc
