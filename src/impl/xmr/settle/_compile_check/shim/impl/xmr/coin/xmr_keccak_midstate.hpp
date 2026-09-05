// COMPILE-CHECK SHIM ONLY -- not a deliverable. Minimal KeccakMidstate stand-in
// (real one wraps the vendored monero-project keccak). finalize_copy() returns a
// zeroed digest here; the exact-sum/allocation logic under test uses no hashing.
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "xmr_crypto_types.hpp"

namespace xmr { namespace coin {

class KeccakMidstate {
public:
    KeccakMidstate() = default;
    void absorb(const void*, std::size_t) {}
    void absorb(const std::vector<unsigned char>&) {}
    Hash256 finalize_copy() const { return Hash256{}; }
};

}} // namespace xmr::coin
