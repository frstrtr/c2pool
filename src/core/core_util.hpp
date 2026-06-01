#pragma once

#include <cstdint>

namespace core
{

// Wall-clock seconds since the Unix epoch.
//
// Lives in the dependency-free core_util leaf so that the pool / ltc /
// c2pool libraries can reference it without linking the full core static
// library. Moving this single out-of-line symbol out of core breaks the
// core <-> {pool, ltc, c2pool} static-link cycle (V36 SCC gate).
uint32_t timestamp();

} // namespace core
