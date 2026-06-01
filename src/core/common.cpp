#include "common.hpp"

// core::timestamp() moved to the dependency-free core_util leaf
// (src/core/core_util.cpp) to break the core<->{pool,ltc,c2pool}
// static-link cycle. This translation unit is intentionally minimal.
