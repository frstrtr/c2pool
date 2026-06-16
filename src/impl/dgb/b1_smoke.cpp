// DGB Phase B (B1) sharechain-verify surface — compile-gate translation unit.
//
// The B1 surface (share_types / share / share_tracker / share_check /
// share_messages / redistribute) is header-only at B1: each header passes
// g++ -std=c++20 -fsyntax-only individually, but nothing instantiates them
// inside a real translation unit, so a whole-target compile gate did not yet
// exist. This TU gives the dgb OBJECT lib one compilable source so the surface
// builds AS A UNIT (per-coin dgb smoke gate), turning header-graph breakage
// into a build failure instead of latent rot.
//
// ci-steward build-gate scaffolding (dgb-tree-only). REMOVE this file once the
// real dgb pool-layer translation units land (config_pool.cpp / node.cpp /
// protocol_actual.cpp / protocol_legacy.cpp, owned by dgb-scrypt-steward) and
// supply the OBJECT lib with genuine symbols.
#include "share_types.hpp"
#include "share.hpp"
#include "share_tracker.hpp"
#include "share_check.hpp"
#include "share_messages.hpp"
#include "redistribute.hpp"
