#pragma once
// BCH header-chain validation. Mirrors src/impl/btc/coin/header_chain.hpp.
//
// >>> ASERT INSERTION POINT (M1 §4.3) <<<
// BCH uses ASERT (aserti3-2d) difficulty adjustment since the Nov 2020
// upgrade, NOT BTC retarget. Net-new c2pool code (one of two BCH-specific
// validation slices). TODO(M3): port aserti3-2d target calc + anchor block.
namespace c2pool::bch { /* TODO(M3): HeaderChain w/ ASERT validate_target() */ }
