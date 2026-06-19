// ---------------------------------------------------------------------------
// bch coinbase KAT -- gated-segwit predicate pin (DGB<->BCH pairing, slice 1).
//
// The DGB<->BCH coinbase-byte KAT pairing (integrator PR #171 DGB side; this is
// the SEPARATE BCH-lane PR per the per-coin isolation invariant) has ONE real
// divergence between the two SHA256d coinbases: the SegWit-commitment output
// the builder gates on `is_segwit_activated(version)` at serialize time.
//
//   - DGB (SegWit active): the gate is TRUE for share versions >= its
//     SEGWIT_ACTIVATION_VERSION, so the coinbase carries the witness-commitment
//     vout (OP_RETURN 0x6a24aa21a9ed || commitment).
//   - BCH (SegWit rejected at the 2017 fork): the oracle p2poolBCH derives the
//     gate from getattr(net,"SEGWIT_ACTIVATION_VERSION",0) (data.py:63-66); the
//     bitcoincash[_testnet].py nets define NO such attribute -> default 0 ->
//     the gate is FALSE for EVERY version -> NO witness-commitment vout is ever
//     emitted, and segwit_data is never present in a BCH share.
//
// This slice pins exactly that predicate: across the full v17..v36 share-version
// range, bch::is_segwit_activated MUST be false, matching the oracle's
// default-0 guard. A regression that re-introduces a non-zero
// SEGWIT_ACTIVATION_VERSION (the old stray-17 BTC/LTC port that forced
// segwit_data on for v17..v35 -> sharechain fork; see share_types.hpp) fails
// here. The byte-vector half of the KAT (full coinbase vs oracle ground-truth
// from p2poolBCH util/pack) is the follow sub-slice.
//
// p2pool-merged-v36 surface: NONE (pins a conformance invariant, adds no wire
// field). per-coin isolation: src/impl/bch/ only. Header-only over
// share_types.hpp -- no peer, socket, or coin lib.
// ---------------------------------------------------------------------------

#include <cassert>
#include <iostream>

#include "../share_types.hpp"

int main()
{
    // The sentinel itself must stay disabled (== 0), reproducing the oracle
    // getattr(net,"SEGWIT_ACTIVATION_VERSION",0) default for the BCH nets.
    assert(bch::SEGWIT_ACTIVATION_VERSION == 0
           && "BCH must keep SEGWIT_ACTIVATION_VERSION disabled (oracle default 0)");

    // The predicate must be FALSE for every share version BCH ships -- the full
    // v17..v36 span and a few sentinels around the boundaries. There is no
    // version at which a BCH coinbase emits the witness-commitment vout.
    for (uint64_t ver = 0; ver <= 64; ++ver)
    {
        assert(!bch::is_segwit_activated(ver)
               && "BCH gated-segwit predicate must be OFF at every share version");
    }

    // Spot-check the versions that actually matter on the sharechain: the
    // legacy floor (17), the field-order transition versions, and v36.
    for (uint64_t ver : {uint64_t(17), uint64_t(33), uint64_t(34),
                         uint64_t(35), uint64_t(36)})
    {
        assert(!bch::is_segwit_activated(ver));
    }

    std::cout << "bch coinbase-KAT segwit-predicate pin: OK "
              << "(is_segwit_activated == false for all versions; "
              << "no witness-commitment vout on any BCH coinbase)\n";
    return 0;
}
