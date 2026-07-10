// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch coinbase KAT -- full-coinbase byte-vector vs oracle ground-truth
// (DGB<->BCH pairing, slice 2; the byte-vector half promised by slice 1s
//  coinbase_kat_segwit_predicate_test.cpp "follow sub-slice").
//
// Slice 1 pinned the gated-segwit PREDICATE (is_segwit_activated == false for
// every BCH share version -> no witness-commitment vout). This slice pins the
// SERIALIZED BYTES of a full BCH coinbase transaction against ground-truth
// produced by the p2poolBCH reference packer (util/pack.py, the SAME oracle the
// share/PPLNS conformance sweep used). A drift in field order, length-prefix
// encoding, int endianness, or an accidental SegWit marker/flag byte fails here.
//
// >>> ORACLE GROUND-TRUTH PROVENANCE <<<
// The expected hex below was emitted by p2pool/util/pack.py`s tx_id_type --
// reconstructed VERBATIM from p2pool/bitcoin/data.py:133-138 (version IntType(32)
// | ListType(tx_in) | ListType(tx_out) | lock_time IntType(32)) -- run over this
// fixed coinbase:
//   version   = 1
//   tx_in[0]  : previous_output = None  (coinbase null prevout: hash=0,
//               index=0xffffffff, via PossiblyNoneType default), sequence = None
//               (0xffffffff), script = 03a0950e 2f6332706f6f6c2f
//               (BIP34 PUSH3 height=955808 LE || "/c2pool/")
//   tx_out[0] : value = 1250000000 (sat), script = 76a914<20-byte ripemd>88ac
//   lock_time = 0
// All emitted bytes pass through the genuine oracle StructType/VarStrType/
// ListType/ComposedType/PossiblyNoneType code; only mechanical py2->py3
// substitutions (iteritems->items, xrange->range) were applied, none of which
// alter output bytes. The BCH legacy (no-SegWit) tx format == Bitcoins
// pre-SegWit tx_id serialization, so this vector doubles as a no-witness pin.
//
// p2pool-merged-v36 surface: NONE (pins a serialization invariant, adds no wire
// field). per-coin isolation: src/impl/bch/ only. Over coin/transaction.hpp +
// core/pack.hpp -- no peer, socket, or live coin lib.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <core/pack.hpp>
#include "../coin/transaction.hpp"

using bch::coin::MutableTransaction;
using bch::coin::TxIn;
using bch::coin::TxOut;


// p2poolBCH util/pack.py tx_id_type ground-truth (see provenance banner).
static const std::string ORACLE_COINBASE_HEX =
    "01000000"                                            // version = 1 (LE32)
    "01"                                                  // 1 tx_in (CompactSize)
    "0000000000000000000000000000000000000000000000000000000000000000" // null prevout hash
    "ffffffff"                                            // prevout index = 0xffffffff
    "0c" "03a0950e2f6332706f6f6c2f"                       // scriptSig (12 bytes)
    "ffffffff"                                            // sequence = 0xffffffff
    "01"                                                  // 1 tx_out (CompactSize)
    "807c814a00000000"                                    // value = 1250000000 (LE64)
    "19" "76a91400112233445566778899aabbccddeeff0011223388ac" // scriptPubKey (25 bytes)
    "00000000";                                           // lock_time = 0

static std::vector<unsigned char> from_hex(const std::string& h)
{
    std::vector<unsigned char> out;
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

static std::string to_hex(std::span<std::byte> sp)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(sp.size() * 2);
    for (std::byte b : sp) {
        auto v = static_cast<unsigned>(b);
        s.push_back(d[(v >> 4) & 0xf]);
        s.push_back(d[v & 0xf]);
    }
    return s;
}

int main()
{
    // Rebuild EXACTLY the coinbase the oracle packed.
    const auto cb_script  = from_hex("03a0950e2f6332706f6f6c2f");
    const auto out_script = from_hex("76a91400112233445566778899aabbccddeeff0011223388ac");

    TxIn vin;
    vin.prevout.hash  = uint256{};        // null prevout: 32 zero bytes
    vin.prevout.index = 0xffffffffu;      // coinbase marker
    vin.scriptSig     = OPScript(cb_script.data(), cb_script.data() + cb_script.size());
    vin.sequence      = 0xffffffffu;

    TxOut vout;
    vout.value        = 1250000000;
    vout.scriptPubKey = OPScript(out_script.data(), out_script.data() + out_script.size());

    MutableTransaction tx;
    tx.version  = 1;                       // match the oracle vector (not CURRENT_VERSION)
    tx.locktime = 0;
    tx.vin.push_back(vin);
    tx.vout.push_back(vout);

    PackStream ss;
    ss << tx;
    const std::string got = to_hex(ss.get_span());

    if (got != ORACLE_COINBASE_HEX) {
        std::cerr << "bch coinbase-KAT byte-vector MISMATCH vs oracle\n"
                  << "  oracle: " << ORACLE_COINBASE_HEX << "\n"
                  << "  bch   : " << got << "\n";
        return 1;
    }

    // No SegWit marker/flag (0x00 0x01) must EVER appear after the 4-byte version
    // -- that is the byte-level corollary of slice 1`s is_segwit_activated==false.
    assert(got.substr(8, 4) != "0001"
           && "BCH coinbase must carry no SegWit marker/flag (legacy format only)");

    std::cout << "bch coinbase-KAT byte-vector: OK ("
              << (got.size() / 2) << " bytes match p2poolBCH util/pack ground-truth; "
              << "legacy no-SegWit serialization)\n";
    return 0;
}