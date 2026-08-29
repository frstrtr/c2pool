// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin CashTokens transparency KAT (CHIP-2022-02, May 2023).
//
// Pins the M1 §4 invariant that the embedded daemon carries CashToken txs
// UNCHANGED: the token prefix (0xef PREFIX_TOKEN) lives INSIDE the
// CompactSize-length-prefixed TxOut scriptPubKey region, so the SHA256d tx
// serializer treats it as opaque locking bytecode -- NO token-aware parsing,
// NO field rewrite. This is the byte-level corollary of transaction.hpp:19-22
// ("round-trips transparently through OPScript") and template_builder.hpp:11
// ("they live in the tx bytes and round-trip unchanged"), which until now were
// asserted only by comment.
//
// Asserts:
//   1. A token-prefixed scriptPubKey serializes as <CompactSize len><blob>,
//      the length == the WHOLE blob (token prefix + locking bytecode), proving
//      the 0xef prefix gets no special-casing.
//   2. The exact token-prefix bytes (0xef || category || bitfield || amount)
//      appear VERBATIM in the serialized tx -- nothing stripped or reordered.
//   3. Full deserialize -> re-serialize is byte-identical (lossless round-trip),
//      so a relayed CashToken tx re-emits into the block template unchanged.
//   4. Mutating one token-prefix byte changes the serialized bytes (the token
//      data is bound into the tx_id pre-image -- relevant for CTOR ordering and
//      the merkle-root accept gate; tokens are not invisible to consensus).
//
// The vector is a representative CHIP-2022-02 FUNGIBLE-only token output; this
// test pins SERIALIZATION TRANSPARENCY, not token validity (consensus token
// rules live in the vendored BCHN slice, not here).
//
// p2pool-merged-v36 surface: NONE (BCH-internal consensus; adds no wire field).
// per-coin isolation: src/impl/bch/ only. Over coin/transaction.hpp +
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

// CHIP-2022-02 fungible-token-prefixed locking bytecode, decomposed:
//   ef                                  PREFIX_TOKEN
//   1122..ff (32 bytes)                 category id (genesis txid, wire order)
//   40                                  bitfield: HAS_AMOUNT (0x40), no NFT
//   fde803                              amount = 1000 (CompactSize)
//   76a914<20-byte hash160>88ac         the actual P2PKH locking bytecode
static const std::string TOKEN_PREFIX_HEX =
    "ef"
    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
    "40"
    "fde803";
static const std::string LOCKING_HEX =
    "76a91400112233445566778899aabbccddeeff0011223388ac";

int main()
{
    const std::string blob_hex = TOKEN_PREFIX_HEX + LOCKING_HEX;
    const auto blob = from_hex(blob_hex);
    const std::size_t blob_len = blob.size();   // 1+32+1+3+25 = 62 (0x3e)

    // Build a 1-in / 1-out tx whose sole output carries the token blob.
    TxIn vin;
    vin.prevout.hash  = uint256{};
    vin.prevout.index = 0x00000000u;
    {
        auto ss = from_hex("ab");               // 1-byte dummy scriptSig
        vin.scriptSig = OPScript(ss.data(), ss.data() + ss.size());
    }
    vin.sequence = 0xffffffffu;

    TxOut vout;
    vout.value        = 0;                       // token-only output (0 sats)
    vout.scriptPubKey = OPScript(blob.data(), blob.data() + blob.size());

    MutableTransaction tx;
    tx.version  = 2;
    tx.locktime = 0;
    tx.vin.push_back(vin);
    tx.vout.push_back(vout);

    PackStream ss;
    ss << tx;
    const std::string got = to_hex(ss.get_span());

    // (1) the scriptPubKey serializes as <CompactSize len><blob>, len == whole
    //     blob (token prefix is NOT split out from the locking bytecode).
    assert(blob_len == 62 && "token blob length sanity");
    const std::string len_then_blob = "3e" + blob_hex;   // 0x3e == 62
    assert(got.find(len_then_blob) != std::string::npos
           && "token scriptPubKey must serialize as <len=0x3e><blob> verbatim");

    // (2) the token-prefix bytes appear verbatim (nothing stripped/reordered).
    assert(got.find(TOKEN_PREFIX_HEX) != std::string::npos
           && "0xef token prefix must survive serialization byte-for-byte");

    // (3) deserialize -> re-serialize is byte-identical (lossless carry).
    {
        std::vector<unsigned char> raw;
        for (std::byte b : ss.get_span()) raw.push_back(static_cast<unsigned char>(b));
        PackStream in2(raw);
        MutableTransaction tx2;
        in2 >> tx2;
        PackStream re;
        re << tx2;
        const std::string round = to_hex(re.get_span());
        if (round != got) {
            std::cerr << "CashToken tx round-trip MISMATCH\n"
                      << "  in : " << got   << "\n"
                      << "  out: " << round << "\n";
            return 1;
        }
    }

    // (4) the token data is bound into the serialized pre-image: flip one prefix
    //     byte and the bytes must change (tokens are not invisible to tx_id).
    {
        auto mutated = blob;
        mutated[0] ^= 0x01;                      // 0xef -> 0xee
        TxOut vout2 = vout;
        vout2.scriptPubKey = OPScript(mutated.data(), mutated.data() + mutated.size());
        MutableTransaction txm = tx;
        txm.vout[0] = vout2;
        PackStream sm;
        sm << txm;
        assert(to_hex(sm.get_span()) != got
               && "token-prefix mutation must change the tx bytes (bound into tx_id)");
    }

    std::cout << "bch CashTokens transparency KAT: OK ("
              << (got.size() / 2) << "-byte tx; 0xef token prefix carried opaque, "
              << "lossless round-trip, bound into tx_id pre-image)\n";
    return 0;
}