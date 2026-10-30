// SPDX-License-Identifier: AGPL-3.0-or-later
// DOGE AuxPoW: the parent coinbase as Dogecoin Core serializes it.
//
// Dogecoin Core 1.14 reads and writes the parent (LTC) coinbase inside an
// AuxPoW proof with the stream's default params, i.e. witness ALLOWED
// (auxpow.h:81 READWRITE(tx); primitives/transaction.h:212), and pushes
// 'headers' without SERIALIZE_TRANSACTION_NO_WITNESS (net_processing.cpp:
// 1977/3205). LTC pools leave the BIP144 witness on their
// coinbase (marker 00, flag 01, the 32-byte witness-reserved value), and a
// peer serves it so whenever it stored it so. A witness-stripped read takes
// the marker for an empty vin and the flag for a one-output vout, loses its
// place inside the coinbase, and the rest of the batch is garbage: the live
// hash schedule broke at h=4715979, 5080796, 5641398 and 6101857.
//
// Fixtures: doge_headers_witness_fixtures.hpp, captured mainnet bytes. The
// expected values come from an independent deserializer (Core field order)
// over the same bytes, not from this code.

#include <gtest/gtest.h>

#include "doge_headers_witness_fixtures.hpp"

#include <impl/doge/coin/auxpow.hpp>
#include <impl/doge/coin/auxpow_header.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/transaction.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<unsigned char>;
using doge::coin::CAuxPow;
using ltc::coin::BlockHeaderType;

struct Fixture {
    const char*                name;
    const unsigned char*       data;
    size_t                     size;
    const char*                first_prev;  // the parent of the first entry
    std::array<const char*, 3> hashes;      // SHA256d of each 80-byte base header
};

const std::array<Fixture, 4> FIXTURES{{
    {"h5641397..h5641399", doge::test::DOGE_HEADERS_WIT_5641398, sizeof(doge::test::DOGE_HEADERS_WIT_5641398),
     "f4f0aa5d1732b3245913ef347ee3f610bb4017a11a14eb15bb5bb96a5f021349",
     {"0a6813c1e49207cc3a8eab74668204b74fdd84ad66f9d8cb4bce862e11836f51",
      "426e533b9fbce78bd4dbfd831cd84f8314f338caa460b533ac30016ade599a21",
      "248f7d07447f1929b6ad9cd09bb95645b6344a5503ce6943cc0fe0920772eded"}},
    {"h5080795..h5080797", doge::test::DOGE_HEADERS_WIT_5080796, sizeof(doge::test::DOGE_HEADERS_WIT_5080796),
     "97b370a3eb18a8fd86749dbf1cf2146d24a42f29c8f681008836b55f80d8221d",
     {"5bd3e540b086d5a02cf5aaa4c6cbb5e9e46a6e732a2485e08ba7391498acb4ce",
      "7f18d06751d61fb944e1bcebf017febbbc9e70f6617cc51137d09d4495422520",
      "8a3394d6212785bf5b7eb29b5fc2249db3d96441fb68a61bb4b172ac0f29f601"}},
    {"h4715978..h4715980", doge::test::DOGE_HEADERS_WIT_4715979, sizeof(doge::test::DOGE_HEADERS_WIT_4715979),
     "6332830c6eeb5e4298bfaf0a8d4707e72bf552572f47727de4ba7892f9559f55",
     {"0e0597f1f85e48beb685d1e7b775ab2294f379bc07f4cba8ebb77e0349c51d23",
      "4d4a08c08223c2651d7b440e51d5741c9539d53ee3b3008903298683fcee862c",
      "ebb501d6ed9c67b83511bec1225fb3eb55eda9af2104333fc56e3e281d280de1"}},
    {"h6101856..h6101858", doge::test::DOGE_HEADERS_WIT_6101857, sizeof(doge::test::DOGE_HEADERS_WIT_6101857),
     "f37ba6645234b618aac3325a0e97c096344edaa0bebb995e292a113eb6ee5866",
     {"a9831141325d2594b0716f59a294c227975dbc6a5465d369425357a6441a84d5",
      "f2b1638deb4515feaa1567ecbd499d4e9cfb4595e8016ee9eff5958d6a7d728e",
      "b3f10ec8763aaca7fcc5ae54ba239f6952730c722fed17f393a4064bd15dbda1"}},
}};

// Witness-stripped txids of the coinbases that carry a witness (independent
// deserializer): fixture index, entry index, txid.
struct WitnessTxid { size_t fixture; size_t entry; const char* txid; };
const std::array<WitnessTxid, 5> WITNESS_TXIDS{{
    {0, 1, "914686fec87b293b9dbe7ecfb3ed3406dfe225bf17268566cc6daaea19bc60ad"},  // h5641398
    {1, 1, "c54625a9309c90896954fc658f7f6255b51921d8545e24b9ad9e2eb819d2a693"},  // h5080796
    {1, 2, "20d4840828d104a67efe63b6c0267a7b112106df1d4e3e8b6fbad5d4e8a4c11e"},  // h5080797
    {2, 1, "1c35c20aca4933df979b42c0b9cc63cc40aa114e9e757fd40d26823437fbbf6b"},  // h4715979
    {3, 1, "2ad95ba7cd10ebfcf4043eb889841c6d97539cc1f28b1c27d048e457b2a1f9bd"},  // h6101857
}};

// Entry h5641398 inside DOGE_HEADERS_WIT_5641398 (payload offsets):
//   entry [882, 1738): 80-byte header, CAuxPow [962, 1737), tx_count at 1737;
//   parent coinbase [962, 1199), 237 bytes: version, marker 00 + flag 01 at
//   966, ..., witness stack (01 20 <32 x 00>) at [1161, 1195), locktime.
constexpr size_t E_BEGIN = 882, E_END = 1738;
constexpr size_t AUX_BEGIN = 962, AUX_END = 1737;
constexpr size_t MARKER = 966;
constexpr size_t WIT_BEGIN = 1161, WIT_END = 1195;

Bytes fixture_bytes(const Fixture& f) { return Bytes(f.data, f.data + f.size); }

Bytes slice(const Bytes& b, size_t from, size_t to) { return Bytes(b.begin() + from, b.begin() + to); }

Bytes erase(Bytes b, size_t from, size_t to)
{
    b.erase(b.begin() + from, b.begin() + to);
    return b;
}

template <typename T>
Bytes pack_bytes(const T& v)
{
    auto ps = pack(v);
    auto sp = ps.get_span();
    return Bytes(reinterpret_cast<const unsigned char*>(sp.data()),
                 reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

std::string hash_hex(const BlockHeaderType& h) { return Hash(pack(h).get_span()).GetHex(); }

PackStream stream_of(const Bytes& b)
{
    return PackStream(std::span<const std::byte>(reinterpret_cast<const std::byte*>(b.data()), b.size()));
}

uint256 stripped_txid(const ltc::coin::MutableTransaction& tx)
{
    return Hash(pack(ltc::coin::TX_NO_WITNESS(tx)).get_span());
}

// The parent coinbase leg of the proof: the txid walked up the branch.
uint256 merkle_root_of(uint256 leaf, const std::vector<uint256>& branch, uint32_t index)
{
    for (size_t i = 0; i < branch.size(); ++i) {
        PackStream ps;
        if ((index >> i) & 1u) {
            ps << branch[i];
            ps << leaf;
        } else {
            ps << leaf;
            ps << branch[i];
        }
        leaf = Hash(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(ps.data()), ps.size()));
    }
    return leaf;
}

struct Entry {
    BlockHeaderType                         header;
    CAuxPow<ltc::coin::MutableTransaction>  aux;
    bool                                    has_aux{false};
};

// Every entry of a fixture, structured (count byte, then header + CAuxPow +
// tx_count per entry).
std::vector<Entry> parse_entries(const Bytes& payload)
{
    auto ps = stream_of(payload);
    const uint64_t n = ReadCompactSize(ps);
    std::vector<Entry> out(n);
    for (auto& e : out) {
        e.header = doge::coin::parse_aux_header(ps, e.aux, e.has_aux);
        EXPECT_EQ(ReadCompactSize(ps), 0u);
    }
    EXPECT_EQ(ps.cursor_size(), 0u);
    return out;
}

const Bytes MINIMAL_TX = [] {
    Bytes b{0x01, 0x00, 0x00, 0x00, 0x01};               // version 1, 1 input
    b.insert(b.end(), 32, 0x00);                         // null prevout hash
    for (unsigned char c : {0xff, 0xff, 0xff, 0xff, 0x01, 0x51, 0xff, 0xff, 0xff, 0xff, 0x01})
        b.push_back(c);                                  // index, scriptSig 51, sequence, 1 output
    b.insert(b.end(), 8, 0x00);                          // value 0
    for (unsigned char c : {0x01, 0x51, 0x00, 0x00, 0x00, 0x00})
        b.push_back(c);                                  // scriptPubKey 51, locktime 0
    return b;
}();

} // namespace

// K1: the live symptom. Every captured batch parses to its count and links.
TEST(DogeAuxPowWitness, HeadersBatch_WitnessParentCoinbase_ParsesAll)
{
    for (const auto& f : FIXTURES) {
        SCOPED_TRACE(f.name);
        const auto hs = doge::coin::parse_doge_headers_message(f.data, f.size);
        ASSERT_EQ(hs.size(), 3u) << "the batch stops at the witness-coinbase entry";
        EXPECT_EQ(hs[0].m_previous_block.GetHex(), f.first_prev);
        for (size_t i = 0; i < hs.size(); ++i) {
            EXPECT_EQ(hash_hex(hs[i]), f.hashes[i]) << "entry " << i;
            if (i > 0)
                EXPECT_EQ(hs[i].m_previous_block, Hash(pack(hs[i - 1]).get_span())) << "entry " << i;
        }
    }
}

// K2: every field of the witness-carrying proof, and a byte-identical re-emit.
TEST(DogeAuxPowWitness, AuxPow_WitnessParentCoinbase_RoundTripsByteIdentical)
{
    const Bytes payload = fixture_bytes(FIXTURES[0]);
    auto ps = stream_of(slice(payload, E_BEGIN, E_END));
    CAuxPow<> aux;
    bool has_aux = false;
    BlockHeaderType hdr;
    ASSERT_NO_THROW(hdr = doge::coin::parse_aux_header(ps, aux, has_aux));
    ASSERT_TRUE(has_aux);
    EXPECT_EQ(hash_hex(hdr), "426e533b9fbce78bd4dbfd831cd84f8314f338caa460b533ac30016ade599a21");
    EXPECT_EQ(static_cast<uint32_t>(hdr.m_version), 0x00620104u);

    const auto& tx = aux.m_merkle_tx.m_tx;
    EXPECT_EQ(tx.version, 2);
    ASSERT_EQ(tx.vin.size(), 1u);
    ASSERT_EQ(tx.vout.size(), 2u);
    ASSERT_EQ(tx.vin[0].scriptWitness.stack.size(), 1u);
    EXPECT_EQ(tx.vin[0].scriptWitness.stack[0], Bytes(32, 0x00));  // the witness-reserved value
    EXPECT_EQ(tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(tx.vout[0].value, 1013812706);
    EXPECT_EQ(tx.vout[1].value, 0);
    ASSERT_GE(tx.vout[1].scriptPubKey.m_data.size(), 6u);
    EXPECT_EQ(Bytes(tx.vout[1].scriptPubKey.m_data.begin(), tx.vout[1].scriptPubKey.m_data.begin() + 6),
              (Bytes{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed}));       // the witness commitment
    EXPECT_EQ(tx.locktime, 0u);
    EXPECT_FALSE(tx.m_hogEx);

    EXPECT_TRUE(aux.m_merkle_tx.m_block_hash.IsNull());
    EXPECT_EQ(aux.m_merkle_tx.m_merkle_link.m_branch.size(), 13u);
    EXPECT_EQ(aux.m_merkle_tx.m_merkle_link.m_index, 0u);
    EXPECT_TRUE(aux.m_chain_merkle_link.m_branch.empty());
    EXPECT_EQ(aux.m_chain_merkle_link.m_index, 0u);
    EXPECT_EQ(static_cast<uint32_t>(aux.m_parent_block_header.m_version), 0x20100000u);
    EXPECT_EQ(hash_hex(aux.m_parent_block_header),
              "e932c3f576472dd352b612925a32d1e7aa1ce0c3a6ca8fb995bd491d833f31ed");

    EXPECT_EQ(ps.cursor_size(), 1u);  // the tx_count byte
    EXPECT_EQ(pack_bytes(aux), slice(payload, AUX_BEGIN, AUX_END)) << "775 captured bytes";
}

// K3: the leaf the parent's merkle branch commits to is the witness-stripped
// txid. Every entry of every fixture: the txid walked up its branch is the
// parent header's merkle root (independent txids for the witness ones).
TEST(DogeAuxPowWitness, AuxPow_ParentCoinbaseTxid_IsWitnessStripped)
{
    for (size_t fi = 0; fi < FIXTURES.size(); ++fi) {
        const auto& f = FIXTURES[fi];
        SCOPED_TRACE(f.name);
        std::vector<Entry> es;
        ASSERT_NO_THROW(es = parse_entries(fixture_bytes(f)));
        ASSERT_EQ(es.size(), 3u);
        for (size_t i = 0; i < es.size(); ++i) {
            ASSERT_TRUE(es[i].has_aux);
            EXPECT_EQ(hash_hex(es[i].header), f.hashes[i]);
            const auto& mt = es[i].aux.m_merkle_tx;
            const uint256 txid = stripped_txid(mt.m_tx);
            EXPECT_EQ(merkle_root_of(txid, mt.m_merkle_link.m_branch, mt.m_merkle_link.m_index),
                      es[i].aux.m_parent_block_header.m_merkle_root)
                << "entry " << i;
            for (const auto& w : WITNESS_TXIDS)
                if (w.fixture == fi && w.entry == i) {
                    EXPECT_FALSE(mt.m_tx.vin.at(0).scriptWitness.IsNull()) << "entry " << i;
                    EXPECT_EQ(txid.GetHex(), w.txid) << "entry " << i;
                }
        }
    }
}

// K4: the same proof served witness-stripped (as peer 52.16.18.241 serves
// it): the same fields and txid; it re-emits stripped. Both encodings in one
// batch parse and link.
TEST(DogeAuxPowWitness, AuxPow_StrippedParentCoinbase_StillParses)
{
    const Bytes payload = fixture_bytes(FIXTURES[0]);
    // Witness first (higher offsets), then marker + flag.
    const Bytes stripped = erase(erase(payload, WIT_BEGIN, WIT_END), MARKER, MARKER + 2);
    ASSERT_EQ(stripped.size(), payload.size() - 36);

    std::vector<Entry> wit, str;
    ASSERT_NO_THROW(wit = parse_entries(payload));
    ASSERT_NO_THROW(str = parse_entries(stripped));
    ASSERT_EQ(wit.size(), 3u);
    ASSERT_EQ(str.size(), 3u);
    const auto& a = wit[1].aux;
    const auto& b = str[1].aux;
    EXPECT_TRUE(b.m_merkle_tx.m_tx.vin.at(0).scriptWitness.IsNull());
    EXPECT_EQ(b.m_merkle_tx.m_tx.vout.size(), 2u);
    EXPECT_EQ(stripped_txid(b.m_merkle_tx.m_tx), stripped_txid(a.m_merkle_tx.m_tx));
    EXPECT_EQ(stripped_txid(b.m_merkle_tx.m_tx).GetHex(),
              "914686fec87b293b9dbe7ecfb3ed3406dfe225bf17268566cc6daaea19bc60ad");
    EXPECT_EQ(b.m_merkle_tx.m_merkle_link.m_branch, a.m_merkle_tx.m_merkle_link.m_branch);
    EXPECT_EQ(hash_hex(b.m_parent_block_header), hash_hex(a.m_parent_block_header));
    EXPECT_EQ(pack_bytes(b), slice(stripped, AUX_BEGIN, AUX_END - 36)) << "re-emits as received";

    const auto hs = doge::coin::parse_doge_headers_message(stripped.data(), stripped.size());
    ASSERT_EQ(hs.size(), 3u);
    for (size_t i = 0; i < 3; ++i)
        EXPECT_EQ(hash_hex(hs[i]), FIXTURES[0].hashes[i]);
}

// K5: a body whose proof carries a witness coinbase: the header and the
// transaction list after the proof (the live handler fell back to the
// standard parse on a throw here: garbage transactions).
TEST(DogeAuxPowWitness, Block_WitnessParentCoinbase_Parses)
{
    const Bytes payload = fixture_bytes(FIXTURES[0]);
    Bytes blk = slice(payload, E_BEGIN, E_END - 1);  // header + proof, no tx_count
    blk.push_back(0x01);                             // one transaction
    blk.insert(blk.end(), MINIMAL_TX.begin(), MINIMAL_TX.end());

    ltc::coin::BlockType block;
    ASSERT_NO_THROW(block = doge::coin::parse_doge_block(blk.data(), blk.size()));
    EXPECT_EQ(hash_hex(static_cast<const BlockHeaderType&>(block)),
              "426e533b9fbce78bd4dbfd831cd84f8314f338caa460b533ac30016ade599a21");
    ASSERT_EQ(block.m_txs.size(), 1u);
    ASSERT_EQ(block.m_txs[0].vin.size(), 1u);
    ASSERT_EQ(block.m_txs[0].vout.size(), 1u);
    EXPECT_EQ(block.m_txs[0].vout[0].value, 0);
    EXPECT_EQ(block.m_txs[0].locktime, 0u);
}

namespace {

std::string parse_error(const Bytes& entry)
{
    auto ps = stream_of(entry);
    CAuxPow<> aux;
    bool has_aux = false;
    try {
        doge::coin::parse_aux_header(ps, aux, has_aux);
    } catch (const std::exception& e) {
        return e.what();
    }
    return {};
}

} // namespace

// K6: flag 0x08 (MWEB) on a parent coinbase is refused, as Core refuses it
// ("Unknown transaction optional data", transaction.h:238): no MWEB here.
TEST(DogeAuxPowWitness, AuxPow_ParentCoinbaseFlag8_Rejected)
{
    Bytes entry = slice(fixture_bytes(FIXTURES[0]), E_BEGIN, E_END);
    ASSERT_EQ(entry[MARKER - E_BEGIN], 0x00);
    ASSERT_EQ(entry[MARKER + 1 - E_BEGIN], 0x01);
    entry[MARKER + 1 - E_BEGIN] = 0x08;
    EXPECT_NE(parse_error(entry).find("Unknown transaction optional data"), std::string::npos)
        << "got: \"" << parse_error(entry) << "\"";
}

// K7: flag 0x01 with every witness stack empty is refused ("Superfluous
// witness record", the LTC transaction reader's check). Stricter than
// Dogecoin Core 1.14.9, which has no such check (primitives/transaction.h:
// 231-236) and accepts that form. Harmless: Core re-serializes a proof from
// the parsed transaction and writes flag 1 only when a stack is non-empty
// (transaction.h:252-256), so a Core peer never sends it; only a non-Core
// peer could, to its own loss.
TEST(DogeAuxPowWitness, AuxPow_ParentCoinbaseEmptyWitness_RefusedStricterThanCore)
{
    Bytes entry = slice(fixture_bytes(FIXTURES[0]), E_BEGIN, E_END);
    entry = erase(entry, WIT_BEGIN - E_BEGIN, WIT_END - E_BEGIN);
    entry.insert(entry.begin() + (WIT_BEGIN - E_BEGIN), 0x00);  // zero stack items
    EXPECT_NE(parse_error(entry).find("Superfluous witness record"), std::string::npos)
        << "got: \"" << parse_error(entry) << "\"";
}
