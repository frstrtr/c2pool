// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_levin_messages_kat.cpp
//
// K-C1-2 (second half): the typed Monero P2P messages.
//
// Two kinds of check live here and they are worth telling apart:
//
//   GOLDENS are hand-derived from the KV serialization maps in monerod
//   (p2p_protocol_defs.h, cryptonote_protocol_defs.h, net_utils_base.h) plus
//   the epee encoding rules. They are built by CONCATENATION of small pinned
//   pieces rather than as one hex wall, so a reader can check each field
//   against the source it came from. They pin the two things an independent
//   implementation gets wrong: the sorted key order, and which fields
//   KV_SERIALIZE_OPT omits when they hold their default.
//
//   ROUND TRIPS cover every message in both directions, including the shapes
//   goldens cannot reach cheaply (a 250-entry peerlist, a pruned block entry).
//
// Byte parity against a captured monerod frame is a different and stronger
// claim; it is owed as U5 and belongs to the C6 parity rig, which has a daemon.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "impl/xmr/native/p2p/levin_messages.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace E = c2pool::xmr::native::epee;
using namespace c2pool::xmr::native::levin;
using namespace c2pool::xmr::native::kat;
using c2pool::xmr::native::BlockEntry;
using c2pool::xmr::native::ChainEntry;
using c2pool::xmr::native::Hash;
using c2pool::xmr::native::PeerSyncData;
using c2pool::xmr::native::TxBlobEntry;

static const char* STORAGE_HEADER_HEX = "0111010101010201 01";

static Hash hash_of(std::uint8_t first) {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(first + i);
    return h;
}

// ---------------------------------------------------------------------------
// GOLDEN 1: CORE_SYNC_DATA.
//
// monerod's map, in declaration order:
//   KV_SERIALIZE(current_height)                       u64, always
//   KV_SERIALIZE(cumulative_difficulty)                u64, always
//   if (is_store) KV_SERIALIZE(cumulative_difficulty_top64)   u64, ALWAYS on store
//   KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)               32-byte string
//   KV_SERIALIZE_OPT(top_version, 0)                   u8,  omitted when 0
//   KV_SERIALIZE_OPT(pruning_seed, 0)                  u32, omitted when 0
//
// On the wire the order is SORTED, which interleaves them differently:
//   cumulative_difficulty, cumulative_difficulty_top64, current_height,
//   top_id, top_version.
static std::vector<std::uint8_t> golden_core_sync_body() {
    std::vector<std::uint8_t> s;
    s.push_back(0x14);                                   // varint(5) entries
    append(s, entry_bytes("cumulative_difficulty",       from_hex("05 8877665544332211")));
    append(s, entry_bytes("cumulative_difficulty_top64", from_hex("05 0000000000000000")));
    append(s, entry_bytes("current_height",              from_hex("05 c0c62d0000000000")));  // 3000000
    append(s, entry_bytes("top_id",                      from_hex("0a 80")));                // string, len 32
    for (std::size_t i = 0; i < 32; ++i) s.push_back(static_cast<std::uint8_t>(i));
    append(s, entry_bytes("top_version",                 from_hex("08 10")));                // u8 = 16
    return s;
}

static PeerSyncData golden_core_sync_value() {
    PeerSyncData s;
    s.current_height           = 3000000;
    s.cumulative_difficulty.lo = 0x1122334455667788ull;
    s.cumulative_difficulty.hi = 0;
    s.top_id                   = hash_of(0);
    s.top_version              = 16;
    s.pruning_seed             = 0;
    return s;
}

// GOLDEN 2: basic_node_data. Sorted order is my_port, network_id, peer_id,
// support_flags; rpc_port and rpc_credits_per_hash are omitted at zero.
static std::vector<std::uint8_t> golden_node_data_body() {
    std::vector<std::uint8_t> s;
    s.push_back(0x10);                                   // varint(4) entries
    append(s, entry_bytes("my_port",       from_hex("06 00000000")));
    append(s, entry_bytes("network_id",    from_hex("0a 40")));   // string, len 16
    for (std::uint8_t b : NETWORK_ID_MAINNET) s.push_back(b);
    append(s, entry_bytes("peer_id",       from_hex("05 efcdab8967452301")));
    append(s, entry_bytes("support_flags", from_hex("06 01000000")));
    return s;
}

static BasicNodeData golden_node_data_value() {
    BasicNodeData n;
    n.network_id    = NETWORK_ID_MAINNET;
    n.peer_id       = 0x0123456789abcdefull;
    n.my_port       = 0;                                  // outbound only (R-LISTEN)
    n.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    return n;
}

static void test_handshake_request_golden() {
    HandshakeRequest req;
    req.node_data    = golden_node_data_value();
    req.payload_data = golden_core_sync_value();

    std::vector<std::uint8_t> got;
    MessageError err = MessageError::None;
    check(encode_handshake_request(req, got, err), "the handshake request encodes");

    // The root section: two entries, sorted (node_data < payload_data), each an
    // OBJECT (tag 0x0c) whose body is the golden above.
    std::vector<std::uint8_t> want = from_hex(STORAGE_HEADER_HEX);
    want.push_back(0x08);                                 // varint(2) entries
    std::vector<std::uint8_t> nd = from_hex("0c");
    append(nd, golden_node_data_body());
    append(want, entry_bytes("node_data", nd));
    std::vector<std::uint8_t> pd = from_hex("0c");
    append(pd, golden_core_sync_body());
    append(want, entry_bytes("payload_data", pd));

    check_bytes(got, want, "COMMAND_HANDSHAKE request golden");

    HandshakeRequest back;
    check(decode_handshake_request(got.data(), got.size(), back, err),
          "the handshake request decodes");
    check(back.node_data.network_id == NETWORK_ID_MAINNET, "network id survives");
    check(back.node_data.peer_id == req.node_data.peer_id, "peer id survives");
    check(back.node_data.my_port == 0, "my_port survives");
    check(back.node_data.support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS, "support flags survive");
    check(back.node_data.rpc_port == 0, "an omitted rpc_port reads as its default");
    check(back.payload_data.current_height == 3000000, "current height survives");
    check(back.payload_data.cumulative_difficulty.lo == 0x1122334455667788ull,
          "the low half of the cumulative difficulty survives");
    check(back.payload_data.top_version == 16, "top_version survives");
    check(back.payload_data.top_id == hash_of(0), "top_id survives");

    // Whole frames, for the transport layer. A handshake is an INVOKE.
    const std::vector<std::uint8_t> frame = make_invoke(CMD_HANDSHAKE, got);
    check(frame.size() == HEADER_SIZE + got.size(), "the frame is header plus body");
    check(frame[16] == 1, "the handshake asks for an answer");
}

// ---------------------------------------------------------------------------
// GOLDEN 3: NOTIFY_REQUEST_CHAIN. Two ids as ONE concatenated blob
// (KV_SERIALIZE_CONTAINER_POD_AS_BLOB), and prune written only when true.
static void test_request_chain_golden() {
    RequestChain m;
    m.block_ids = {hash_of(0x10), hash_of(0x40)};
    m.prune     = true;

    std::vector<std::uint8_t> got;
    MessageError err = MessageError::None;
    check(encode_request_chain(m, got, err), "REQUEST_CHAIN encodes");

    std::vector<std::uint8_t> want = from_hex(STORAGE_HEADER_HEX);
    want.push_back(0x08);                                 // varint(2) entries
    // 64 bytes of ids: varint(64) is the WORD form, (64<<2)|1 = 0x0101.
    std::vector<std::uint8_t> ids = from_hex("0a 0101");
    for (const Hash& h : m.block_ids) for (std::uint8_t b : h) ids.push_back(b);
    append(want, entry_bytes("block_ids", ids));
    append(want, entry_bytes("prune", from_hex("0b 01")));
    check_bytes(got, want, "NOTIFY_REQUEST_CHAIN golden");

    RequestChain back;
    check(decode_request_chain(got.data(), got.size(), back, err), "REQUEST_CHAIN decodes");
    check(back.block_ids == m.block_ids, "both ids come back in order");
    check(back.prune, "prune survives");

    // prune=false is OMITTED, which is the wire format and not an optimisation.
    m.prune = false;
    got.clear();
    check(encode_request_chain(m, got, err), "REQUEST_CHAIN without pruning encodes");
    E::Value root;
    E::StorageError serr = E::StorageError::None;
    check(E::read_storage(got, root, serr) && E::find(root, "prune") == nullptr,
          "prune=false is omitted, not written as a false byte");
    check(decode_request_chain(got.data(), got.size(), back, err) && !back.prune,
          "and reads back as false");

    // An empty locator omits the blob entirely (epee never writes an empty
    // container), and the decoder must read that as empty rather than missing.
    m.block_ids.clear();
    got.clear();
    check(encode_request_chain(m, got, err), "an empty locator encodes");
    check(decode_request_chain(got.data(), got.size(), back, err) && back.block_ids.empty(),
          "an absent container decodes as empty");

    // A blob whose length is not a multiple of 32 is a defect, not a rounding.
    std::vector<std::uint8_t> odd;
    check(encode_body(E::v_object({{"block_ids", E::v_blob(std::vector<std::uint8_t>(33, 0))}}), odd, err),
          "a 33-byte id blob can be built");
    check(!decode_request_chain(odd.data(), odd.size(), back, err)
              && err == MessageError::BadBlobLength,
          "and is refused");
}

// ---------------------------------------------------------------------------
// GOLDEN 4: the empty request bodies. PING and REQUEST_SUPPORT_FLAGS have an
// EMPTY KV map, which is an empty SECTION -- nine header bytes and a zero
// varint -- not a zero-length body. Sending 0 bytes makes epee's reader throw
// on construction (`sz == 0`), which the peer sees as a protocol error.
static void test_empty_requests() {
    const std::vector<std::uint8_t> got = encode_empty_request();
    check_bytes(got, from_hex(std::string(STORAGE_HEADER_HEX) + "00"),
                "an empty request body is an empty section, not zero bytes");
    check(got.size() == E::STORAGE_HEADER_SIZE + 1, "ten bytes exactly");
}

// ---------------------------------------------------------------------------
// network_address and peerlist_entry.
static void test_network_address() {
    NetworkAddress a;
    a.kind = NetworkAddress::Kind::Ipv4;
    a.m_ip = ipv4_from_octets(176, 9, 0, 187);            // a real mainnet IP seed
    a.port = 18080;

    E::Value v;
    MessageError err = MessageError::None;
    check(encode_network_address(a, v, err), "an ipv4 address encodes");

    std::vector<std::uint8_t> bytes;
    check(encode_body(v, bytes, err), "and serialises");

    // m_ip is monerod's field verbatim: its little-endian bytes are the octets
    // in dotted order, so 176.9.0.187 appears on the wire as b0 09 00 bb.
    std::vector<std::uint8_t> want = from_hex(STORAGE_HEADER_HEX);
    want.push_back(0x08);                                 // varint(2): addr, type
    std::vector<std::uint8_t> addr = from_hex("0c 08");   // object, varint(2) entries
    append(addr, entry_bytes("m_ip",   from_hex("06 b00900bb")));
    append(addr, entry_bytes("m_port", from_hex("07 a046")));   // 18080 = 0x46a0
    append(want, entry_bytes("addr", addr));
    append(want, entry_bytes("type", from_hex("08 01")));
    check_bytes(bytes, want, "ipv4 network_address golden");

    E::Value root;
    E::StorageError serr = E::StorageError::None;
    check(E::read_storage(bytes, root, serr), "the address body parses");
    NetworkAddress back;
    check(decode_network_address(root, back, err), "and decodes");
    check(back.kind == NetworkAddress::Kind::Ipv4 && back.m_ip == a.m_ip && back.port == a.port,
          "the ipv4 address survives");
    const std::array<std::uint8_t, 4> oct = ipv4_octets(back.m_ip);
    check(oct[0] == 176 && oct[1] == 9 && oct[2] == 0 && oct[3] == 187,
          "and reads out as 176.9.0.187");

    // ipv6 round trip.
    NetworkAddress six;
    six.kind = NetworkAddress::Kind::Ipv6;
    for (std::size_t i = 0; i < six.ipv6.size(); ++i) six.ipv6[i] = static_cast<std::uint8_t>(0xa0 + i);
    six.port = 38080;
    E::Value sv;
    std::vector<std::uint8_t> sbytes;
    check(encode_network_address(six, sv, err) && encode_body(sv, sbytes, err), "an ipv6 address encodes");
    E::Value sroot;
    check(E::read_storage(sbytes, sroot, serr), "the ipv6 body parses");
    NetworkAddress sback;
    check(decode_network_address(sroot, sback, err), "and decodes");
    check(sback.kind == NetworkAddress::Kind::Ipv6 && sback.ipv6 == six.ipv6 && sback.port == six.port,
          "the ipv6 address survives");

    // tor and i2p appear in real peerlists. They are PARSED AND DISCARDED: the
    // kind is kept so the peer store can count them, and nothing else is read,
    // so a malformed onion address cannot fail a whole handshake response.
    std::vector<std::uint8_t> tor;
    check(encode_body(E::v_object({
              {"type", E::v_u8(4)},
              {"addr", E::v_object({{"host", E::v_str("expyuzz4wqqyqhjn.onion")},
                                    {"port", E::v_u16(18083)}})},
          }), tor, err),
          "a tor address body can be built");
    E::Value troot;
    check(E::read_storage(tor, troot, serr), "the tor body parses");
    NetworkAddress tback;
    check(decode_network_address(troot, tback, err), "a tor address does not fail the decode");
    check(tback.kind == NetworkAddress::Kind::Tor && !tback.dialable(),
          "it is recorded as tor and never dialled");

    // An address type we have never heard of is recorded as invalid, again
    // without failing the message around it.
    std::vector<std::uint8_t> weird;
    check(encode_body(E::v_object({{"type", E::v_u8(9)}}), weird, err), "type 9 can be built");
    E::Value wroot;
    check(E::read_storage(weird, wroot, serr) && decode_network_address(wroot, tback, err),
          "an unknown address type does not fail the decode");
    check(tback.kind == NetworkAddress::Kind::Invalid, "and is recorded as invalid");

    // We never encode what we could not dial.
    NetworkAddress bad;
    bad.kind = NetworkAddress::Kind::Tor;
    E::Value out;
    check(!encode_network_address(bad, out, err) && err == MessageError::Unencodable,
          "we refuse to encode an address we cannot dial");
}

static void test_peerlist() {
    HandshakeResponse resp;
    resp.node_data    = golden_node_data_value();
    resp.payload_data = golden_core_sync_value();

    PeerlistEntry p;
    p.adr.kind = NetworkAddress::Kind::Ipv4;
    p.adr.m_ip = ipv4_from_octets(88, 198, 163, 90);
    p.adr.port = 18080;
    p.id                   = 0xdeadbeefcafef00dull;
    p.last_seen            = 1757500000;
    p.pruning_seed         = 0;
    p.rpc_port             = 18081;
    p.rpc_credits_per_hash = 0;
    resp.local_peerlist_new.assign(3, p);

    std::vector<std::uint8_t> bytes;
    MessageError err = MessageError::None;
    check(encode_handshake_response(resp, bytes, err), "a handshake response with peers encodes");

    HandshakeResponse back;
    check(decode_handshake_response(bytes.data(), bytes.size(), back, err), "and decodes");
    check(back.local_peerlist_new.size() == 3, "all three peers come back");
    if (back.local_peerlist_new.size() == 3) {
        const PeerlistEntry& q = back.local_peerlist_new[1];
        check(q.id == p.id, "peer id survives");
        check(q.adr.m_ip == p.adr.m_ip && q.adr.port == p.adr.port, "peer address survives");
        check(q.last_seen == p.last_seen, "last_seen survives as a signed value");
        check(q.rpc_port == p.rpc_port, "rpc_port survives when non-zero");
        check(q.pruning_seed == 0, "an omitted pruning_seed reads as zero");
    }

    // The zero-valued optional fields are omitted, exactly as KV_SERIALIZE_OPT
    // does on store.
    PeerlistEntry bare;
    bare.adr.kind = NetworkAddress::Kind::Ipv4;
    bare.adr.m_ip = ipv4_from_octets(127, 0, 0, 1);
    bare.adr.port = 18080;
    bare.id       = 7;
    E::Value pv;
    check(encode_peerlist_entry(bare, pv, err), "a bare peerlist entry encodes");
    check(pv.obj.size() == 2, "with only adr and id");

    // An empty peerlist omits the key entirely; the response is still valid,
    // because KV_SERIALIZE discards the loader's failure to find it.
    resp.local_peerlist_new.clear();
    bytes.clear();
    check(encode_handshake_response(resp, bytes, err), "a response with no peers encodes");
    E::Value root;
    E::StorageError serr = E::StorageError::None;
    check(E::read_storage(bytes, root, serr) && E::find(root, "local_peerlist_new") == nullptr,
          "an empty peerlist is omitted, not written as an empty array");
    check(decode_handshake_response(bytes.data(), bytes.size(), back, err)
              && back.local_peerlist_new.empty(),
          "and decodes as empty");

    // P2P_MAX_PEERS_IN_HANDSHAKE: monerod calls more than 250 "spamming" and
    // drops the sender. We refuse the message rather than allocate for it.
    resp.local_peerlist_new.assign(MAX_PEERS_IN_HANDSHAKE, p);
    bytes.clear();
    check(encode_handshake_response(resp, bytes, err), "250 peers encode");
    check(decode_handshake_response(bytes.data(), bytes.size(), back, err)
              && back.local_peerlist_new.size() == MAX_PEERS_IN_HANDSHAKE,
          "250 peers are accepted");
    resp.local_peerlist_new.assign(MAX_PEERS_IN_HANDSHAKE + 1, p);
    bytes.clear();
    check(encode_handshake_response(resp, bytes, err), "251 peers encode");
    check(!decode_handshake_response(bytes.data(), bytes.size(), back, err)
              && err == MessageError::TooManyElements,
          "251 peers are refused");
}

// ---------------------------------------------------------------------------
// block_complete_entry: the `pruned` flag changes the SHAPE of "txs".
static void test_block_complete_entry() {
    MessageError err = MessageError::None;

    // The fluffy block monerod actually relays: a block blob and an EMPTY tx
    // list, because it expects the receiver to ask for what it misses.
    NewBlock fluffy;
    fluffy.b.block_blob = {0x10, 0x10, 0xaa, 0xbb};
    fluffy.current_blockchain_height = 3000001;

    std::vector<std::uint8_t> bytes;
    check(encode_new_fluffy_block(fluffy, bytes, err), "a bare fluffy block encodes");
    E::Value root;
    E::StorageError serr = E::StorageError::None;
    check(E::read_storage(bytes, root, serr), "and parses");
    const E::Value* b = E::get_object(root, "b");
    check(b != nullptr && E::find(*b, "pruned") == nullptr, "pruned=false is omitted");
    check(b != nullptr && E::find(*b, "block_weight") == nullptr, "block_weight=0 is omitted");
    check(b != nullptr && E::find(*b, "txs") == nullptr, "an empty tx list is omitted");

    NewBlock back;
    check(decode_new_fluffy_block(bytes.data(), bytes.size(), back, err), "and decodes");
    check(back.b.block_blob == fluffy.b.block_blob, "the block blob survives");
    check(back.b.txs.empty() && !back.b.pruned, "with no transactions and not pruned");
    check(back.current_blockchain_height == 3000001, "the claimed height survives");

    // The block WE push carries every body, so the receiver needs no round trip
    // (design section 5). Not pruned: "txs" is a flat array of blobs.
    NewBlock ours = fluffy;
    ours.b.txs.push_back(TxBlobEntry{{0x01, 0x02}, {}, false});
    ours.b.txs.push_back(TxBlobEntry{{0x03}, {}, false});
    ours.b.block_weight_claimed_hint = 4321;
    bytes.clear();
    check(encode_new_fluffy_block(ours, bytes, err), "a fluffy block with bodies encodes");
    check(E::read_storage(bytes, root, serr), "and parses");
    b = E::get_object(root, "b");
    const E::Value* txs = b ? E::get_array(*b, "txs", E::Type::String) : nullptr;
    check(txs != nullptr && txs->arr.size() == 2, "unpruned txs are a flat array of blobs");
    check(b != nullptr && E::find(*b, "block_weight") != nullptr, "a non-zero weight is written");
    check(decode_new_fluffy_block(bytes.data(), bytes.size(), back, err), "and decodes");
    check(back.b.txs.size() == 2 && back.b.txs[0].blob == ours.b.txs[0].blob,
          "the bodies come back in order");
    check(back.b.block_weight_claimed_hint == 4321, "the weight HINT survives (and stays a hint)");

    // Pruned: "txs" becomes an array of objects carrying the prunable hash.
    // This is the shape D-4 pins for chain sync, and it is the one an
    // implementation that only ever tested fluffy relay would never produce.
    BlockEntry pruned;
    pruned.pruned     = true;
    pruned.block_blob = {0x10, 0x10};
    pruned.txs.push_back(TxBlobEntry{{0x05, 0x06}, hash_of(0x70), true});
    ResponseGetObjects objs;
    objs.blocks.push_back(pruned);
    objs.missed_ids.push_back(hash_of(0x90));
    objs.current_blockchain_height = 3000002;

    bytes.clear();
    check(encode_response_get_objects(objs, bytes, err), "a pruned objects response encodes");
    check(E::read_storage(bytes, root, serr), "and parses");
    const E::Value* blocks = E::get_array(root, "blocks", E::Type::Object);
    check(blocks != nullptr && blocks->arr.size() == 1, "one block entry");
    if (blocks && blocks->arr.size() == 1) {
        const E::Value* ptxs = E::get_array(blocks->arr[0], "txs", E::Type::Object);
        check(ptxs != nullptr && ptxs->arr.size() == 1, "pruned txs are an array of objects");
        if (ptxs && ptxs->arr.size() == 1) {
            check(E::get_blob(ptxs->arr[0], "prunable_hash") != nullptr,
                  "each carries its prunable hash");
        }
    }

    ResponseGetObjects oback;
    check(decode_response_get_objects(bytes.data(), bytes.size(), oback, err), "and decodes");
    check(oback.blocks.size() == 1 && oback.blocks[0].pruned, "the pruned flag survives");
    check(oback.blocks[0].txs.size() == 1
              && oback.blocks[0].txs[0].prunable_hash == hash_of(0x70)
              && oback.blocks[0].txs[0].pruned,
          "and so does the prunable hash");
    check(oback.missed_ids.size() == 1 && oback.missed_ids[0] == hash_of(0x90),
          "missed ids survive");
    check(oback.current_blockchain_height == 3000002, "the height survives");

    // A pruned entry whose txs arrived in the unpruned SHAPE is a mismatch, not
    // something to guess about.
    std::vector<std::uint8_t> mismatched;
    check(encode_body(E::v_object({
              {"b", E::v_object({{"pruned", E::v_bool(true)},
                                 {"block", E::v_blob({0x10})},
                                 {"txs", E::v_array(E::Type::String, {E::v_blob({0x01})})}})},
              {"current_blockchain_height", E::v_u64(1)},
          }), mismatched, err),
          "a mismatched entry can be built");
    check(!decode_new_fluffy_block(mismatched.data(), mismatched.size(), back, err)
              && err == MessageError::BadFieldType,
          "and is refused rather than guessed at");
}

// ---------------------------------------------------------------------------
// The rest of the message set, round trip.
static void test_round_trips() {
    MessageError err = MessageError::None;
    std::vector<std::uint8_t> bytes;

    // 1002 TIMED_SYNC, both directions.
    TimedSyncRequest tsq;
    tsq.payload_data = golden_core_sync_value();
    check(encode_timed_sync_request(tsq, bytes, err), "TIMED_SYNC request encodes");
    TimedSyncRequest tsq_back;
    check(decode_timed_sync_request(bytes.data(), bytes.size(), tsq_back, err)
              && tsq_back.payload_data.current_height == 3000000,
          "TIMED_SYNC request round trips");

    TimedSyncResponse tsr;
    tsr.payload_data = golden_core_sync_value();
    bytes.clear();
    check(encode_timed_sync_response(tsr, bytes, err), "TIMED_SYNC response encodes");
    TimedSyncResponse tsr_back;
    check(decode_timed_sync_response(bytes.data(), bytes.size(), tsr_back, err)
              && tsr_back.payload_data.top_id == hash_of(0)
              && tsr_back.local_peerlist_new.empty(),
          "TIMED_SYNC response round trips with an empty peerlist");

    // 1003 PING response.
    PingResponse ping;
    ping.status  = PING_OK_RESPONSE_STATUS_TEXT;
    ping.peer_id = 42;
    bytes.clear();
    check(encode_ping_response(ping, bytes, err), "PING response encodes");
    PingResponse ping_back;
    check(decode_ping_response(bytes.data(), bytes.size(), ping_back, err)
              && ping_back.status == "OK" && ping_back.peer_id == 42,
          "PING response round trips");

    // 1007 support flags.
    SupportFlagsResponse sf;
    sf.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    bytes.clear();
    check(encode_support_flags_response(sf, bytes, err), "support flags encode");
    SupportFlagsResponse sf_back;
    check(decode_support_flags_response(bytes.data(), bytes.size(), sf_back, err)
              && sf_back.support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS,
          "support flags round trip");

    // 2002 NEW_TRANSACTIONS. dandelionpp_fluff defaults to TRUE when absent
    // (KV_SERIALIZE_OPT(dandelionpp_fluff, true)); a stem-phase relay is the
    // one that writes it, as false.
    NewTransactions tx;
    tx.txs.push_back({0x02, 0x00, 0x01});
    tx.txs.push_back({0x02, 0x00, 0x02});
    bytes.clear();
    check(encode_new_transactions(tx, bytes, err), "a fluff-phase relay encodes");
    E::Value root;
    E::StorageError serr = E::StorageError::None;
    check(E::read_storage(bytes, root, serr), "and parses");
    check(E::find(root, "dandelionpp_fluff") == nullptr, "fluff=true is omitted");
    check(E::get_blob(root, "_") != nullptr, "the padding field is written even when empty");
    NewTransactions tx_back;
    check(decode_new_transactions(bytes.data(), bytes.size(), tx_back, err), "and decodes");
    check(tx_back.txs.size() == 2 && tx_back.dandelionpp_fluff,
          "an absent flag reads as fluff, not as stem");

    tx.dandelionpp_fluff = false;
    tx.padding.assign(8, 0);
    bytes.clear();
    check(encode_new_transactions(tx, bytes, err), "a stem-phase relay encodes");
    check(decode_new_transactions(bytes.data(), bytes.size(), tx_back, err)
              && !tx_back.dandelionpp_fluff && tx_back.padding.size() == 8,
          "and the stem flag plus padding survive");

    // 2003 REQUEST_GET_OBJECTS. monerod drops a peer asking for more than
    // CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT ids, so we never build one.
    RequestGetObjects go;
    for (std::size_t i = 0; i < c2pool::xmr::native::MAX_OBJECT_REQUEST_IDS; ++i)
        go.blocks.push_back(hash_of(static_cast<std::uint8_t>(i)));
    go.prune = true;
    bytes.clear();
    check(encode_request_get_objects(go, bytes, err), "100 ids encode");
    RequestGetObjects go_back;
    check(decode_request_get_objects(bytes.data(), bytes.size(), go_back, err)
              && go_back.blocks.size() == c2pool::xmr::native::MAX_OBJECT_REQUEST_IDS
              && go_back.prune,
          "100 ids round trip with prune=true");

    go.blocks.push_back(hash_of(0xff));
    bytes.clear();
    check(!encode_request_get_objects(go, bytes, err) && err == MessageError::TooManyElements,
          "101 ids are refused on the way out, before a peer can drop us for it");

    // 2007 RESPONSE_CHAIN_ENTRY, onto the W0 ChainEntry.
    ChainEntry ce;
    ce.start_height                 = 3000000;
    ce.total_height                 = 3010000;
    ce.cumulative_difficulty_hint.lo = 0x0102030405060708ull;
    ce.cumulative_difficulty_hint.hi = 9;
    ce.ids                          = {hash_of(1), hash_of(2), hash_of(3)};
    ce.weights_claimed_hint         = {1000, 2000, 3000};
    ce.first_block                  = {0x10, 0x10, 0x20};
    bytes.clear();
    check(encode_response_chain_entry(ce, bytes, err), "RESPONSE_CHAIN_ENTRY encodes");
    ChainEntry ce_back;
    check(decode_response_chain_entry(bytes.data(), bytes.size(), ce_back, err), "and decodes");
    check(ce_back.start_height == ce.start_height && ce_back.total_height == ce.total_height,
          "the heights survive");
    check(ce_back.cumulative_difficulty_hint.lo == ce.cumulative_difficulty_hint.lo
              && ce_back.cumulative_difficulty_hint.hi == ce.cumulative_difficulty_hint.hi,
          "the 128-bit cumulative difficulty survives in both halves");
    check(ce_back.ids == ce.ids, "the id list survives");
    check(ce_back.weights_claimed_hint == ce.weights_claimed_hint,
          "the weight HINTS survive (still hints: C2 recomputes them)");
    check(ce_back.first_block == ce.first_block, "first_block survives");

    // U2: m_block_weights may be absent on some daemons. That must decode as an
    // empty vector, not as a failure -- the fallback is C2's problem, not a
    // reason to drop the peer.
    std::vector<std::uint8_t> no_weights;
    check(encode_body(E::v_object({
              {"start_height", E::v_u64(1)},
              {"total_height", E::v_u64(2)},
              {"cumulative_difficulty", E::v_u64(3)},
              {"m_block_ids", E::v_blob(std::vector<std::uint8_t>(32, 0))},
              {"first_block", E::v_blob({})},
          }), no_weights, err),
          "a chain entry without weights can be built");
    check(decode_response_chain_entry(no_weights.data(), no_weights.size(), ce_back, err)
              && ce_back.weights_claimed_hint.empty() && ce_back.ids.size() == 1,
          "and decodes with an empty weight list");

    // 2009 REQUEST_FLUFFY_MISSING_TX: INDICES, not hashes.
    RequestFluffyMissingTx miss;
    miss.block_hash                = hash_of(0x55);
    miss.current_blockchain_height = 3000003;
    miss.missing_tx_indices        = {0, 3, 7};
    bytes.clear();
    check(encode_request_fluffy_missing_tx(miss, bytes, err), "2009 encodes");
    RequestFluffyMissingTx miss_back;
    check(decode_request_fluffy_missing_tx(bytes.data(), bytes.size(), miss_back, err)
              && miss_back.block_hash == miss.block_hash
              && miss_back.missing_tx_indices == miss.missing_tx_indices,
          "2009 round trips");

    // 2010 GET_TXPOOL_COMPLEMENT: we send what we HAVE and the peer answers
    // with a NOTIFY_NEW_TRANSACTIONS of what we lack.
    GetTxpoolComplement comp;
    for (std::size_t i = 0; i < 5; ++i) comp.hashes.push_back(hash_of(static_cast<std::uint8_t>(i * 7)));
    bytes.clear();
    check(encode_get_txpool_complement(comp, bytes, err), "2010 encodes");
    GetTxpoolComplement comp_back;
    check(decode_get_txpool_complement(bytes.data(), bytes.size(), comp_back, err)
              && comp_back.hashes == comp.hashes,
          "2010 round trips");
    comp.hashes.clear();
    bytes.clear();
    check(encode_get_txpool_complement(comp, bytes, err)
              && decode_get_txpool_complement(bytes.data(), bytes.size(), comp_back, err)
              && comp_back.hashes.empty(),
          "an empty complement is legal in both directions");
}

// ---------------------------------------------------------------------------
// Network ids and ports: a wrong network id is the fastest way to be banned by
// every peer on the network we did not mean to join.
static void test_network_ids() {
    check(network_id_of(XmrNet::Mainnet)  == NETWORK_ID_MAINNET,  "mainnet id");
    check(network_id_of(XmrNet::Testnet)  == NETWORK_ID_TESTNET,  "testnet id");
    check(network_id_of(XmrNet::Stagenet) == NETWORK_ID_STAGENET, "stagenet id");
    check(NETWORK_ID_MAINNET[15] == 0x10 && NETWORK_ID_TESTNET[15] == 0x11
              && NETWORK_ID_STAGENET[15] == 0x12,
          "the three ids differ only in the last byte");
    check(p2p_default_port(XmrNet::Mainnet) == 18080, "mainnet p2p port");
    check(p2p_default_port(XmrNet::Testnet) == 28080, "testnet p2p port");
    check(p2p_default_port(XmrNet::Stagenet) == 38080, "stagenet p2p port");
}

// ---------------------------------------------------------------------------
// Malformed bodies. Every decoder must fail rather than invent a default for a
// field that has none.
static void test_malformed() {
    MessageError err = MessageError::None;
    HandshakeRequest hs;
    HandshakeResponse hsr;
    NewBlock nb;

    const std::vector<std::uint8_t> empty;
    check(!decode_handshake_request(empty.data(), empty.size(), hs, err)
              && err == MessageError::BadStorage,
          "a zero-length body is not a message");

    std::vector<std::uint8_t> no_payload;
    check(encode_body(E::v_object({{"node_data", E::v_object({})}}), no_payload, err),
          "a handshake with no payload can be built");
    check(!decode_handshake_request(no_payload.data(), no_payload.size(), hs, err)
              && err == MessageError::MissingField,
          "and is refused for the missing payload");

    std::vector<std::uint8_t> short_id;
    check(encode_body(E::v_object({
              {"node_data", E::v_object({{"network_id", E::v_blob(std::vector<std::uint8_t>(15, 0))},
                                         {"peer_id", E::v_u64(1)},
                                         {"my_port", E::v_u32(0)}})},
              {"payload_data", E::v_object({})},
          }), short_id, err),
          "a 15-byte network id can be built");
    check(!decode_handshake_request(short_id.data(), short_id.size(), hs, err)
              && err == MessageError::BadBlobLength,
          "and is refused: a 15-byte network id is not a network id");

    std::vector<std::uint8_t> no_block;
    check(encode_body(E::v_object({{"b", E::v_object({})},
                                   {"current_blockchain_height", E::v_u64(1)}}), no_block, err),
          "a fluffy block with no block blob can be built");
    check(!decode_new_block(no_block.data(), no_block.size(), nb, err)
              && err == MessageError::MissingField,
          "and is refused");

    // A truncated body: cut a valid frame short at every offset and check that
    // nothing crashes and nothing is silently accepted as complete.
    HandshakeResponse full;
    full.node_data    = golden_node_data_value();
    full.payload_data = golden_core_sync_value();
    std::vector<std::uint8_t> bytes;
    check(encode_handshake_response(full, bytes, err), "the reference response encodes");
    int accepted_short = 0;
    for (std::size_t cut = 0; cut < bytes.size(); ++cut) {
        HandshakeResponse out;
        MessageError e = MessageError::None;
        if (decode_handshake_response(bytes.data(), cut, out, e)) ++accepted_short;
    }
    checkf(accepted_short == 0, "no truncation of a valid response parses (%d did)", accepted_short);
    check(decode_handshake_response(bytes.data(), bytes.size(), hsr, err),
          "and the untruncated one still does");
}

int main() {
    test_handshake_request_golden();
    test_request_chain_golden();
    test_empty_requests();
    test_network_address();
    test_peerlist();
    test_block_complete_entry();
    test_round_trips();
    test_network_ids();
    test_malformed();
    return report("xmr_levin_messages_kat");
}
