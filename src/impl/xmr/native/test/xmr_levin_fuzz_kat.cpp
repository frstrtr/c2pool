// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_levin_fuzz_kat.cpp
//
// K-C1-2 (fuzz half): a bounded, DETERMINISTIC fuzz pass over the levin header
// reader, the epee portable-storage decoder and every message decoder.
//
// This is the KAT that earns its keep on the sanitizer leg. It runs in the
// ordinary lane too, because the invariants it asserts are not only about
// memory safety:
//
//   INV-1  No input, however malformed, makes a decoder read outside its
//          buffer, recurse past the depth bound, or allocate on a count the
//          input chose. (ASan/UBSan prove the first; the checks below prove the
//          second and third by inspecting what came back.)
//   INV-2  Decoding is TOTAL: every buffer produces a verdict, never a hang.
//   INV-3  Re-encoding is IDEMPOTENT. If a buffer decodes, the value tree
//          re-encodes and re-decodes to the SAME tree. That is what makes the
//          encoder and the decoder each other's oracle, and it is the property
//          that would catch a sort-order or a size-mark bug that a round trip
//          through our own encoder alone would hide.
//   INV-4  A message decoder never reports success on a buffer the storage
//          decoder rejected.
//
// The corpus is generated from the real message encoders rather than checked in
// as binary blobs, so it cannot drift from the codec. `--dump-corpus <dir>`
// writes it out for an external libFuzzer run, which is how the corpus becomes
// files without becoming committed binaries.
//
// Deterministic: a fixed splitmix64 seed and no <random> distributions, so a
// failure reproduces byte for byte on any host.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// ---------------------------------------------------------------------------
// Value-tree helpers the invariants need.
static std::size_t tree_depth(const E::Value& v) {
    std::size_t deepest = 1;
    if (v.is_array) {
        for (const E::Value& e : v.arr) {
            const std::size_t d = (e.type == E::Type::Object) ? 1 + tree_depth(e) : 1;
            if (d > deepest) deepest = d;
        }
        return deepest;
    }
    if (v.type != E::Type::Object) return 1;
    for (const E::Entry& e : v.obj) {
        const std::size_t d = 1 + tree_depth(e.value);
        if (d > deepest) deepest = d;
    }
    return deepest;
}

static std::size_t tree_entries(const E::Value& v) {
    std::size_t n = 0;
    if (v.is_array) {
        for (const E::Value& e : v.arr) n += tree_entries(e);
        return n;
    }
    if (v.type != E::Type::Object) return 0;
    n += v.obj.size();
    for (const E::Entry& e : v.obj) n += tree_entries(e.value);
    return n;
}

// Order-insensitive: a decoded tree keeps wire order, a re-decoded one keeps
// sorted order, and INV-3 is about content rather than about the vector layout.
static bool same_tree(const E::Value& a, const E::Value& b) {
    if (a.type != b.type || a.is_array != b.is_array) return false;
    if (a.is_array) {
        if (a.arr.size() != b.arr.size()) return false;
        for (std::size_t i = 0; i < a.arr.size(); ++i)
            if (!same_tree(a.arr[i], b.arr[i])) return false;
        return true;
    }
    switch (a.type) {
        case E::Type::String: return a.str == b.str;
        case E::Type::Double: {
            std::uint64_t x = 0, y = 0;
            std::memcpy(&x, &a.d, sizeof(x));
            std::memcpy(&y, &b.d, sizeof(y));
            return x == y;                       // bit equality: NaN is a value here
        }
        case E::Type::Object: break;
        default: return a.u == b.u;
    }
    if (a.obj.size() != b.obj.size()) return false;
    for (const E::Entry& ea : a.obj) {
        const E::Value* vb = E::find(b, ea.name);
        if (!vb || !same_tree(ea.value, *vb)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// The seed corpus: one real body per command, built by the encoders.
struct Seed { std::string name; std::vector<std::uint8_t> bytes; };

static Hash hash_of(std::uint8_t first) {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(first + i * 3);
    return h;
}

static PeerSyncData sync_data() {
    PeerSyncData s;
    s.current_height           = 3123456;
    s.cumulative_difficulty.lo = 0x00000000abcdef01ull;
    s.cumulative_difficulty.hi = 1;
    s.top_id                   = hash_of(0x11);
    s.top_version              = 16;
    s.pruning_seed             = 0;
    return s;
}

static BasicNodeData node_data() {
    BasicNodeData n;
    n.network_id    = NETWORK_ID_STAGENET;
    n.peer_id       = 0x51a6e7a1c0ffee00ull;
    n.my_port       = 0;
    n.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    return n;
}

static PeerlistEntry peer(std::uint8_t last_octet, std::uint16_t port) {
    PeerlistEntry p;
    p.adr.kind = NetworkAddress::Kind::Ipv4;
    p.adr.m_ip = ipv4_from_octets(37, 187, 74, last_octet);
    p.adr.port = port;
    p.id                   = 0x1234567890abcdefull ^ last_octet;
    p.last_seen            = 1757400000 + last_octet;
    p.pruning_seed         = (last_octet & 1) ? 384 : 0;
    p.rpc_port             = (last_octet & 2) ? 38081 : 0;
    p.rpc_credits_per_hash = 0;
    return p;
}

static std::vector<Seed> build_corpus() {
    std::vector<Seed> out;
    MessageError err = MessageError::None;
    std::vector<std::uint8_t> b;

    auto add = [&](const char* name, bool ok) {
        if (ok) out.push_back(Seed{name, b});
        b.clear();
    };

    HandshakeRequest hs_req;
    hs_req.node_data    = node_data();
    hs_req.payload_data = sync_data();
    add("1001_handshake_request", encode_handshake_request(hs_req, b, err));

    HandshakeResponse hs_resp;
    hs_resp.node_data    = node_data();
    hs_resp.payload_data = sync_data();
    for (std::uint8_t i = 0; i < 24; ++i)
        hs_resp.local_peerlist_new.push_back(peer(static_cast<std::uint8_t>(100 + i), 38080));
    add("1001_handshake_response", encode_handshake_response(hs_resp, b, err));

    TimedSyncRequest ts_req;
    ts_req.payload_data = sync_data();
    add("1002_timed_sync_request", encode_timed_sync_request(ts_req, b, err));

    TimedSyncResponse ts_resp;
    ts_resp.payload_data = sync_data();
    ts_resp.local_peerlist_new.push_back(peer(9, 38080));
    add("1002_timed_sync_response", encode_timed_sync_response(ts_resp, b, err));

    b = encode_empty_request();
    add("1003_ping_request", true);

    PingResponse ping;
    ping.status  = PING_OK_RESPONSE_STATUS_TEXT;
    ping.peer_id = 0x51a6e7a1c0ffee00ull;
    add("1003_ping_response", encode_ping_response(ping, b, err));

    SupportFlagsResponse sf;
    sf.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    add("1007_support_flags_response", encode_support_flags_response(sf, b, err));

    NewBlock fluffy;
    fluffy.b.block_blob.assign(96, 0x5a);
    fluffy.current_blockchain_height = 3123457;
    add("2008_fluffy_block_bare", encode_new_fluffy_block(fluffy, b, err));

    NewBlock fluffy_full = fluffy;
    fluffy_full.b.block_weight_claimed_hint = 3210;
    for (std::uint8_t i = 0; i < 4; ++i)
        fluffy_full.b.txs.push_back(TxBlobEntry{std::vector<std::uint8_t>(40 + i, i), {}, false});
    add("2008_fluffy_block_with_bodies", encode_new_fluffy_block(fluffy_full, b, err));

    NewTransactions txs;
    txs.txs.push_back(std::vector<std::uint8_t>(200, 0x02));
    txs.txs.push_back(std::vector<std::uint8_t>(37, 0x03));
    txs.dandelionpp_fluff = false;
    txs.padding.assign(16, 0);
    add("2002_new_transactions", encode_new_transactions(txs, b, err));

    RequestGetObjects go;
    for (std::uint8_t i = 0; i < 20; ++i) go.blocks.push_back(hash_of(i));
    go.prune = true;
    add("2003_request_get_objects", encode_request_get_objects(go, b, err));

    ResponseGetObjects ro;
    ro.current_blockchain_height = 3123458;
    for (std::uint8_t i = 0; i < 3; ++i) {
        BlockEntry e;
        e.pruned     = true;
        e.block_blob.assign(80, i);
        e.txs.push_back(TxBlobEntry{std::vector<std::uint8_t>(60, i), hash_of(i), true});
        ro.blocks.push_back(std::move(e));
    }
    ro.missed_ids.push_back(hash_of(0xf0));
    add("2004_response_get_objects", encode_response_get_objects(ro, b, err));

    RequestChain rc;
    for (std::uint8_t i = 0; i < 12; ++i) rc.block_ids.push_back(hash_of(static_cast<std::uint8_t>(i * 5)));
    rc.prune = true;
    add("2006_request_chain", encode_request_chain(rc, b, err));

    ChainEntry ce;
    ce.start_height                  = 3123400;
    ce.total_height                  = 3123458;
    ce.cumulative_difficulty_hint.lo = 0x0102030405060708ull;
    ce.cumulative_difficulty_hint.hi = 3;
    for (std::uint8_t i = 0; i < 40; ++i) {
        ce.ids.push_back(hash_of(i));
        ce.weights_claimed_hint.push_back(2000 + i);
    }
    ce.first_block.assign(120, 0x77);
    add("2007_response_chain_entry", encode_response_chain_entry(ce, b, err));

    RequestFluffyMissingTx miss;
    miss.block_hash                = hash_of(0x33);
    miss.current_blockchain_height = 3123459;
    miss.missing_tx_indices        = {0, 1, 5, 9, 17};
    add("2009_request_fluffy_missing_tx", encode_request_fluffy_missing_tx(miss, b, err));

    GetTxpoolComplement comp;
    for (std::uint8_t i = 0; i < 64; ++i) comp.hashes.push_back(hash_of(i));
    add("2010_get_txpool_complement", encode_get_txpool_complement(comp, b, err));

    return out;
}

// ---------------------------------------------------------------------------
// Run every decoder over one buffer and assert the invariants.
// Returns whether the buffer decoded as portable storage, so the callers can
// assert COVERAGE: a mutation pass that never reaches the success path (or
// never reaches the failure path) is testing one branch and calling it two.
static bool probe(const std::vector<std::uint8_t>& buf) {
    E::Value tree;
    E::StorageError serr = E::StorageError::None;
    const bool storage_ok = E::read_storage(buf.data(), buf.size(), tree, serr);

    if (storage_ok) {
        // INV-1 (structure): whatever came back is inside the bounds.
        const E::Limits limits;
        if (tree_depth(tree) > limits.max_depth) {
            check(false, "a decoded tree exceeded the depth bound");
        }
        if (tree_entries(tree) > limits.max_entries) {
            check(false, "a decoded tree exceeded the entry bound");
        }

        // INV-3: canonical re-encoding is idempotent.
        std::vector<std::uint8_t> again;
        E::StorageError werr = E::StorageError::None;
        if (!E::write_storage(tree, again, werr)) {
            // The only legitimate refusal is a value the encoder cannot express,
            // and nothing the decoder produces is such a value.
            checkf(false, "a decoded tree failed to re-encode: %s", E::to_string(werr));
        } else {
            E::Value tree2;
            E::StorageError rerr = E::StorageError::None;
            if (!E::read_storage(again.data(), again.size(), tree2, rerr)) {
                checkf(false, "a re-encoded tree failed to re-decode: %s", E::to_string(rerr));
            } else if (!same_tree(tree, tree2)) {
                check(false, "re-encoding changed the value tree");
            } else {
                // And the second encoding is a fixed point: sorting is stable.
                std::vector<std::uint8_t> third;
                E::StorageError terr = E::StorageError::None;
                if (E::write_storage(tree2, third, terr) && !bytes_equal(again, third)) {
                    check(false, "canonical re-encoding is not a fixed point");
                }
            }
        }
    }

    // INV-2 and INV-4: every decoder returns, and none of them succeeds on a
    // buffer the storage layer refused.
    MessageError err = MessageError::None;
    bool any_message_ok = false;

    HandshakeRequest       m1;  any_message_ok |= decode_handshake_request(buf.data(), buf.size(), m1, err);
    HandshakeResponse      m2;  any_message_ok |= decode_handshake_response(buf.data(), buf.size(), m2, err);
    TimedSyncRequest       m3;  any_message_ok |= decode_timed_sync_request(buf.data(), buf.size(), m3, err);
    TimedSyncResponse      m4;  any_message_ok |= decode_timed_sync_response(buf.data(), buf.size(), m4, err);
    PingResponse           m5;  any_message_ok |= decode_ping_response(buf.data(), buf.size(), m5, err);
    SupportFlagsResponse   m6;  any_message_ok |= decode_support_flags_response(buf.data(), buf.size(), m6, err);
    NewBlock               m7;  any_message_ok |= decode_new_block(buf.data(), buf.size(), m7, err);
    NewTransactions        m8;  any_message_ok |= decode_new_transactions(buf.data(), buf.size(), m8, err);
    RequestGetObjects      m9;  any_message_ok |= decode_request_get_objects(buf.data(), buf.size(), m9, err);
    ResponseGetObjects     m10; any_message_ok |= decode_response_get_objects(buf.data(), buf.size(), m10, err);
    RequestChain           m11; any_message_ok |= decode_request_chain(buf.data(), buf.size(), m11, err);
    ChainEntry             m12; any_message_ok |= decode_response_chain_entry(buf.data(), buf.size(), m12, err);
    RequestFluffyMissingTx m13; any_message_ok |= decode_request_fluffy_missing_tx(buf.data(), buf.size(), m13, err);
    GetTxpoolComplement    m14; any_message_ok |= decode_get_txpool_complement(buf.data(), buf.size(), m14, err);

    if (any_message_ok && !storage_ok) {
        check(false, "a message decoded from a body the storage layer rejected");
    }
    return storage_ok;
}

// ---------------------------------------------------------------------------
// 1. The seed corpus itself must survive.
static void test_corpus_decodes(const std::vector<Seed>& corpus) {
    checkf(corpus.size() >= 16, "the corpus covers every command (%zu seeds)", corpus.size());
    for (const Seed& s : corpus) {
        E::Value tree;
        E::StorageError serr = E::StorageError::None;
        checkf(E::read_storage(s.bytes.data(), s.bytes.size(), tree, serr),
               "seed %s parses as portable storage (%s)", s.name.c_str(), E::to_string(serr));
        probe(s.bytes);
    }
}

// ---------------------------------------------------------------------------
// 2. Mutation fuzz over the corpus.
static void test_mutations(const std::vector<Seed>& corpus) {
    Rng rng(0x0C1A11E5A5EEDULL);
    const int rounds_per_seed = 320;
    std::size_t survived      = 0;
    std::size_t still_decoded = 0;

    for (const Seed& s : corpus) {
        for (int i = 0; i < rounds_per_seed; ++i) {
            std::vector<std::uint8_t> m = s.bytes;
            const int op = static_cast<int>(rng.below(7));
            switch (op) {
                case 0: {   // flip one bit
                    if (m.empty()) break;
                    const std::size_t at = rng.below(static_cast<std::uint32_t>(m.size()));
                    m[at] = static_cast<std::uint8_t>(m[at] ^ (1u << rng.below(8)));
                    break;
                }
                case 1: {   // set one byte to a chosen value
                    if (m.empty()) break;
                    m[rng.below(static_cast<std::uint32_t>(m.size()))] = rng.byte();
                    break;
                }
                case 2: {   // truncate
                    m.resize(rng.below(static_cast<std::uint32_t>(m.size() + 1)));
                    break;
                }
                case 3: {   // append junk
                    const std::uint32_t n = rng.below(24);
                    for (std::uint32_t k = 0; k < n; ++k) m.push_back(rng.byte());
                    break;
                }
                case 4: {   // splice in a slice of another seed
                    const Seed& other = corpus[rng.below(static_cast<std::uint32_t>(corpus.size()))];
                    if (other.bytes.empty() || m.empty()) break;
                    const std::size_t at  = rng.below(static_cast<std::uint32_t>(m.size()));
                    const std::size_t len = rng.below(static_cast<std::uint32_t>(other.bytes.size()));
                    m.resize(at);
                    m.insert(m.end(), other.bytes.begin(), other.bytes.begin() + static_cast<long>(len));
                    break;
                }
                case 5: {   // maximise a varint-looking byte: the classic
                            // "declare a huge count" attack
                    if (m.size() <= E::STORAGE_HEADER_SIZE) break;
                    const std::size_t at = E::STORAGE_HEADER_SIZE
                                         + rng.below(static_cast<std::uint32_t>(m.size() - E::STORAGE_HEADER_SIZE));
                    m[at] = 0xff;
                    break;
                }
                default: {  // set the array flag on a random byte, turning a
                            // scalar into an array header
                    if (m.empty()) break;
                    const std::size_t at = rng.below(static_cast<std::uint32_t>(m.size()));
                    m[at] = static_cast<std::uint8_t>(m[at] | 0x80);
                    break;
                }
            }
            if (probe(m)) ++still_decoded;
            ++survived;
        }
    }
    checkf(survived == corpus.size() * static_cast<std::size_t>(rounds_per_seed),
           "every mutation was probed (%zu)", survived);
    // Coverage, not decoration: if no mutation still decoded, the pass only
    // exercised the reject path; if every one did, the mutations were inert.
    checkf(still_decoded > 0, "some mutations still decoded (%zu of %zu)", still_decoded, survived);
    checkf(still_decoded < survived, "and some did not (%zu of %zu)", still_decoded, survived);
}

// ---------------------------------------------------------------------------
// 3. Structured random trees: encode, decode, compare. This exercises the
//    encoder over shapes the protocol never produces, which is where an
//    element-type or a sort-order bug hides.
static void random_value(Rng& rng, E::Value& out, std::size_t depth_left) {
    const std::uint32_t pick = rng.below(depth_left > 0 ? 12u : 10u);
    switch (pick) {
        case 0:  out = E::v_u64(rng.next()); break;
        case 1:  out = E::v_u32(static_cast<std::uint32_t>(rng.next())); break;
        case 2:  out = E::v_u16(static_cast<std::uint16_t>(rng.next())); break;
        case 3:  out = E::v_u8(rng.byte()); break;
        case 4:  out = E::v_i64(static_cast<std::int64_t>(rng.next())); break;
        case 5:  out = E::v_i32(static_cast<std::int32_t>(rng.next())); break;
        case 6:  out = E::v_bool((rng.next() & 1) != 0); break;
        case 7: {
            std::vector<std::uint8_t> blob(rng.below(48));
            for (std::uint8_t& b : blob) b = rng.byte();
            out = E::v_blob(std::move(blob));
            break;
        }
        case 8: {   // an array of a scalar type
            const E::Type elems[] = {E::Type::Uint64, E::Type::Uint32, E::Type::Uint8,
                                     E::Type::Int64, E::Type::Bool};
            const E::Type t = elems[rng.below(5)];
            std::vector<E::Value> arr;
            const std::uint32_t n = rng.below(6);
            for (std::uint32_t i = 0; i < n; ++i) {
                E::Value e;
                e.type = t;
                e.u = (t == E::Type::Bool) ? (rng.next() & 1) : rng.next();
                if (t == E::Type::Uint32) e.u &= 0xffffffffull;
                if (t == E::Type::Uint8)  e.u &= 0xffull;
                arr.push_back(e);
            }
            out = E::v_array(t, std::move(arr));
            break;
        }
        case 9: {   // an array of strings.
            //
            // Every element gets at least one payload byte, and that is not
            // squeamishness: epee pins ps_min_bytes<std::string> at 2 while an
            // EMPTY string element is one byte, so an array of empty strings at
            // the tail of a body fails epee's own pre-allocation guard. monerod
            // refuses such a frame, we mirror the refusal (see the dedicated
            // check in xmr_epee_storage_kat), and generating one here would be
            // asserting that we decode something the network cannot carry.
            std::vector<E::Value> arr;
            const std::uint32_t n = rng.below(4);
            for (std::uint32_t i = 0; i < n; ++i) {
                std::vector<std::uint8_t> blob(1 + rng.below(11));
                for (std::uint8_t& b : blob) b = rng.byte();
                arr.push_back(E::v_blob(std::move(blob)));
            }
            out = E::v_array(E::Type::String, std::move(arr));
            break;
        }
        case 10: {  // a nested section
            std::vector<E::Entry> entries;
            const std::uint32_t n = rng.below(4);
            for (std::uint32_t i = 0; i < n; ++i) {
                E::Value v;
                random_value(rng, v, depth_left - 1);
                char name[16];
                std::snprintf(name, sizeof(name), "k%u_%u", i, rng.below(1000));
                entries.push_back({name, std::move(v)});
            }
            out = E::v_object(std::move(entries));
            break;
        }
        default: {  // an array of sections
            std::vector<E::Value> arr;
            const std::uint32_t n = rng.below(3);
            for (std::uint32_t i = 0; i < n; ++i) {
                E::Value v;
                random_value(rng, v, depth_left - 1);
                if (!v.is_object()) v = E::v_object({{"x", std::move(v)}});
                arr.push_back(std::move(v));
            }
            out = E::v_array(E::Type::Object, std::move(arr));
            break;
        }
    }
}

static void test_structured_random() {
    Rng rng(0xFEEDFACE12345678ULL);
    int encoded = 0;
    for (int i = 0; i < 1500; ++i) {
        std::vector<E::Entry> entries;
        const std::uint32_t n = 1 + rng.below(6);
        for (std::uint32_t k = 0; k < n; ++k) {
            E::Value v;
            random_value(rng, v, 4);
            char name[16];
            std::snprintf(name, sizeof(name), "f%u_%u", k, rng.below(10000));
            entries.push_back({name, std::move(v)});
        }
        const E::Value root = E::v_object(std::move(entries));

        std::vector<std::uint8_t> bytes;
        E::StorageError err = E::StorageError::None;
        if (!E::write_storage(root, bytes, err)) continue;   // duplicate name draw
        ++encoded;

        E::Value back;
        if (!E::read_storage(bytes.data(), bytes.size(), back, err)) {
            checkf(false, "a self-encoded tree failed to decode: %s", E::to_string(err));
            continue;
        }
        if (!same_tree(root, back)) {
            check(false, "a structured random tree did not survive the round trip");
            continue;
        }
        probe(bytes);
    }
    checkf(encoded > 1000, "most structured trees encoded (%d of 1500)", encoded);
}

// ---------------------------------------------------------------------------
// 4. The levin header reader over random 33-byte buffers. It must never accept
//    a frame whose body size is above the cap for its command.
static void test_header_fuzz() {
    Rng rng(0x1E71A0FFBADC0DE1ULL);
    int accepted        = 0;
    int no_signature    = 0;
    int over_cap        = 0;
    int silent_rejects  = 0;
    for (int i = 0; i < 20000; ++i) {
        std::vector<std::uint8_t> h(HEADER_SIZE);
        for (std::uint8_t& b : h) b = rng.byte();

        // Fully random bytes essentially never survive byte 0, so the buffer is
        // seeded in three tiers: raw noise, a valid signature and version, and
        // a plausible frame (real command, one of the four flag words, a body
        // size in the region where the cap decision is actually interesting).
        // Without the third tier this loop tests only the reject path -- which
        // is exactly what it did before, reaching zero accepts in 20000 tries.
        const int tier = i % 3;
        if (tier >= 1) {
            std::vector<std::uint8_t> sig;
            put_u64_le(sig, SIGNATURE);
            std::memcpy(h.data(), sig.data(), sig.size());
            h[29] = 1; h[30] = 0; h[31] = 0; h[32] = 0;   // protocol version 1
        }
        if (tier == 2) {
            static const std::uint32_t commands[] = {
                CMD_HANDSHAKE, CMD_TIMED_SYNC, CMD_PING, CMD_REQUEST_SUPPORT_FLAGS,
                CMD_NEW_BLOCK, CMD_NEW_TRANSACTIONS, CMD_REQUEST_GET_OBJECTS,
                CMD_RESPONSE_GET_OBJECTS, CMD_REQUEST_CHAIN, CMD_RESPONSE_CHAIN_ENTRY,
                CMD_NEW_FLUFFY_BLOCK, CMD_REQUEST_FLUFFY_MISSING_TX,
                CMD_GET_TXPOOL_COMPLEMENT, 1004, 2005, 4242,
            };
            static const std::uint32_t flag_words[] = {
                PACKET_REQUEST, PACKET_RESPONSE, PACKET_BEGIN | PACKET_END, 0,
            };
            std::vector<std::uint8_t> field;
            put_u32_le(field, commands[rng.below(16)]);
            std::memcpy(h.data() + 17, field.data(), 4);
            field.clear();
            put_u32_le(field, flag_words[rng.below(4)]);
            std::memcpy(h.data() + 25, field.data(), 4);
            field.clear();
            // Straddle the caps: sometimes plainly legal, sometimes plainly not.
            put_u64_le(field, (rng.next() & 1) ? rng.below(4096)
                                               : (1ull << 20) + rng.below(1u << 24));
            std::memcpy(h.data() + 8, field.data(), 8);
        }

        HeaderPolicy policy;
        policy.handshaked = (i % 3) == 0;
        BucketHead out;
        HeaderError err = HeaderError::None;
        if (read_header(h.data(), h.size(), policy, out, err)) {
            ++accepted;
            if (out.signature != SIGNATURE) ++no_signature;
            const FrameClass cls = classify(out);
            const bool fragment = (cls != FrameClass::Notify && cls != FrameClass::Invoke
                                   && cls != FrameClass::Response);
            if (!fragment && out.cb > max_body_bytes(out.command, policy.handshaked)) ++over_cap;
        } else if (err == HeaderError::None) {
            ++silent_rejects;
        }
    }
    checkf(accepted > 0, "the header fuzz reached the accept path (%d times)", accepted);
    checkf(no_signature == 0, "every accepted header carried the levin signature (%d did not)",
           no_signature);
    checkf(over_cap == 0, "no accepted frame was above its command cap (%d were)", over_cap);
    checkf(silent_rejects == 0, "every rejection named a reason (%d did not)", silent_rejects);
}

// ---------------------------------------------------------------------------
static int dump_corpus(const std::vector<Seed>& corpus, const char* dir) {
    for (const Seed& s : corpus) {
        std::string path = std::string(dir) + "/" + s.name + ".bin";
        std::FILE* f = std::fopen(path.c_str(), "wb");
        if (!f) {
            std::fprintf(stderr, "cannot write %s\n", path.c_str());
            return 1;
        }
        if (!s.bytes.empty()) std::fwrite(s.bytes.data(), 1, s.bytes.size(), f);
        std::fclose(f);
        std::printf("wrote %s (%zu bytes)\n", path.c_str(), s.bytes.size());
    }
    return 0;
}

int main(int argc, char** argv) {
    const std::vector<Seed> corpus = build_corpus();

    // `--dump-corpus <dir>` exports the seeds for an external libFuzzer run.
    // The corpus lives in this file rather than as committed binaries so it
    // cannot drift away from the codec it is meant to exercise.
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--dump-corpus") == 0) return dump_corpus(corpus, argv[i + 1]);
    }

    test_corpus_decodes(corpus);
    test_mutations(corpus);
    test_structured_random();
    test_header_fuzz();
    return report("xmr_levin_fuzz_kat");
}
