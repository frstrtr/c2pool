// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/test/p2pool_parse_kat.cpp
//
// THE P2POOL OBSERVER KAT: two real frames off the live mini sidechain, plus
// the properties that make the observer safe to point at a public network.
//
// THE GOLDENS are complete BLOCK_RESPONSE frames -- message-id byte,
// little-endian u32 length, body -- captured by `xmr_p2pool_observer
// --capture-golden` during the session this component was proven in, with
// nothing stripped, normalised or re-serialised. Their expected values were
// computed by test/gen_p2pool_golden.py, an INDEPENDENT Python reading of the
// same bytes (its own keccak, its own varint decoder, its own CryptoNote tree
// hash), so this file is a cross-implementation agreement rather than a
// photograph of what the C++ produced.
//
//   A -- mini height 14757167, id 4443f87a...665f6d, 688 PPLNS payout lines,
//        91 transactions, templated on Monero height 3760080.
//   B -- mini height 14757139, id f11e43b5...ea31fb, TWO merge-mining chain
//        ids. This is the block that broke the first cut of the parser; see
//        the P2POOL HASH ORDER section below.
//
// TWO EXTERNAL ANCHORS, so the goldens are not self-referential:
//
//   1. MONERO. Each block carries the id of the Monero block it templates on
//      TOP of -- prev_id of a block templated on height H is the id of H-1.
//      A's prev_id is 4a051a76...19dd0 and B's is 79f93953...53a56; those are
//      the ids a public Monero source reported for heights 3760079 and
//      3760077 at capture time. They are asserted by name below.
//   2. P2POOL ITSELF. A's `parent` field, read straight off the wire, is
//      5249d3f8...3d680a -- the sidechain id this same code RECOMPUTED for the
//      previous block in the same session. The network's own linkage confirms
//      the recomputation; a wrong sidechain-id derivation could not produce a
//      chain whose parent pointers close.
//
// WHAT ELSE IS PINNED, and why each earns a place:
//
//   * The outbound surface. ControlMessage has four values and encode() is
//     total over it; the KAT asserts the emitted message-id set is exactly
//     {0, 1, 3, 6} and that each encoding has the exact length upstream reads.
//     Adding a fifth encoder -- a block broadcast, a listen port -- fails here
//     before it can reach a socket. This is the read-only claim, as a test.
//   * P2Pool hash order. Upstream compares 32-byte ids as four little-endian
//     words, most significant first, NOT lexicographically, and the
//     merge-mining list is emitted in that order. Golden B's two chain ids
//     descend lexicographically and ascend in P2Pool's order, so a parser that
//     uses std::array's operator< rejects a legal live block. It did.
//   * The handshake. The consensus id is the membership test, so the KAT shows
//     that the same challenge under the MAIN consensus id does not verify
//     under MINI, and that the simplified proof-of-work bound agrees with the
//     128-bit product upstream actually computes.
//   * Truncation. Every prefix of golden A is fed to the parser: none may
//     succeed and none may crash. The bytes come from an unauthenticated peer.
//   * The read model. Same-height contests, cadence with its sample count, and
//     the refusal to report a rate from one sample.
//
// Offline: no network, no daemon, no fixture file.
// ---------------------------------------------------------------------------

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/p2pool/p2pool_block.hpp"
#include "impl/xmr/p2pool/p2pool_consensus.hpp"
#include "impl/xmr/p2pool/p2pool_handshake.hpp"
#include "impl/xmr/p2pool/p2pool_read_model.hpp"
#include "impl/xmr/p2pool/p2pool_wire.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"

#include "p2pool_golden_frames.hpp"

namespace p2p = c2pool::xmr::p2pool;
namespace nat = c2pool::xmr::native;
namespace gold = c2pool::xmr::p2pool::golden;

namespace {

int g_checks = 0;
int g_fail   = 0;

void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("FAIL: %s\n", what); }
}

template <typename A, typename B>
void check_eq(const A& a, const B& b, const char* what) {
    ++g_checks;
    if (!(a == static_cast<A>(b))) {
        ++g_fail;
        std::printf("FAIL: %s\n", what);
    }
}

std::vector<std::uint8_t> unhex(const char* h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    for (const char* p = h; p[0] && p[1]; p += 2)
        out.push_back(static_cast<std::uint8_t>((nib(p[0]) << 4) | nib(p[1])));
    return out;
}

p2p::Hash hash_of(const char* h) {
    const std::vector<std::uint8_t> v = unhex(h);
    p2p::Hash out{};
    if (v.size() == 32) std::memcpy(out.data(), v.data(), 32);
    return out;
}

std::string hex_of(const nat::BlockHash& h) {
    static const char* d = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) { s[2 * i] = d[h[i] >> 4]; s[2 * i + 1] = d[h[i] & 15]; }
    return s;
}

// ---------------------------------------------------------------------------
// The Monero ids a public source reported for the heights these two blocks
// template on top of. Written here rather than derived, because their whole
// value is that they came from somewhere else.
// ---------------------------------------------------------------------------
constexpr const char* kPublicMoneroId3760079 =
    "4a051a761dd0f3f148084bd4ed82fe8e406fefc337bff0b811fcf65163919dd0";
constexpr const char* kPublicMoneroId3760077 =
    "79f9395334269cc9b339cb3b4a4284efaa0f7dcaa75280e31dd03df2cd153a56";

// ---------------------------------------------------------------------------
// 1) Frame splitting, then the full parse, then the embedded Monero block.
// ---------------------------------------------------------------------------
void check_golden(const char* name, const char* frame_hex, const gold::GoldenExpect& e) {
    const std::vector<std::uint8_t> frame = unhex(frame_hex);
    check_eq(frame.size(), e.frame_bytes, "golden frame length");

    // --- framing -------------------------------------------------------------
    std::size_t flen = 0;
    const p2p::FrameStatus st = p2p::frame_size(frame.data(), frame.size(), flen);
    check(st == p2p::FrameStatus::Complete, "frame_size: complete");
    check_eq(flen, e.frame_bytes, "frame_size: whole frame consumed");
    check(frame[0] == static_cast<std::uint8_t>(p2p::MessageId::BlockResponse),
          "frame is a BLOCK_RESPONSE");
    check_eq(p2p::frame_body_length(frame.data(), flen), e.body_bytes, "body length");

    // A frame one byte short must be Incomplete, never Complete: the splitter
    // is the only thing standing between a partial read and a parser.
    std::size_t partial = 0;
    check(p2p::frame_size(frame.data(), frame.size() - 1, partial)
              == p2p::FrameStatus::Incomplete,
          "frame_size: one byte short is incomplete");

    // --- the sidechain block -------------------------------------------------
    const std::uint8_t* body = frame.data() + 5;
    p2p::PoolBlock pb;
    const p2p::BlockStatus bs = p2p::deserialize(body, e.body_bytes,
                                                 p2p::consensus_id(p2p::Sidechain::Mini),
                                                 p2p::BlobShape::Full, pb);
    if (bs != p2p::BlockStatus::Ok) {
        std::printf("FAIL: %s did not parse: %s\n", name, p2p::to_string(bs));
        ++g_fail; ++g_checks;
        return;
    }
    ++g_checks;

    check(pb.sidechain_id_verified, "sidechain id was recomputed, not taken from the wire");
    check(p2p::hex(pb.sidechain_id) == std::string(e.sidechain_id), "sidechain id");
    check_eq(pb.sidechain_height, e.sidechain_height, "sidechain height");
    check(p2p::hex(pb.parent) == std::string(e.parent), "parent");
    check_eq(pb.difficulty.lo, e.difficulty_lo, "difficulty lo");
    check_eq(pb.difficulty.hi, e.difficulty_hi, "difficulty hi");
    check_eq(pb.cumulative_difficulty.lo, e.cumulative_lo, "cumulative difficulty lo");
    check_eq(pb.cumulative_difficulty.hi, e.cumulative_hi, "cumulative difficulty hi");
    check_eq(pb.uncles.size(), e.uncle_count, "uncle count");
    check_eq(pb.outputs.size(), e.share_outputs, "PPLNS payout lines");
    check_eq(pb.total_reward, e.total_reward, "total coinbase reward");
    check_eq(pb.tx_hashes.size(), e.tx_count, "transaction count");
    check_eq(pb.merkle_proof.size(), e.merkle_proof_len, "merge-mining merkle proof length");
    check_eq(pb.merge_mining_extra.size(), e.mm_extra_count, "merge-mining extra entries");
    check_eq(pb.mm_n_aux_chains, e.mm_n_aux_chains, "merge-mining aux chain count");
    check_eq(pb.mm_nonce, e.mm_nonce, "merge-mining nonce");
    check_eq(pb.major_version, e.major_version, "monero major version");
    check_eq(pb.minor_version, e.minor_version, "monero minor version");
    check_eq(pb.timestamp, e.monero_timestamp, "monero timestamp");
    check_eq(pb.nonce, e.monero_nonce, "monero nonce");
    check_eq(pb.txin_gen_height, e.monero_height, "monero template height");
    check(p2p::hex(pb.prev_id) == std::string(e.monero_prev_id), "monero prev_id");
    check_eq(pb.sidechain_offset, e.sidechain_offset, "monero/sidechain boundary");
    check(p2p::hex(pb.merkle_root) == std::string(e.merkle_root), "merge-mining root");
    check(p2p::hex(pb.txkey_pub) == std::string(e.txkey_pub), "transaction public key");

    // The share set is the point of the whole sidechain: every payout line must
    // be non-degenerate and they must sum to the coinbase total.
    std::uint64_t sum = 0;
    bool all_nonzero = true;
    for (const p2p::ShareOutput& o : pb.outputs) {
        sum += o.reward;
        if (o.reward == 0) all_nonzero = false;
    }
    check_eq(sum, e.total_reward, "payout lines sum to the coinbase total");
    check(all_nonzero, "no zero-value payout line");
    check(pb.total_reward >= p2p::kBaseBlockReward, "coinbase pays at least the base reward");

    // --- the embedded Monero block, through the NATIVE lane ------------------
    // This is the reuse the component is stacked on M3 for: the same parser and
    // the same block identity the native node runs against monerod.
    const std::vector<std::uint8_t> mblob = p2p::monero_block_blob(body, pb);
    check_eq(mblob.size(), e.sidechain_offset, "embedded monero blob length");

    nat::ParsedBlock   mpb;
    nat::BlockIdentity mid;
    const nat::BlockParseStatus ms = nat::parse_and_identify(mblob, mpb, mid);
    check(ms == nat::BlockParseStatus::Ok, "embedded monero block parses natively");
    if (ms == nat::BlockParseStatus::Ok) {
        check_eq(mpb.header.major_version, e.major_version, "native: major version agrees");
        check_eq(mpb.header.timestamp, e.monero_timestamp, "native: timestamp agrees");
        check_eq(mpb.header.nonce, e.monero_nonce, "native: nonce agrees");
        check(hex_of(mpb.header.prev_id) == std::string(e.monero_prev_id),
              "native: prev_id agrees with the p2pool reading");
        check_eq(mpb.tx_hashes.size(), e.tx_count, "native: transaction count agrees");
        check(hex_of(mid.id) == std::string(e.monero_block_id), "native: monero block id");
        check(hex_of(mid.miner_tx_hash) == std::string(e.monero_miner_tx_hash),
              "native: coinbase hash");
        check(hex_of(mid.tree_root) == std::string(e.monero_tree_root), "native: tree root");
        check_eq(mid.hashing_blob.size(), e.monero_hashing_bytes, "native: hashing blob size");

        nat::CoinbaseFields cb;
        check(nat::parse_coinbase_fields(mblob.data(), mpb, cb), "native: coinbase fields");
        check_eq(cb.height, e.monero_height, "native: coinbase height == template height");
        check_eq(cb.n_outputs, e.share_outputs, "native: coinbase output count == share count");
        check_eq(cb.output_sum, e.total_reward, "native: coinbase sum == reward");
    }

    // --- the wrong sidechain -------------------------------------------------
    // The consensus id is inside the hash, so reading the same bytes as a MAIN
    // sidechain block must produce a different id. That is the membership test
    // the whole protocol rests on.
    p2p::PoolBlock wrong;
    const p2p::BlockStatus ws = p2p::deserialize(body, e.body_bytes,
                                                 p2p::consensus_id(p2p::Sidechain::Main),
                                                 p2p::BlobShape::Full, wrong);
    check(ws == p2p::BlockStatus::Ok, "the same bytes still parse structurally");
    check(p2p::hex(wrong.sidechain_id) != std::string(e.sidechain_id),
          "a different consensus id yields a different sidechain id");
}

// ---------------------------------------------------------------------------
// 2) P2Pool's hash order -- the defect golden B exists to pin.
// ---------------------------------------------------------------------------
void check_hash_order() {
    const p2p::Hash a = hash_of(gold::kBMergeMiningChainIds[0]);
    const p2p::Hash b = hash_of(gold::kBMergeMiningChainIds[1]);

    check(p2p::p2pool_hash_less(a, b), "live chain ids ascend in p2pool order");
    check(!(a < b), "the same pair DESCENDS lexicographically");
    check(!p2p::p2pool_hash_less(b, a), "p2pool order is antisymmetric here");
    check(!p2p::p2pool_hash_less(a, a), "p2pool order is irreflexive");

    // The comparator looks at the LAST word first. Two ids differing only in
    // byte 0 order by byte 0; two differing only in byte 31 order by byte 31,
    // and the second must dominate.
    p2p::Hash lo{}, hi{};
    lo[0] = 1; hi[31] = 1;
    check(p2p::p2pool_hash_less(lo, hi), "the most significant word dominates");
    check(!(lo < hi), "and lexicographically that same pair orders the other way");

    // Transitivity over a handful of values, so the comparator is a usable
    // strict weak ordering and not just right on one pair.
    p2p::Hash x{}, y{}, z{};
    x[31] = 1; y[31] = 2; z[31] = 3;
    check(p2p::p2pool_hash_less(x, y) && p2p::p2pool_hash_less(y, z)
              && p2p::p2pool_hash_less(x, z),
          "p2pool order is transitive");
}

// ---------------------------------------------------------------------------
// 3) The outbound surface. This is the read-only claim expressed as a test.
// ---------------------------------------------------------------------------
void check_write_surface() {
    check_eq(p2p::kControlMessageCount, 4u, "exactly four control messages exist");

    const p2p::ControlMessage all[] = {
        p2p::ControlMessage::HandshakeChallenge,
        p2p::ControlMessage::HandshakeSolution,
        p2p::ControlMessage::BlockRequest,
        p2p::ControlMessage::PeerListRequest,
    };

    // The whole set of message ids this process can ever put on a socket.
    bool emitted[12] = {false};
    p2p::ControlArgs a{};
    a.peer_id = 0x0123456789abcdefull;
    for (p2p::ControlMessage c : all) {
        const std::vector<std::uint8_t> bytes = p2p::encode(c, a);
        check(!bytes.empty(), "control message encodes to something");
        const std::uint8_t id = bytes[0];
        check(id < 12, "encoded id is a known p2pool message id");
        if (id < 12) emitted[id] = true;
        // Every control message must be exactly the length upstream reads for
        // that id, or the peer resynchronises on garbage and bans us.
        std::size_t want = 0;
        const p2p::FrameStatus fs = p2p::frame_size(bytes.data(), bytes.size(), want);
        check(fs == p2p::FrameStatus::Complete, "encoded control message is a whole frame");
        check_eq(bytes.size(), want, "encoded length matches the wire length for its id");
    }

    // The pin: the emitted id set is exactly
    //   0 HANDSHAKE_CHALLENGE, 1 HANDSHAKE_SOLUTION, 3 BLOCK_REQUEST, 6 PEER_LIST_REQUEST
    // and in particular NOT 2 LISTEN_PORT, NOT 4 BLOCK_RESPONSE,
    // NOT 5 BLOCK_BROADCAST, NOT 8 BLOCK_BROADCAST_COMPACT, NOT 9 BLOCK_NOTIFY,
    // NOT 10 AUX_JOB_DONATION, NOT 11 MONERO_BLOCK_BROADCAST.
    const bool want_emitted[12] = {true, true, false, true, false, false,
                                   true, false, false, false, false, false};
    for (int i = 0; i < 12; ++i) {
        if (emitted[i] != want_emitted[i]) {
            std::printf("FAIL: outbound id %d (%s) emitted=%d expected=%d\n", i,
                        p2p::to_string(static_cast<p2p::MessageId>(i)),
                        emitted[i] ? 1 : 0, want_emitted[i] ? 1 : 0);
            ++g_fail;
        }
        ++g_checks;
    }

    // Exact byte lengths, spelled out so a silent field addition is caught.
    check_eq(p2p::encode(p2p::ControlMessage::HandshakeChallenge, a).size(), 17u,
             "HANDSHAKE_CHALLENGE is 17 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::HandshakeSolution, a).size(), 41u,
             "HANDSHAKE_SOLUTION is 41 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::BlockRequest, a).size(), 33u,
             "BLOCK_REQUEST is 33 bytes");
    check_eq(p2p::encode(p2p::ControlMessage::PeerListRequest, a).size(), 1u,
             "PEER_LIST_REQUEST is 1 byte");

    // An all-zero block id is how "send me your tip" is spelled.
    const std::vector<std::uint8_t> tip = p2p::encode(p2p::ControlMessage::BlockRequest, a);
    bool all_zero = true;
    for (std::size_t i = 1; i < tip.size(); ++i) if (tip[i]) all_zero = false;
    check(all_zero, "a default BLOCK_REQUEST asks for the tip");

    // The peer id is written little-endian, byte for byte as upstream reads it.
    const std::vector<std::uint8_t> ch = p2p::encode(p2p::ControlMessage::HandshakeChallenge, a);
    std::uint64_t round_trip = 0;
    for (int i = 7; i >= 0; --i) round_trip = (round_trip << 8) | ch[9 + static_cast<std::size_t>(i)];
    check_eq(round_trip, a.peer_id, "peer id round-trips little-endian");
}

// ---------------------------------------------------------------------------
// 4) Framing: every id has the length upstream expects, and bad input is fatal
//    rather than resynchronised.
// ---------------------------------------------------------------------------
void check_framing() {
    struct { std::uint8_t id; std::size_t len; } fixed[] = {
        {0, 17}, {1, 41}, {2, 5}, {3, 33}, {6, 1}, {9, 33},
    };
    for (const auto& f : fixed) {
        std::vector<std::uint8_t> buf(f.len, 0);
        buf[0] = f.id;
        std::size_t n = 0;
        check(p2p::frame_size(buf.data(), buf.size(), n) == p2p::FrameStatus::Complete,
              "fixed-size frame is complete at its exact length");
        check_eq(n, f.len, "fixed-size frame length");
        if (f.len > 1) {
            std::size_t m = 0;
            check(p2p::frame_size(buf.data(), f.len - 1, m) == p2p::FrameStatus::Incomplete,
                  "fixed-size frame short by one is incomplete");
        }
    }

    // An unknown id is fatal. Upstream bans for it; we close.
    std::uint8_t bad[1] = {12};
    std::size_t n = 0;
    check(p2p::frame_size(bad, 1, n) == p2p::FrameStatus::BadId, "unknown message id is fatal");

    // A length above MAX_BLOCK_SIZE is fatal before a single byte is buffered.
    std::vector<std::uint8_t> huge(5, 0);
    huge[0] = 4;
    const std::uint32_t too_big = p2p::kMaxBlockSize + 1;
    std::memcpy(huge.data() + 1, &too_big, 4);
    check(p2p::frame_size(huge.data(), huge.size(), n) == p2p::FrameStatus::TooBig,
          "oversized body length is fatal");

    // A peer list longer than the protocol allows is refused, not truncated.
    std::vector<std::uint8_t> peers(2 + 17 * 19, 0);
    peers[0] = 7; peers[1] = 17;
    check(p2p::frame_size(peers.data(), peers.size(), n) == p2p::FrameStatus::TooBig,
          "over-long peer list is fatal");

    // A legal peer list, including upstream's version-announcement entry.
    std::vector<std::uint8_t> pl(2 + 2 * 19, 0);
    pl[0] = 7; pl[1] = 2;
    // entry 0: the version announcement -- 255.255.255.255 : 65535
    std::uint8_t* e0 = pl.data() + 2;
    e0[0] = 0;
    const std::uint32_t proto = p2p::kProtocolVersion14;
    std::memcpy(e0 + 1, &proto, 4);
    std::memset(e0 + 1 + 12, 0xFF, 4);
    e0[17] = 0xFF; e0[18] = 0xFF;
    // entry 1: an IPv4-mapped address 203.0.113.7:37888
    std::uint8_t* e1 = pl.data() + 2 + 19;
    e1[0] = 0;
    e1[1 + 10] = 0xFF; e1[1 + 11] = 0xFF;
    e1[1 + 12] = 203; e1[1 + 13] = 0; e1[1 + 14] = 113; e1[1 + 15] = 7;
    const std::uint16_t port = p2p::kPortMini;
    std::memcpy(e1 + 17, &port, 2);

    std::size_t plen = 0;
    check(p2p::frame_size(pl.data(), pl.size(), plen) == p2p::FrameStatus::Complete,
          "legal peer list frames");
    std::vector<p2p::PeerEntry> decoded;
    check(p2p::decode_peer_list(pl.data(), plen, decoded), "peer list decodes");
    check_eq(decoded.size(), 2u, "two peer entries");
    if (decoded.size() == 2) {
        check(decoded[0].is_version_announcement(), "entry 0 is the version announcement");
        check_eq(decoded[0].announced_protocol_version(), p2p::kProtocolVersion14,
                 "announced protocol version");
        check(!decoded[1].is_version_announcement(), "entry 1 is a real address");
        check(decoded[1].is_ipv4_mapped(), "entry 1 is ipv4-mapped");
        check_eq(decoded[1].port, p2p::kPortMini, "entry 1 port");
    }
}

// ---------------------------------------------------------------------------
// 5) The handshake: consensus id as membership, and the proof-of-work bound.
// ---------------------------------------------------------------------------
void check_handshake() {
    p2p::Challenge challenge{};
    for (std::size_t i = 0; i < challenge.size(); ++i)
        challenge[i] = static_cast<std::uint8_t>(0xA0 + i);

    // Deterministic: same inputs, same hash.
    p2p::Challenge salt{};
    for (std::size_t i = 0; i < salt.size(); ++i) salt[i] = static_cast<std::uint8_t>(i);
    const p2p::Hash32 h1 = p2p::handshake_hash(challenge, p2p::kConsensusMini, salt);
    const p2p::Hash32 h2 = p2p::handshake_hash(challenge, p2p::kConsensusMini, salt);
    check(h1 == h2, "handshake hash is deterministic");

    // The consensus id is what separates the sidechains.
    const p2p::Hash32 hmain = p2p::handshake_hash(challenge, p2p::kConsensusMain, salt);
    check(!(h1 == hmain), "mini and main produce different handshake hashes");
    check(p2p::verify_handshake(challenge, p2p::kConsensusMini, h1, salt),
          "the right consensus id verifies");
    check(!p2p::verify_handshake(challenge, p2p::kConsensusMain, h1, salt),
          "the wrong consensus id does not verify");

    // The three sidechain ids are distinct and non-empty, so a copy-paste
    // between them is caught here rather than by a peer hanging up.
    check(!(p2p::kConsensusMini == p2p::kConsensusMain), "mini != main consensus id");
    check(!(p2p::kConsensusNano == p2p::kConsensusMain), "nano != main consensus id");
    check(!(p2p::kConsensusNano == p2p::kConsensusMini), "nano != mini consensus id");
    check(p2p::default_port(p2p::Sidechain::Main) == 37889, "main p2p port");
    check(p2p::default_port(p2p::Sidechain::Mini) == 37888, "mini p2p port");
    check(p2p::default_port(p2p::Sidechain::Nano) == 37890, "nano p2p port");

    // Both chains target ten-second blocks -- the difference between them is
    // hashrate, not cadence. Pinned because it is easy to assume otherwise.
    check_eq(p2p::params_of(p2p::Sidechain::Main).target_block_time, 10u,
             "main targets 10 s blocks");
    check_eq(p2p::params_of(p2p::Sidechain::Mini).target_block_time, 10u,
             "mini targets 10 s blocks");
    check_eq(p2p::params_of(p2p::Sidechain::Nano).target_block_time, 30u,
             "nano targets 30 s blocks");

    // The simplified proof-of-work bound must agree with the 128-bit product
    // upstream computes, over a sweep that straddles it.
    bool agree = true;
    for (std::uint64_t i = 0; i < 4096; ++i) {
        p2p::Challenge s{};
        std::uint64_t k = i;
        for (std::size_t b = 0; b < s.size(); ++b) { s[b] = static_cast<std::uint8_t>(k & 0xFF); k >>= 8; }
        const p2p::Hash32 h = p2p::handshake_hash(challenge, p2p::kConsensusMini, s);
        if (p2p::handshake_pow_ok(h) != (p2p::handshake_pow_high(h) == 0)) agree = false;
    }
    check(agree, "the pow bound agrees with the 128-bit product over 4096 salts");

    // And the search actually finds one, at roughly the advertised cost.
    const p2p::HandshakeSolution sol =
            p2p::solve_handshake(challenge, p2p::kConsensusMini, 12345u);
    check(sol.iterations > 0, "handshake solution found");
    check(p2p::handshake_pow_ok(sol.solution), "the found solution clears the difficulty");
    check(p2p::handshake_hash(challenge, p2p::kConsensusMini, sol.salt) == sol.solution,
          "the found solution is the hash of its own salt");

    // Deterministic seed -> deterministic solution, which is what makes this a KAT.
    const p2p::HandshakeSolution again =
            p2p::solve_handshake(challenge, p2p::kConsensusMini, 12345u);
    check(again.salt == sol.salt && again.iterations == sol.iterations,
          "the same seed finds the same solution");
}

// ---------------------------------------------------------------------------
// 6) Hostile input: every truncation of a real frame, and a flipped byte.
// ---------------------------------------------------------------------------
void check_hostile() {
    const std::vector<std::uint8_t> frame = unhex(gold::kAFrameHex);
    const std::uint8_t* body = frame.data() + 5;
    const std::size_t   blen = gold::kAExpect.body_bytes;
    const p2p::ConsensusId& cid = p2p::consensus_id(p2p::Sidechain::Mini);

    // Every prefix except the whole thing must fail, and none may crash. A
    // stride keeps the KAT fast while still visiting every structural boundary
    // in the first two kilobytes, where all the fixed-size fields live.
    std::size_t rejected = 0, tested = 0;
    for (std::size_t n = 0; n < blen; n += (n < 2048 ? 1 : 97)) {
        p2p::PoolBlock pb;
        ++tested;
        if (p2p::deserialize(body, n, cid, p2p::BlobShape::Full, pb) != p2p::BlockStatus::Ok)
            ++rejected;
    }
    check_eq(rejected, tested, "every truncated prefix is rejected");
    check(tested > 2000, "the truncation sweep actually ran");

    // The SHAPE is authoritative, and it comes from the message id rather than
    // from the bytes. Reading the same full blob as if it had arrived in a
    // broadcast still parses -- an unpruned blob is legal in either -- but the
    // id must then be left unverified rather than silently recomputed, because
    // a broadcast is the case where the outputs may have been elided.
    {
        p2p::PoolBlock pruned_view;
        const p2p::BlockStatus s = p2p::deserialize(body, blen, cid,
                                                    p2p::BlobShape::Pruned, pruned_view);
        check(s == p2p::BlockStatus::Ok, "the same blob parses under the pruned shape");
        check(!pruned_view.monero_blob_contiguous(),
              "a pruned-shaped blob does not hand out a monero blob");
        check(p2p::monero_block_blob(body, pruned_view).empty(),
              "and monero_block_blob refuses to invent one");
    }

    // Flip one byte inside the miner's spend key -- a field that is hashed but
    // not otherwise validated. The block must still parse and its id must
    // change, which is what makes the id an integrity check on the whole blob.
    {
        std::vector<std::uint8_t> tampered(body, body + blen);
        tampered[gold::kAExpect.sidechain_offset] ^= 0x01;
        p2p::PoolBlock pb;
        const p2p::BlockStatus s =
                p2p::deserialize(tampered.data(), tampered.size(), cid, p2p::BlobShape::Full, pb);
        check(s == p2p::BlockStatus::Ok, "a tampered spend key still parses structurally");
        if (s == p2p::BlockStatus::Ok)
            check(p2p::hex(pb.sidechain_id) != std::string(gold::kAExpect.sidechain_id),
                  "a tampered byte changes the sidechain id");
    }

    // Trailing garbage is refused: upstream requires the cursor to land exactly
    // on the end, and so does this.
    {
        std::vector<std::uint8_t> extra(body, body + blen);
        extra.push_back(0x00);
        p2p::PoolBlock pb;
        check(p2p::deserialize(extra.data(), extra.size(), cid, p2p::BlobShape::Full, pb)
                  == p2p::BlockStatus::TrailingBytes,
              "trailing bytes are refused");
    }

    // Empty and null inputs.
    {
        p2p::PoolBlock pb;
        check(p2p::deserialize(nullptr, 0, cid, p2p::BlobShape::Full, pb)
                  != p2p::BlockStatus::Ok, "null input is refused");
        const std::uint8_t one = 0;
        check(p2p::deserialize(&one, 1, cid, p2p::BlobShape::Full, pb)
                  != p2p::BlockStatus::Ok, "a one-byte blob is refused");
    }
}

// ---------------------------------------------------------------------------
// 7) The read model: contests, cadence, and the refusal to guess.
// ---------------------------------------------------------------------------
void check_read_model() {
    p2p::ReadModel m(p2p::Sidechain::Mini);
    check_eq(m.distinct_blocks(), 0u, "empty model");

    double cad = 0.0;
    std::size_t n = 0;
    check(!m.cadence_seconds(cad, n), "no cadence from zero samples");

    auto mk = [](std::uint8_t tag, std::uint64_t h, std::uint64_t t) {
        p2p::ObservedBlock b;
        b.sidechain_id[0] = tag;
        b.sidechain_height = h;
        b.first_seen_ms = t;
        b.difficulty.lo = 1000;
        b.monero_height = 3760080;
        return b;
    };

    // The first block observed sets the FRONTIER: the tip that already existed
    // when the run started.
    check(m.observe(mk(1, 100, 1000)), "first block is new");
    check_eq(m.frontier_height(), 100u, "frontier is the first height seen");
    check(!m.observe(mk(1, 100, 1500)), "the same id again is a duplicate");
    check_eq(m.duplicate_receives(), 1u, "duplicate counted");
    check(!m.cadence_seconds(cad, n), "no cadence at the frontier itself");
    check_eq(n, 0u, "the frontier height is not a cadence sample");

    // A BACKFILLED ancestor: fetched by the parent walk seconds after the run
    // began, mined long before it. It must not enter the cadence window --
    // counting it is what made the first live run report 4.4 s on a chain that
    // targets 10.
    check(m.observe(mk(2, 99, 2000)), "backfilled ancestor recorded");
    check(!m.cadence_seconds(cad, n), "a backfilled ancestor adds no cadence sample");
    check_eq(n, 0u, "still no live samples");

    check(m.observe(mk(3, 101, 11000)), "first live height");
    check(!m.cadence_seconds(cad, n), "one live height is not a rate");
    check_eq(n, 1u, "one live sample");

    check(m.observe(mk(4, 102, 21000)), "second live height");
    check(m.cadence_seconds(cad, n), "cadence from two live heights");
    check_eq(n, 2u, "two live samples");
    check(cad > 9.9 && cad < 10.1, "ten seconds per live height");

    // More backfill, arriving late, still does not move the rate.
    check(m.observe(mk(7, 98, 22000)), "deeper ancestor backfilled");
    check(m.cadence_seconds(cad, n), "cadence survives more backfill");
    check_eq(n, 2u, "still two live samples");
    check(cad > 9.9 && cad < 10.1, "and the rate is unchanged");

    // A second block at a height that already has one is a contest.
    check_eq(m.contested_heights(), 0u, "no contest yet");
    check(m.observe(mk(5, 101, 11400)), "competing block at the same height");
    check_eq(m.contested_heights(), 1u, "contest recorded");
    const std::vector<p2p::HeightContest> c = m.contests();
    check_eq(c.size(), 1u, "one contested height");
    if (c.size() == 1) {
        check_eq(c[0].height, 101u, "contested height number");
        check_eq(c[0].ids.size(), 2u, "two blocks at that height");
        check_eq(c[0].spread_ms(), 400u, "contest spread in milliseconds");
    }

    // A third block at the same height does not double-count the contest.
    check(m.observe(mk(6, 101, 11800)), "third block at the same height");
    check_eq(m.contested_heights(), 1u, "still one contested height");

    // An uncle is only 'resolved' once the block it names has been seen.
    p2p::ObservedBlock with_uncle = mk(8, 103, 31000);
    p2p::Hash u{};
    u[0] = 5;                       // the loser at height 101, above
    with_uncle.uncles.push_back(u);
    check(m.observe(with_uncle), "block naming an uncle");
    check_eq(m.uncles_seen(), 1u, "uncle counted");
    check_eq(m.uncles_resolved(), 1u, "uncle resolved because we hold that block");

    p2p::ObservedBlock unknown_uncle = mk(9, 104, 41000);
    p2p::Hash v{};
    v[0] = 0xEE;
    unknown_uncle.uncles.push_back(v);
    check(m.observe(unknown_uncle), "block naming an unseen uncle");
    check_eq(m.uncles_seen(), 2u, "second uncle counted");
    check_eq(m.uncles_resolved(), 1u, "the unseen uncle is not resolved");

    check_eq(m.tip_height(), 104u, "tip height");
    check_eq(m.height_span(), 6u, "height span");
    check(m.cadence_seconds(cad, n), "cadence over the whole live window");
    check_eq(n, 4u, "four live heights");
    check(cad > 9.9 && cad < 10.1, "ten seconds per live height across the run");
    check(!m.status(60000).empty(), "status line renders");

    // Difficulty printing, including the 128-bit path.
    p2p::Difficulty d{};
    d.lo = 245492179; d.hi = 0;
    check(d.to_string() == "245492179", "64-bit difficulty prints");
    d.lo = 0; d.hi = 1;
    check(d.to_string() == "18446744073709551616", "128-bit difficulty prints");
    p2p::Difficulty small{}; small.lo = 5;
    check(small < d, "128-bit comparison orders by the high word");
}

// ---------------------------------------------------------------------------
// 8) The external anchors, asserted by name.
// ---------------------------------------------------------------------------
void check_external_anchors() {
    check(std::string(gold::kAExpect.monero_prev_id) == kPublicMoneroId3760079,
          "golden A templates on the publicly reported Monero block 3760079");
    check(std::string(gold::kBExpect.monero_prev_id) == kPublicMoneroId3760077,
          "golden B templates on the publicly reported Monero block 3760077");
    check_eq(gold::kAExpect.monero_height, 3760080ull, "golden A monero height");
    check_eq(gold::kBExpect.monero_height, 3760078ull, "golden B monero height");
    // A's parent is the id this same derivation produced for the previous block
    // of the same live session: the network's own linkage over our arithmetic.
    check(std::string(gold::kAExpect.parent)
              == "5249d3f80d397f1ea09723456d1095cfabbc5b4e945ca4ea8915667d563d680a",
          "golden A's parent is the previous block of the captured session");
}

} // namespace

int main() {
    std::printf("xmr_p2pool_parse_kat: read-only P2Pool sidechain observer\n");

    check_golden("goldenA", gold::kAFrameHex, gold::kAExpect);
    check_golden("goldenB", gold::kBFrameHex, gold::kBExpect);
    check_hash_order();
    check_write_surface();
    check_framing();
    check_handshake();
    check_hostile();
    check_read_model();
    check_external_anchors();

    std::printf("checks=%d failures=%d\n", g_checks, g_fail);
    if (g_fail) { std::printf("KAT FAILED\n"); return 1; }
    std::printf("KAT OK\n");
    return 0;
}
