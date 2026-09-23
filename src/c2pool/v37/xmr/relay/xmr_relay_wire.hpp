// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_relay_wire.hpp   (GAP-2 stage 1)
//
// The Family-B (Monero / RandomX) c2pool-to-c2pool RECEIPT RELAY wire: the
// frames that replace the --credit-feed file and the --wire-in/--wire-out
// directory drop of main_v37_xmr.cpp with real TCP P2P
// (docs/xmr-lane/gap2-sharechain-relay-design.md §3).
//
// Transport = carrier_net.hpp CarrierPeerNode framing [u32 LE len][frame]. The
// FIRST BYTE of a frame selects the codec:
//
//     0x01..0x3f   Family-A CarrierWire versions (0x01/0x02 live) -> counted, ignored
//     0x40..0x4f   ★ Family-B relay (this file; claimed range, KAT-pinned)
//         0x40 FB_HELLO      the pool/consensus-id gate, first frame both ways
//         0x41 FB_RECEIPTS   1..8 PoW-carrying receipts (flood / re-offer)
//         0x42 FB_BLOCK_WON  the block-winner cut descriptor (fast path A)
//     0x80..0x83   carrier_supply.hpp GETORDER/ORDER/GETFRAMES/FRAMES (reused)
//
// Every integer is little-endian, every decoder is TOTAL and BOUNDED (a bad
// frame is reported, never thrown past this header, never allocates more than
// its bound), and the receipt body reuses the ratified MoneroReceipt codec
// (impl/xmr/wire/xmr_carrier_wire.hpp encode_receipt/decode_receipt) verbatim.
//
// THE RECEIPT ON THE WIRE (fb_receipt), and what makes it re-verifiable:
//
//   u16 len ; len bytes = encode_receipt(MoneroReceipt)
//       hashing_blob (the exact RandomX input, nonce included) + the coinbase
//       OPENING (Keccak midstate + tail + tx_extra in the clear) + the leaf-0
//       tree branch + info_digest. A receiver resumes the midstate, forms the
//       coinbase tx hash, walks the branch and requires the root it gets to be
//       the tree_root INSIDE the RandomX-hashed blob; then RandomX(blob) must
//       meet the lane's share difficulty. A forged or altered blob/coinbase
//       fails one of those two checks.
//   side_data_v2 (56 B) = t_origin.lo u64 | t_origin.hi u64 | identity b32 |
//       chain_id u32 | give_author u16 | reserved u16
//   payee ref (66 B)    = u8 kind (0x10 XMR_STD | 0x11 XMR_SUB) | u8 len=64 | 64 B
//
//   info_digest == side_digest_v2(side) (self-consistency), identity ==
//   xmr_identity_key(payee). The PoW BINDING of side_data_v2 (payee, give-
//   author) is rbind_v1(chain_id, side) inside the coinbase 0x02 region
//   [extra_nonce 4 | rbind 32] -- SEAM-1: the template writes it per job
//   (IXmrSettlementSource::extra_nonce_bind, xmr_rbind_registry.hpp) when the
//   node runs --relay-bind rbind. BindMode::Rbind enforces it; BindMode::None
//   relays PoW-verified receipts whose payee is carried, dedup-keyed on the
//   blob, but NOT PoW-bound. HELLO pins the mode so two nodes can never
//   disagree on it silently.
//
// This header defines NO consensus digest and includes nothing from
// src/sharechain/v37 beyond the descriptor / lane-param TYPES it reads.
// ===========================================================================
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>             // ::v37::bytes32
#include <sharechain/v37/v37_descriptor_xmr.hpp>   // ScriptRef, XMR_STD/XMR_SUB, xmr_identity_key
#include <sharechain/v37/v37_lane.hpp>             // ::v37::LaneParams (read-only, for the HELLO digest)

#include "impl/xmr/receipt/xmr_receipt.hpp"        // ::v37::xmr::MoneroReceipt
#include "impl/xmr/wire/xmr_carrier_wire.hpp"      // encode_receipt / decode_receipt (the ratified codec)
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"   // ::xmr::coin::keccak256
#include "../xmr_fee_model.hpp"                    // S4: the fee-model gate folded into lane_params_digest

namespace c2pool::v37n::xmr::relay {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using bytes32 = ::v37::bytes32;

// ── the first-byte namespace ────────────────────────────────────────────────
inline constexpr u8  FB_NS_FIRST  = 0x40;
inline constexpr u8  FB_NS_LAST   = 0x4f;
inline constexpr u8  FB_HELLO     = 0x40;
inline constexpr u8  FB_RECEIPTS  = 0x41;
inline constexpr u8  FB_BLOCK_WON = 0x42;
inline constexpr u8  kFbVersion   = 0x01;
inline constexpr u32 kFbMagic     = 0x52583243u;   // bytes 'C','2','X','R' little-endian

inline constexpr bool is_family_b_opcode(u8 b) { return b >= FB_NS_FIRST && b <= FB_NS_LAST; }

// ── bounds ──────────────────────────────────────────────────────────────────
// SEAM-2: the digest-committed per-receipt budget for the XMR lane is 768 B
// (v37::xmr::budget::PER_RECEIPT_BUDGET). A settlement coinbase that carries the
// 44-byte credit-cut tail (and, after SEAM-1, the 32-byte rbind) opens to a
// larger tx_extra than the 768 figure was sized for, so the relay decodes
// against 1024 B. Raising the committed value is the operator's ruling; until
// then this relay-local bound is what an honest maximal receipt needs.
inline constexpr std::size_t kFbReceiptBudget       = 1024;
inline constexpr std::size_t kFbMaxReceiptsPerFrame = 8;
inline constexpr std::size_t kSideV2Bytes           = 56;
inline constexpr std::size_t kPayeeBytes            = 66;   // kind + len + 64
inline constexpr std::size_t kFbReceiptMaxBytes     = 2 + kFbReceiptBudget + kSideV2Bytes + kPayeeBytes;
inline constexpr std::size_t kFbReceiptsHeader      = 1 + 1 + 4 + 1;
inline constexpr std::size_t kFbMaxFrame            = kFbReceiptsHeader + kFbMaxReceiptsPerFrame * kFbReceiptMaxBytes;
inline constexpr std::size_t kHelloBytes            = 1 + 1 + 4 + 1 + 4 + 32 + 8 + 8 + 2 + 8 + 32 + 1;   // 102
inline constexpr std::size_t kBlockWonBytes         = 1 + 1 + 4 + 32 + 8 + 8 + 32 + 8 + 1 + 32;       // 127

// The work one receipt contributes to the lane (LaneRecord::push w). Every
// receipt is admitted at EXACTLY the lane share difficulty (R-1, HELLO-pinned),
// so one receipt = one unit -- the same "idx 1" the credit-feed stand-in wrote.
inline constexpr u64 kReceiptWeight = 1;

enum class BindMode : u8 { None = 0, Rbind = 1 };
inline const char* to_string(BindMode m) { return m == BindMode::Rbind ? "rbind" : "none"; }

// ── little-endian helpers ───────────────────────────────────────────────────
namespace le {
inline void put16(std::vector<u8>& b, u16 v) { b.push_back(u8(v)); b.push_back(u8(v >> 8)); }
inline void put32(std::vector<u8>& b, u32 v) { for (int i = 0; i < 4; ++i) b.push_back(u8(v >> (8 * i))); }
inline void put64(std::vector<u8>& b, u64 v) { for (int i = 0; i < 8; ++i) b.push_back(u8(v >> (8 * i))); }
inline void putb(std::vector<u8>& b, const bytes32& h) { b.insert(b.end(), h.begin(), h.end()); }
inline u16 get16(const u8* p) { return u16(p[0] | (u16(p[1]) << 8)); }
inline u32 get32(const u8* p) { u32 v = 0; for (int i = 0; i < 4; ++i) v |= u32(p[i]) << (8 * i); return v; }
inline u64 get64(const u8* p) { u64 v = 0; for (int i = 0; i < 8; ++i) v |= u64(p[i]) << (8 * i); return v; }
inline bytes32 getb(const u8* p) { bytes32 h; std::memcpy(h.data(), p, 32); return h; }
} // namespace le

inline bytes32 keccak_bytes(const std::vector<u8>& v) {
    const auto h = ::xmr::coin::keccak256(v.data(), v.size());
    bytes32 out; std::memcpy(out.data(), h.data(), 32); return out;
}

// ── side_data_v2 ────────────────────────────────────────────────────────────
struct SideDataV2 {
    u64     t_lo = 0, t_hi = 0;      // T_origin (R-1: == the lane share difficulty)
    bytes32 identity{};              // xmr_identity_key(payee)
    u32     chain_id = 0;            // lane ChainId
    u16     give_author = 0;         // the receipt-carried give-author u16 (fee model S3; folded only under FeeModelGate)
    u16     reserved = 0;            // must be 0

    std::vector<u8> bytes() const {
        std::vector<u8> b; b.reserve(kSideV2Bytes);
        le::put64(b, t_lo); le::put64(b, t_hi); le::putb(b, identity);
        le::put32(b, chain_id); le::put16(b, give_author); le::put16(b, reserved);
        return b;
    }
    static SideDataV2 from(const u8* p) {
        SideDataV2 s;
        s.t_lo = le::get64(p); s.t_hi = le::get64(p + 8); s.identity = le::getb(p + 16);
        s.chain_id = le::get32(p + 48); s.give_author = le::get16(p + 52); s.reserved = le::get16(p + 54);
        return s;
    }
    bool operator==(const SideDataV2&) const = default;
};

inline constexpr char kSideV2Domain[] = "c2pool-v37-xmr-side-v2";
inline constexpr char kRbindDomain[]  = "c2pool-v37-xmr-rbind-v1";
inline constexpr char kLaneParamsDomain[] = "c2pool-v37-xmr-lane-params-v1";

// info_digest of a v2 receipt = keccak256(domain || side_data_v2 bytes).
inline bytes32 side_digest_v2(const SideDataV2& s) {
    std::vector<u8> b(kSideV2Domain, kSideV2Domain + sizeof(kSideV2Domain) - 1);
    const auto sb = s.bytes(); b.insert(b.end(), sb.begin(), sb.end());
    return keccak_bytes(b);
}

// SEAM-1 binding value: what the per-worker coinbase 0x02 region carries after
// the 4-byte extra_nonce once the template writes it.
inline bytes32 rbind_v1(u32 chain_id, const SideDataV2& s) {
    std::vector<u8> b(kRbindDomain, kRbindDomain + sizeof(kRbindDomain) - 1);
    le::put32(b, chain_id);
    const auto sb = s.bytes(); b.insert(b.end(), sb.begin(), sb.end());
    return keccak_bytes(b);
}

// ── the relayed receipt ─────────────────────────────────────────────────────
struct FbReceipt {
    ::v37::xmr::MoneroReceipt receipt;
    SideDataV2                side;
    ::v37::ScriptRef          payee;
};

// receipt_id = keccak256(hashing_blob) -- byte-identical to
// v37::xmr::verify::cheap_receipt_id (KAT-pinned), the admission dedup key.
inline bytes32 receipt_id_of_blob(const std::vector<u8>& blob) { return keccak_bytes(blob); }
inline bytes32 receipt_id(const FbReceipt& r) { return receipt_id_of_blob(r.receipt.hashing_blob.bytes); }

// Encode one fb_receipt. Empty on an unencodable input (never throws).
inline std::vector<u8> encode_fb_receipt(const FbReceipt& r) {
    std::vector<u8> body;
    try {
        ::v37::xmr::wire::Writer w;
        ::v37::xmr::wire::encode_receipt(w, r.receipt);
        body = std::move(w.out);
    } catch (...) { return {}; }
    if (body.empty() || body.size() > kFbReceiptBudget) return {};
    if (!::v37::xmr::is_xmr_kind(r.payee.kind) || r.payee.payload.size() != 64) return {};
    std::vector<u8> out; out.reserve(2 + body.size() + kSideV2Bytes + kPayeeBytes);
    le::put16(out, static_cast<u16>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    const auto sb = r.side.bytes(); out.insert(out.end(), sb.begin(), sb.end());
    out.push_back(static_cast<u8>(r.payee.kind));
    out.push_back(64);
    out.insert(out.end(), r.payee.payload.begin(), r.payee.payload.end());
    return out;
}

// Decode one fb_receipt starting at p (n bytes available). `used` = bytes
// consumed. Total: false + why on ANY malformation, never throws.
inline bool decode_fb_receipt(const u8* p, std::size_t n, std::size_t& used, FbReceipt& out,
                              std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (n < 2) return bad("fb_receipt: short (len)");
    const std::size_t len = le::get16(p);
    if (len == 0 || len > kFbReceiptBudget) return bad("fb_receipt: receipt len over the relay budget");
    if (n < 2 + len + kSideV2Bytes + kPayeeBytes) return bad("fb_receipt: short (body/side/payee)");
    try {
        ::v37::xmr::wire::Reader rd(p + 2, len);
        out.receipt = ::v37::xmr::wire::decode_receipt(rd, kFbReceiptBudget);
        if (!rd.eof()) return bad("fb_receipt: trailing bytes inside the receipt body");
    } catch (const std::exception& e) {
        if (why) *why = std::string("fb_receipt: ") + e.what();
        return false;
    }
    const u8* q = p + 2 + len;
    out.side = SideDataV2::from(q);
    q += kSideV2Bytes;
    const u8 kind = q[0], plen = q[1];
    if (!::v37::xmr::is_xmr_kind(static_cast<::v37::ScriptKind>(kind))) return bad("fb_receipt: payee kind is not XMR_STD/XMR_SUB");
    if (plen != 64) return bad("fb_receipt: payee payload length != 64");
    out.payee.kind = static_cast<::v37::ScriptKind>(kind);
    out.payee.payload.assign(q + 2, q + 2 + 64);
    used = 2 + len + kSideV2Bytes + kPayeeBytes;
    return true;
}
inline bool decode_fb_receipt(const std::vector<u8>& b, FbReceipt& out, std::string* why = nullptr) {
    std::size_t used = 0;
    if (!decode_fb_receipt(b.data(), b.size(), used, out, why)) return false;
    if (used != b.size()) { if (why) *why = "fb_receipt: trailing bytes"; return false; }
    return true;
}

// ── FB_RECEIPTS (0x41) ──────────────────────────────────────────────────────
// u8 0x41 ; u8 ver ; u32 chain_id ; u8 n (1..8) ; n x fb_receipt
// Built from already-ENCODED fb_receipt bytes (the vault stores exactly those,
// so a flood, a re-offer and a GETFRAMES serve are the same bytes).
inline std::vector<u8> encode_receipts_frame(u32 chain_id, const std::vector<const std::vector<u8>*>& encoded) {
    if (encoded.empty() || encoded.size() > kFbMaxReceiptsPerFrame) return {};
    std::vector<u8> f; f.reserve(kFbReceiptsHeader + encoded.size() * 800);
    f.push_back(FB_RECEIPTS); f.push_back(kFbVersion); le::put32(f, chain_id);
    f.push_back(static_cast<u8>(encoded.size()));
    for (const auto* e : encoded) { if (!e || e->empty()) return {}; f.insert(f.end(), e->begin(), e->end()); }
    return f.size() <= kFbMaxFrame ? f : std::vector<u8>{};
}

struct ReceiptsFrame {
    u32 chain_id = 0;
    std::vector<FbReceipt>       receipts;
    std::vector<std::vector<u8>> raw;       // each receipt's exact fb_receipt bytes
};

inline bool decode_receipts_frame(const std::vector<u8>& f, ReceiptsFrame& out, std::string* why = nullptr) {
    auto bad = [&](const std::string& m) { if (why) *why = m; return false; };
    if (f.size() > kFbMaxFrame) return bad("receipts: frame over kFbMaxFrame");
    if (f.size() < kFbReceiptsHeader) return bad("receipts: short header");
    if (f[0] != FB_RECEIPTS) return bad("receipts: wrong opcode");
    if (f[1] != kFbVersion) return bad("receipts: unknown version");
    out.chain_id = le::get32(f.data() + 2);
    const std::size_t n = f[6];
    if (n == 0 || n > kFbMaxReceiptsPerFrame) return bad("receipts: n out of range (1..8)");
    out.receipts.clear(); out.raw.clear();
    std::size_t off = kFbReceiptsHeader;
    for (std::size_t i = 0; i < n; ++i) {
        FbReceipt r; std::size_t used = 0; std::string w;
        if (!decode_fb_receipt(f.data() + off, f.size() - off, used, r, &w))
            return bad("receipts[" + std::to_string(i) + "]: " + w);
        out.raw.emplace_back(f.begin() + static_cast<std::ptrdiff_t>(off),
                             f.begin() + static_cast<std::ptrdiff_t>(off + used));
        out.receipts.push_back(std::move(r));
        off += used;
    }
    if (off != f.size()) return bad("receipts: trailing bytes after the last receipt");
    return true;
}

// ── FB_HELLO (0x40) ─────────────────────────────────────────────────────────
struct Hello {
    u8      network = 0;              // 0 mainnet 1 testnet 2 stagenet 3 regtest
    u32     chain_id = 0;
    bytes32 lane_params_digest{};
    u64     share_diff = 0;
    u64     node_nonce = 0;           // per process; self-connect detection
    u16     listen_port = 0;          // 0 = dial-only
    u64     lane_next_pos = 0;        // our lane tip (diagnostic + backfill hint)
    bytes32 lane_digest{};            // LaneSnapshot digest at that tip (diagnostic)
    BindMode bind = BindMode::None;
    bool operator==(const Hello&) const = default;
};

inline std::vector<u8> encode_hello(const Hello& h) {
    std::vector<u8> f; f.reserve(kHelloBytes);
    f.push_back(FB_HELLO); f.push_back(kFbVersion); le::put32(f, kFbMagic);
    f.push_back(h.network); le::put32(f, h.chain_id); le::putb(f, h.lane_params_digest);
    le::put64(f, h.share_diff); le::put64(f, h.node_nonce); le::put16(f, h.listen_port);
    le::put64(f, h.lane_next_pos); le::putb(f, h.lane_digest); f.push_back(static_cast<u8>(h.bind));
    return f;
}

inline bool decode_hello(const std::vector<u8>& f, Hello& h, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() != kHelloBytes) return bad("hello: wrong length");
    if (f[0] != FB_HELLO) return bad("hello: wrong opcode");
    if (f[1] != kFbVersion) return bad("hello: unknown version");
    if (le::get32(f.data() + 2) != kFbMagic) return bad("hello: bad magic (not a c2pool XMR relay)");
    const u8* p = f.data() + 6;
    h.network = p[0]; p += 1;
    h.chain_id = le::get32(p); p += 4;
    h.lane_params_digest = le::getb(p); p += 32;
    h.share_diff = le::get64(p); p += 8;
    h.node_nonce = le::get64(p); p += 8;
    h.listen_port = le::get16(p); p += 2;
    h.lane_next_pos = le::get64(p); p += 8;
    h.lane_digest = le::getb(p); p += 32;
    if (p[0] > static_cast<u8>(BindMode::Rbind)) return bad("hello: unknown bind mode");
    h.bind = static_cast<BindMode>(p[0]);
    return true;
}

// Why a peer's HELLO does not match ours ("" = compatible). The fields are the
// ones that decide whether two nodes can fold the same lane: a mismatch is an
// EXPLICIT refusal with a reason, never a silent divergence (the memory-recorded
// "mismatched-LaneParams nodes must reject explicitly" gap).
inline std::string hello_mismatch(const Hello& ours, const Hello& theirs) {
    if (theirs.network != ours.network)   return "network " + std::to_string(theirs.network) + " != ours " + std::to_string(ours.network);
    if (theirs.chain_id != ours.chain_id) return "lane chain_id " + std::to_string(theirs.chain_id) + " != ours " + std::to_string(ours.chain_id);
    if (theirs.share_diff != ours.share_diff)
        return "share_diff " + std::to_string(theirs.share_diff) + " != ours " + std::to_string(ours.share_diff) + " (R-1 pin)";
    if (theirs.bind != ours.bind) return std::string("bind mode ") + to_string(theirs.bind) + " != ours " + to_string(ours.bind);
    if (theirs.lane_params_digest != ours.lane_params_digest) return "lane_params_digest differs (different LaneParams geometry/gates)";
    if (theirs.node_nonce == ours.node_nonce) return "self-connection (node_nonce equal)";
    return "";
}

// ── FB_BLOCK_WON (0x42) ─────────────────────────────────────────────────────
// The frozen v0x02 CutDescriptor field list (w3_relay.hpp), flat.
struct BlockWon {
    u32     chain_id = 0;
    bytes32 bid{};
    u64     h_b = 0;
    u64     cut_next_pos = 0;
    bytes32 cut_spine_digest{};
    u64     reward = 0;
    bool    payout_emitted = false;
    bytes32 owed_digest_at_win{};
    bool operator==(const BlockWon&) const = default;
};

inline std::vector<u8> encode_block_won(const BlockWon& b) {
    std::vector<u8> f; f.reserve(kBlockWonBytes);
    f.push_back(FB_BLOCK_WON); f.push_back(kFbVersion); le::put32(f, b.chain_id);
    le::putb(f, b.bid); le::put64(f, b.h_b); le::put64(f, b.cut_next_pos); le::putb(f, b.cut_spine_digest);
    le::put64(f, b.reward); f.push_back(b.payout_emitted ? 1 : 0); le::putb(f, b.owed_digest_at_win);
    return f;
}

inline bool decode_block_won(const std::vector<u8>& f, BlockWon& b, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (f.size() != kBlockWonBytes) return bad("block_won: wrong length");
    if (f[0] != FB_BLOCK_WON) return bad("block_won: wrong opcode");
    if (f[1] != kFbVersion) return bad("block_won: unknown version");
    const u8* p = f.data() + 2;
    b.chain_id = le::get32(p); p += 4;
    b.bid = le::getb(p); p += 32;
    b.h_b = le::get64(p); p += 8;
    b.cut_next_pos = le::get64(p); p += 8;
    b.cut_spine_digest = le::getb(p); p += 32;
    b.reward = le::get64(p); p += 8;
    if (p[0] > 1) return bad("block_won: payout_emitted not 0/1");
    b.payout_emitted = p[0] != 0; p += 1;
    b.owed_digest_at_win = le::getb(p);
    return true;
}

// ── SEAM-4: the lane-parameter digest HELLO carries ─────────────────────────
// A canonical serialization of every LaneParams field that decides the lane
// digest or the fold (geometry + the four ADD-ONLY gates), the R-1 share
// difficulty, the bind mode and the per-receipt weight rule. Two nodes whose
// digests differ would fold different lanes from identical receipts; they now
// refuse each other at HELLO instead. The field order is pinned by a golden in
// xmr_relay_wire_kat -- a LaneParams field added later must be appended here.
inline bytes32 lane_params_digest(const ::v37::LaneParams& p, u64 share_diff, BindMode bind) {
    std::vector<u8> b(kLaneParamsDomain, kLaneParamsDomain + sizeof(kLaneParamsDomain) - 1);
    le::put64(b, p.window); le::put64(b, p.c0); le::put64(b, p.rollup);
    le::put32(b, static_cast<u32>(p.level_caps.size()));
    for (u64 c : p.level_caps) le::put64(b, c);
    le::put64(b, p.half_life); le::put64(b, p.journal_depth);
    // subthreshold (RDWR-OQ2)
    b.push_back(p.subthreshold.enabled ? 1 : 0);
    le::put32(b, p.subthreshold.K); le::put32(b, p.subthreshold.mode); le::put32(b, p.subthreshold.version);
    // mrr
    le::put64(b, p.mrr.activation_pos); le::put64(b, p.mrr.ckpt_retain);
    // win
    le::put64(b, p.win.win_activation_pos); le::put32(b, p.win.win_version);
    le::put64(b, p.win.coverage_blocks); le::put64(b, p.win.bin_seconds); le::put64(b, p.win.w_min_bins);
    le::put64(b, p.win.w_default_bins); le::put64(b, p.win.w_max_bins); le::put64(b, p.win.retarget_bins);
    le::put64(b, p.win.damp_factor); le::put64(b, p.win.burial_depth); le::put64(b, p.win.lambda_levels);
    // nr
    le::put64(b, p.nr.nr_activation_pos); le::put32(b, p.nr.nr_version); le::put64(b, p.nr.fold_cap);
    le::put64(b, p.nr.open_horizon_bins); le::put64(b, p.nr.w_min_bins); le::put64(b, p.nr.w_max_bins);
    le::put64(b, p.nr.w_default_bins); le::put64(b, p.nr.coverage_blocks); le::put64(b, p.nr.bin_seconds);
    le::put64(b, p.nr.retarget_bins); le::put64(b, p.nr.ckpt_bins); le::put64(b, p.nr.n_ctx_bins);
    b.push_back(p.nr.allow_digit_repeat ? 1 : 0);
    // relay-level consensus pins
    le::put64(b, share_diff);
    b.push_back(static_cast<u8>(bind));
    le::put64(b, kReceiptWeight);
    // S4 (fee model): the FeeModelGate is folded ONLY when it is ON, so a
    // gate-OFF node's digest stays byte-identical to master's (the W4 golden
    // does not move) while a gate-ON node differs from BOTH a gate-OFF node
    // and a master node -> a mixed fleet refuses at HELLO, never diverges.
    // Folds the version, the per-receipt weight rule and the compiled-in
    // donation identity (a node with another donation address refuses too).
    if (p.fee.enabled) {
        static constexpr char kFeeTag[] = "FEE1";
        b.insert(b.end(), kFeeTag, kFeeTag + 4);
        le::put32(b, p.fee.version);
        le::put64(b, ::c2pool::v37n::xmr::fee::kFeeReceiptWeight);
        le::putb(b, ::c2pool::v37n::xmr::fee::donation_identity());
    }
    return keccak_bytes(b);
}

} // namespace c2pool::v37n::xmr::relay
