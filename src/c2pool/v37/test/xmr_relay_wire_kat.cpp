// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// xmr_relay_wire_kat -- the kept Family-B relay frames (xmr/relay/xmr_relay_wire.hpp; RandomX-free):
//   W1  opcodes: FB_GETCTX 0x43, FB_CTX 0x44, FB_PING 0x48, FB_PONG 0x49, FB_GETADDR 0x4c, FB_ADDR 0x4d, distinct,
//       equal to the Path B relay wire's (impl/xmr/pathb/pathb_relay_wire.hpp), none on 0x4a / 0x4b, none a
//       Family-A CarrierWire version, all below the control opcodes (0x80)
//   W2  FB_GETCTX / FB_CTX: golden bytes, round trip, refusals (opcode, version, n 0 / 9, length, blob over
//       the caller's cap, here P-13 at hf 16 = 600,051); both decoders total under truncation
//   W3  FB_PING / FB_PONG: golden bytes, round trip, refusals
//   W7  base58 address decode (checksum, prefixes) of a known address
//   W8  FB_GETADDR / FB_ADDR: golden bytes, round trip, bounds, refusals, the routable filter
#include <cstdio>
#include <set>
#include <string>
#include <vector>

#include <c2pool/v37/carrier_net.hpp>
#include <c2pool/v37/w3_wire_freeze.hpp>
#include <c2pool/v37/xmr/relay/xmr_address.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>
#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_relay_wire.hpp"

using namespace c2pool::v37n::xmr::relay;
namespace pb = ::c2pool::xmr::pathb;

namespace {
int g_checks = 0, g_fail = 0;
void C(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("  FAIL: %s\n", what.c_str()); }
}
std::string hex(const std::vector<u8>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (u8 b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
    return s;
}
bytes32 fill32(u8 b) { bytes32 h; h.fill(b); return h; }
std::string rep(const char* two, int n) { std::string s; for (int i = 0; i < n; ++i) s += two; return s; }
}  // namespace

int main() {
    std::printf("== xmr_relay_wire_kat ==\n");

    // ── W1 opcodes ──────────────────────────────────────────────────────────
    {
        const std::vector<u8> ops = {FB_GETCTX, FB_CTX, FB_PING, FB_PONG, FB_GETADDR, FB_ADDR};
        C(FB_GETCTX == 0x43 && FB_CTX == 0x44 && FB_PING == 0x48 && FB_PONG == 0x49 && FB_GETADDR == 0x4c && FB_ADDR == 0x4d,
          "W1 the kept opcodes 0x43 0x44 0x48 0x49 0x4c 0x4d");
        C(std::set<u8>(ops.begin(), ops.end()).size() == ops.size(), "W1 the kept opcodes are distinct");
        C(FB_GETCTX == pb::kOpFbGetCtx && FB_CTX == pb::kOpFbCtx && FB_PING == pb::kOpFbPing && FB_PONG == pb::kOpFbPong &&
          FB_GETADDR == pb::kOpFbGetAddr && FB_ADDR == pb::kOpFbAddr,
          "W1 equal to the Path B relay wire's opcodes");
        bool clash = false, reserved = false, ctrl = false;
        for (u8 o : ops) {
            for (std::uint8_t v : c2pool::v37n::wire_freeze::kAcceptedVersions) clash = clash || o == v;
            reserved = reserved || o == 0x4a || o == 0x4b;
            ctrl = ctrl || o >= c2pool::v37n::kCtrlOpcodeBase;
        }
        C(!clash, "W1 no kept opcode is a Family-A accepted CarrierWire version");
        C(!reserved, "W1 no kept opcode uses 0x4a / 0x4b");
        C(!ctrl, "W1 every kept opcode lies below the control opcodes (0x80)");
        const std::size_t cap16 = ::c2pool::xmr::pathb::blob_cap_ctx(16, ::c2pool::xmr::pathb::zone(16)).value_or(0);
        C(cap16 == 600051 && kCtxHeader + cap16 < c2pool::v37n::kMaxCarrierFrame &&
                  kAddrMaxFrame < c2pool::v37n::kMaxCarrierFrame,
          "W1 the FB_CTX frame at P-13 (hf 16: 600,051) and the largest FB_ADDR frame fit the transport ceiling");
    }

    // ── W2 FB_GETCTX / FB_CTX ───────────────────────────────────────────────
    {
        const std::vector<u8> g = encode_getctx(7, {fill32(0x11), fill32(0x12)});
        C(hex(g) == "4301" "07000000" "02" + rep("11", 32) + rep("12", 32), "W2 getctx(7, [11.., 12..]) golden");
        u32 ch = 0; std::vector<bytes32> ids; std::string why;
        C(decode_getctx(g, ch, ids, &why) && ch == 7 && ids.size() == 2 && ids[0] == fill32(0x11) && ids[1] == fill32(0x12),
          "W2 getctx round-trip");
        C(encode_getctx(7, {}).empty() && encode_getctx(7, std::vector<bytes32>(kCtxMaxIds + 1, fill32(1))).empty(),
          "W2 getctx with 0 or 9 ids not encodable");
        C(encode_getctx(7, std::vector<bytes32>(kCtxMaxIds, fill32(1))).size() == 7 + 32 * kCtxMaxIds, "W2 getctx with 8 ids");
        std::vector<u8> b = g; b[0] = FB_CTX;   C(!decode_getctx(b, ch, ids), "W2 getctx wrong opcode refused");
        b = g; b[1] = 2;                         C(!decode_getctx(b, ch, ids), "W2 getctx unknown version refused");
        b = g; b[6] = 0;                         C(!decode_getctx(b, ch, ids), "W2 getctx n 0 refused");
        b = g; b[6] = 9;                         C(!decode_getctx(b, ch, ids), "W2 getctx n 9 refused");
        {   // nine ids, the length matching nine
            std::vector<u8> nine = {FB_GETCTX, kFbVersion, 7, 0, 0, 0, 9};
            for (int i = 0; i < 9; ++i) { const bytes32 id = fill32(static_cast<u8>(0x20 + i)); nine.insert(nine.end(), id.begin(), id.end()); }
            C(!decode_getctx(nine, ch, ids), "W2 getctx with 9 ids (length consistent) refused");
        }
        b = g; b.push_back(0);                   C(!decode_getctx(b, ch, ids), "W2 getctx trailing byte refused");
        b = g; b.pop_back();                     C(!decode_getctx(b, ch, ids), "W2 getctx truncated refused");

        // cap: P-13 at hf 16, Z = zone(16) (blob_cap_ctx = 600,051)
        const std::size_t cap = ::c2pool::xmr::pathb::blob_cap_ctx(16, ::c2pool::xmr::pathb::zone(16)).value_or(0);
        const std::vector<u8> blob = {'a', 'b', 'c'};
        const std::vector<u8> c = encode_ctx(7, fill32(0x22), blob, cap);
        C(hex(c) == "4401" "07000000" + rep("22", 32) + "03000000" "616263", "W2 ctx(7, 22.., \"abc\") golden");
        bytes32 id{}; std::vector<u8> got;
        C(decode_ctx(c, ch, id, got, cap, &why) && ch == 7 && id == fill32(0x22) && got == blob, "W2 ctx round-trip");
        const std::vector<u8> none = encode_ctx(7, fill32(0x22), {}, cap);
        C(none.size() == kCtxHeader && decode_ctx(none, ch, id, got, cap) && got.empty(),
          "W2 ctx with an empty blob (unknown here)");
        C(encode_ctx(7, fill32(1), std::vector<u8>(cap + 1, 0), cap).empty(), "W2 ctx blob over the cap not encodable");
        const std::vector<u8> full = encode_ctx(7, fill32(1), std::vector<u8>(cap, 0), cap);
        C(full.size() == kCtxHeader + cap && decode_ctx(full, ch, id, got, cap) && got.size() == cap,
          "W2 ctx blob at the cap (600,051 B) accepted");
        b = c; b[38] = 0; b[39] = 0; b[40] = 8; b[41] = 0;   // claims 0x00080000 = 524288 bytes, carries 3
        C(!decode_ctx(b, ch, id, got, cap), "W2 ctx len != the frame's bytes refused");
        std::vector<u8> over(kCtxHeader, 0); over[0] = FB_CTX; over[1] = kFbVersion;
        const std::size_t cap1 = cap + 1;   // 600,052
        over[38] = static_cast<u8>(cap1); over[39] = static_cast<u8>(cap1 >> 8); over[40] = static_cast<u8>(cap1 >> 16);
        over[41] = static_cast<u8>(cap1 >> 24);
        C(!decode_ctx(over, ch, id, got, cap), "W2 ctx len over the cap refused");
        over.resize(kCtxHeader + cap1, 0);   // the frame carries the cap + 1 bytes it claims
        C(!decode_ctx(over, ch, id, got, cap), "W2 ctx of the cap + 1 (length consistent) refused");
        C(decode_ctx(over, ch, id, got, cap1) && got.size() == cap1, "W2 the same frame under a cap one byte higher decodes");
        b = c; b[0] = FB_GETCTX;                 C(!decode_ctx(b, ch, id, got, cap), "W2 ctx wrong opcode refused");
        b = c; b[1] = 2;                         C(!decode_ctx(b, ch, id, got, cap), "W2 ctx unknown version refused");
        bool total = true;
        for (std::size_t n = 0; n <= c.size(); ++n) {
            const std::vector<u8> t(c.begin(), c.begin() + static_cast<std::ptrdiff_t>(n));
            try {
                u32 x = 0; bytes32 y{}; std::vector<u8> z; std::vector<bytes32> w;
                const bool ok1 = decode_ctx(t, x, y, z, cap);
                (void)decode_getctx(t, x, w);
                if (ok1 != (n == c.size())) total = false;
            } catch (...) { total = false; }
        }
        C(total, "W2 the FB_CTX / FB_GETCTX decoders are total under truncation (only the whole frame decodes)");
    }

    // ── W3 FB_PING / FB_PONG ────────────────────────────────────────────────
    {
        const std::vector<u8> p = encode_ping(FB_PING, 0x1122334455667788ull);
        C(hex(p) == "4801" "8877665544332211", "W3 ping golden");
        u8 op = 0; u64 n = 0;
        C(decode_ping(p, op, n) && op == FB_PING && n == 0x1122334455667788ull, "W3 ping round-trip");
        const std::vector<u8> q = encode_ping(FB_PONG, 7);
        C(hex(q) == "4901" "0700000000000000" && decode_ping(q, op, n) && op == FB_PONG && n == 7, "W3 pong golden + round-trip");
        C(encode_ping(FB_GETCTX, 1).empty(), "W3 another opcode not encodable");
        std::vector<u8> b = p; b.pop_back();     C(!decode_ping(b, op, n), "W3 wrong length refused");
        b = p; b[1] = 2;                         C(!decode_ping(b, op, n), "W3 unknown version refused");
        b = p; b[0] = FB_GETADDR;                C(!decode_ping(b, op, n), "W3 wrong opcode refused");
    }

    // ── W7 base58 ───────────────────────────────────────────────────────────
    {
        const std::string addr = "47hHNpPZU8qQRAQ2LZupNPiQoeQvo18tA5DPZvwkWajH1qsUkwHmbugfMyoXv1yQdPQhDTq6x8MFiV6cMmi7uUmX7yhotxk";
        const auto d = decode_address(addr);
        C(d.has_value() && d->prefix == 18 && !d->subaddress && !d->integrated, "W7 mainnet/regtest standard address decodes (prefix 18, checksum ok)");
        if (d) {
            C(hex(std::vector<u8>(d->spend.begin(), d->spend.end())) == "a03ab8e2191c928bffa5c875c42834f793a356c12cd6d319310619055bcc7005",
              "W7 spend golden");
            C(hex(std::vector<u8>(d->view.begin(), d->view.end())) == "099b5b60c9a497e55985b3843c3fda8da741814c39f0cda7fab35c0c4c1c023d",
              "W7 view golden");
            C(::v37::xmr::xmr_ref_valid(d->ref()), "W7 decoded keys are valid ed25519 points (payee ref valid)");
        }
        std::string bad = addr; bad[20] = (bad[20] == 'a') ? 'b' : 'a';
        C(!decode_address(bad).has_value(), "W7 one flipped character -> checksum refusal");
        C(!decode_address(addr.substr(0, 90)).has_value(), "W7 truncated address -> refused");
        C(!decode_address("0OIl" + addr.substr(4)).has_value(), "W7 non-alphabet characters -> refused");
    }

    // ── W8 FB_GETADDR (0x4c) / FB_ADDR (0x4d) ───────────────────────────────
    {
        const auto g = encode_getaddr(7, 64);
        C(hex(g) == "4c01070000004000", "W8 getaddr(7,64) golden");
        u32 ch = 0; u16 want = 0; std::string why;
        C(decode_getaddr(g, ch, want, &why) && ch == 7 && want == 64, "W8 getaddr round-trip");
        C(encode_getaddr(7, 0).empty() && encode_getaddr(7, 257).empty(), "W8 getaddr want 0 / 257 not encodable");
        auto gb = g; gb[6] = 0; gb[7] = 0;
        C(!decode_getaddr(gb, ch, want), "W8 getaddr want 0 refused");
        gb = g; gb.push_back(0);
        C(!decode_getaddr(gb, ch, want), "W8 getaddr trailing byte refused");
        gb = g; gb[1] = 2;
        C(!decode_getaddr(gb, ch, want), "W8 getaddr unknown version refused");

        AddrEntry a4, a6;
        C(addr_entry_of("203.0.113.9", 59321, 1700000000, a4) && a4.family == kAddrFamV4, "W8 IPv4 literal -> entry");
        C(addr_entry_of("2001:db8::7", 59321, 1700000001, a6) && a6.family == kAddrFamV6, "W8 IPv6 literal -> entry");
        C(!addr_entry_of("pool.example", 1, 0, a4 = AddrEntry{}), "W8 a DNS name is not an entry (no resolution on the wire)");
        addr_entry_of("203.0.113.9", 59321, 1700000000, a4);
        const auto f = encode_addr(7, {a4, a6});
        C(f.size() == kAddrHeader + 2 * kAddrEntryBytes, "W8 addr frame = 8 + 2 x 27 bytes");
        C(hex(f) == "4d0107000000020004cb007109000000000000000000000000b9e700f15365000000000620010db8000000000000000000000007b9e701f1536500000000",
          "W8 addr(7,[v4,v6]) golden");
        std::vector<AddrEntry> v;
        C(decode_addr(f, ch, v, &why) && ch == 7 && v.size() == 2 && v[0] == a4 && v[1] == a6, "W8 addr round-trip (v4 + v6)");
        C(addr_host(v[0]) == "203.0.113.9" && addr_host(v[1]) == "2001:db8::7", "W8 entry -> host literal");
        std::vector<u8> empty = encode_addr(7, {});
        C(decode_addr(empty, ch, v) && v.empty(), "W8 an empty ADDR (nothing known) decodes");
        std::vector<AddrEntry> many(kAddrMaxEntries, a4), over(kAddrMaxEntries + 1, a4);
        const auto fm = encode_addr(7, many);
        C(fm.size() == kAddrMaxFrame && decode_addr(fm, ch, v) && v.size() == kAddrMaxEntries, "W8 256 entries = the bound, accepted");
        C(encode_addr(7, over).empty(), "W8 257 entries not encodable");
        auto fb = fm; fb[6] = 1; fb[7] = 1;   // n = 257 claimed
        C(!decode_addr(fb, ch, v) && v.empty(), "W8 n > 256 refused");
        fb = f; fb.pop_back();
        C(!decode_addr(fb, ch, v), "W8 truncated entry refused");
        fb = f; fb[8] = 5;
        C(!decode_addr(fb, ch, v) && v.empty(), "W8 unknown address family refused (total: no partial output)");
        fb = f; fb[8 + 1 + 5] = 1;
        C(!decode_addr(fb, ch, v), "W8 IPv4 entry with non-zero padding refused");
        fb = f; fb[8 + 17] = 0; fb[8 + 18] = 0;
        C(!decode_addr(fb, ch, v), "W8 port 0 refused");
        AddrEntry z = a4; z.port = 0;
        C(encode_addr(7, {z}).empty(), "W8 port 0 not encodable");
        auto is_pub = [](const char* h) { AddrEntry e; return addr_entry_of(h, 1, 0, e) && addr_routable(e); };
        C(is_pub("1.1.1.1") && is_pub("8.8.8.8") && is_pub("2001:4860::1"), "W8 public addresses are routable");
        C(!is_pub("127.0.0.1") && !is_pub("10.1.2.3") && !is_pub("192.168.86.114") && !is_pub("172.20.0.1") &&
          !is_pub("100.64.0.1") && !is_pub("169.254.1.1") && !is_pub("0.0.0.0") && !is_pub("224.0.0.1") &&
          !is_pub("::1") && !is_pub("fd00::1") && !is_pub("fe80::1") && !is_pub("::ffff:192.168.1.1"),
          "W8 loopback / RFC1918 / CGNAT / link-local / unspecified / multicast / ULA / mapped-private are NOT routable");
    }
    std::printf("xmr_relay_wire_kat: %s: %d checks, %d failures\n", g_fail ? "FAIL" : "PASS", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
