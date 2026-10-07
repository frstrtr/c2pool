// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_parse_bounds_kat -- non-wrapping bounds checks in the parsers that
// read peer data (receipt tx_extra and hashing blob, a context block's layout,
// the receipt wire reader) and the index snapshot reader.
//
// Every check is written "len > size - pos" with pos <= size, never
// "pos + len > size": a varint or u64 length near SIZE_MAX would wrap the
// latter and pass. Each case below puts such a length at a position near the
// end of its buffer and requires a clean refusal; built with
// -fsanitize=address,undefined (the CI sanitizer leg builds this target too) a
// read past the buffer or a wrapped pointer would abort the run.
//
//   P1  parse_tx_extra 0x02 (extra-nonce) length in the wrap window, for every
//       wrap target inside the buffer
//   P2  parse_tx_extra 0x03 (merge-mining field) length in the wrap window
//   P3  parse_tx_extra 0x04 (additional pubkeys) count whose x32 overflows
//   P4  parse_hashing_blob truncated at every length
//   P5  parse_block_layout / verify_block_ctx: miner_tx extra length in the
//       wrap window (a peer-served FB_CTX blob)
//   P6  the receipt wire reader (bytes_ / fixed_) asked for ~SIZE_MAX bytes
//   P7  ChainIndex::load_snapshot: a body length in the wrap window
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include "impl/xmr/receipt/xmr_receipt_verify.hpp"
#include "impl/xmr/wire/xmr_carrier_wire.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"

using namespace gap2test;
namespace vfy = ::v37::xmr::verify;
namespace nat = c2pool::xmr::native;

static constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

static std::vector<u8> pubkey_field() {   // 0x01 || 32 bytes: a valid leading field
    std::vector<u8> e{0x01};
    for (int i = 0; i < 32; ++i) e.push_back(static_cast<u8>(0x40 + i));
    return e;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_parse_bounds_kat ==\n");

    // ── P1 0x02 extra-nonce length in the wrap window ──────────────────────
    {
        std::vector<u8> ok = pubkey_field();
        ok.push_back(0x02); put_varint(ok, 3); ok.push_back(1); ok.push_back(2); ok.push_back(3);
        vfy::ParsedTxExtra px;
        C(vfy::parse_tx_extra(ok, px) && px.has_pubkey && px.has_nonce && px.nonce.size() == 3, "P1 control: a well-formed 0x01 + 0x02 extra parses");
        bool all_refused = true; std::size_t cases = 0;
        const std::size_t pos_after = pubkey_field().size() + 1 + 10;   // tag + a 10-byte varint of a ~2^64 value
        for (std::uint64_t j = 0; j < pos_after; ++j) {                // every wrap target inside the buffer
            std::vector<u8> e = pubkey_field();
            e.push_back(0x02);
            const std::uint64_t len = kMax - pos_after + 1 + j;   // pos + len wraps to j
            put_varint(e, len);
            if (e.size() != pos_after) { all_refused = false; break; }
            for (int k = 0; k < 4; ++k) e.push_back(0xAA);
            vfy::ParsedTxExtra p2;
            ++cases;
            if (vfy::parse_tx_extra(e, p2)) all_refused = false;
        }
        C(all_refused && cases == pos_after, "P1 a 0x02 length that wraps pos+len onto every value 0.." + std::to_string(pos_after - 1) +
          " is refused (" + std::to_string(cases) + " cases)");
        std::vector<u8> e = pubkey_field(); e.push_back(0x02); put_varint(e, kMax);
        vfy::ParsedTxExtra p3;
        C(!vfy::parse_tx_extra(e, p3), "P1 a 0x02 length of 2^64-1 at the very end is refused");
    }

    // ── P2 0x03 merge-mining field length in the wrap window ───────────────
    {
        bool all_refused = true;
        const std::size_t pos_after = pubkey_field().size() + 1 + 10;
        for (std::uint64_t j = 0; j < pos_after; ++j) {
            std::vector<u8> e = pubkey_field();
            e.push_back(0x03);
            put_varint(e, kMax - pos_after + 1 + j);
            e.push_back(0x00);
            for (int k = 0; k < 40; ++k) e.push_back(0x55);
            vfy::ParsedTxExtra p;
            if (vfy::parse_tx_extra(e, p)) all_refused = false;
        }
        C(all_refused, "P2 a 0x03 field length that wraps is refused");
    }

    // ── P3 0x04 count whose x32 overflows ──────────────────────────────────
    {
        std::vector<u8> e = pubkey_field();
        e.push_back(0x04);
        put_varint(e, (std::uint64_t{1} << 59) + 1);   // x32 == 2^64 + 32 -> wraps to 32
        for (int k = 0; k < 32; ++k) e.push_back(0x66);
        vfy::ParsedTxExtra p;
        C(!vfy::parse_tx_extra(e, p), "P3 an additional-pubkeys count whose byte size overflows to 32 is refused (not read as one key)");
        std::vector<u8> e2 = pubkey_field(); e2.push_back(0x04); put_varint(e2, kMax / 32 + 1);
        vfy::ParsedTxExtra p2;
        C(!vfy::parse_tx_extra(e2, p2), "P3 a count near 2^64/32 is refused");
        std::vector<u8> e3 = pubkey_field(); e3.push_back(0x04); put_varint(e3, 1);
        for (int k = 0; k < 32; ++k) e3.push_back(0x66);
        vfy::ParsedTxExtra p3;
        C(vfy::parse_tx_extra(e3, p3), "P3 control: one additional pubkey parses");
    }

    // ── P4 parse_hashing_blob truncated at every length ────────────────────
    {
        const SynthBlock sb = make_block(100, b32_of(4), 1, nullptr, 2, 9);
        vfy::ParsedBlob pb;
        ::v37::xmr::HashingBlob hb; hb.bytes = sb.hashing_blob;
        C(vfy::parse_hashing_blob(hb, pb), "P4 control: a full hashing blob parses");
        bool all_refused = true;
        for (std::size_t n = 0; n < sb.hashing_blob.size(); ++n) {
            ::v37::xmr::HashingBlob t; t.bytes.assign(sb.hashing_blob.begin(), sb.hashing_blob.begin() + static_cast<std::ptrdiff_t>(n));
            if (vfy::parse_hashing_blob(t, pb)) all_refused = false;
        }
        C(all_refused, "P4 every truncation of a hashing blob is refused");
    }

    // ── P5 a peer-served context block whose miner_tx extra length wraps ───
    {
        const SynthBlock sb = make_block(100, b32_of(4), 1, nullptr, 0, 9);
        BlockLayout L; std::string why;
        C(parse_block_layout(sb.full_blob, L, &why) && L.extra_size > 0, "P5 control: the block layout parses");
        // the blob up to (not including) the miner_tx extra-length varint
        std::size_t p = L.miner_tx_offset; std::uint64_t v = 0, nout = 0;
        auto rd = [&](std::uint64_t& out) { return c2pool::v37n::xmr::relay::detail::rd_varint(sb.full_blob, p, out); };
        rd(v); rd(v); rd(v); ++p; rd(v); rd(nout);
        for (std::uint64_t i = 0; i < nout; ++i) { rd(v); const u8 t = sb.full_blob[p++]; p += (t == 0x03 ? 33 : 32); }
        const std::vector<u8> head(sb.full_blob.begin(), sb.full_blob.begin() + static_cast<std::ptrdiff_t>(p));
        rd(v); const std::size_t after_xlen = p;   // skip the original extra-length varint
        bool all_refused = true;
        for (std::uint64_t j = 0; j < 48; ++j) {
            std::vector<u8> t = head;
            const std::size_t pos_after = t.size() + 10;
            put_varint(t, kMax - pos_after + 1 + j);
            t.insert(t.end(), sb.full_blob.begin() + static_cast<std::ptrdiff_t>(after_xlen), sb.full_blob.end());
            BlockLayout L2; std::string w; BlockCtx bc;
            if (parse_block_layout(t, L2, &w)) all_refused = false;
            if (verify_block_ctx(b32_of(5), t, bc, &w)) all_refused = false;
        }
        C(all_refused, "P5 a context blob whose miner_tx extra length wraps is refused (layout and verify_block_ctx)");
        // A shaped case: the length and the tail are chosen so that every
        // later field check would also pass if the length check wrapped; only
        // the length check itself can refuse it.
        {
            const std::size_t j = L.miner_tx_offset - 1;
            std::vector<u8> t = head;
            const std::size_t pos_after = t.size() + 10;
            put_varint(t, kMax - pos_after + 1 + j);
            const std::size_t want = j + 2 + 32 * sb.full_blob[j + 1];
            const bool shaped = sb.full_blob[j] == 0x00 && t.size() <= want;
            while (t.size() < want) t.push_back(0x33);
            BlockLayout L2; std::string w; BlockCtx bc;
            const bool lay = parse_block_layout(t, L2, &w);
            C(shaped && !lay, "P5 the crafted wrap (lands on a zero byte, tail sized to match) is refused by the layout parser: " + w);
            C(!verify_block_ctx(b32_of(5), t, bc, &w), "P5 ...and by verify_block_ctx, before any slice of the blob");
        }
    }

    // ── P6 the receipt wire reader asked for ~SIZE_MAX bytes ───────────────
    {
        std::vector<u8> buf(16, 0x11);
        bool threw_all = true;
        for (std::size_t consumed = 0; consumed <= buf.size(); ++consumed) {
            for (std::size_t k = 0; k < 4; ++k) {
                ::v37::xmr::wire::Reader r(buf);
                for (std::size_t i = 0; i < consumed; ++i) (void)r.u8_();
                const std::size_t n = std::numeric_limits<std::size_t>::max() - k;
                bool threw = false;
                try { (void)r.bytes_(n, std::numeric_limits<std::size_t>::max(), "kat"); } catch (const ::v37::xmr::wire::WireError&) { threw = true; }
                if (!threw) threw_all = false;
                threw = false;
                u8 dst[1];
                try { r.fixed_(dst, n, "kat"); } catch (const ::v37::xmr::wire::WireError&) { threw = true; }
                if (!threw) threw_all = false;
            }
        }
        C(threw_all, "P6 bytes_ / fixed_ for ~SIZE_MAX bytes at every read position throw a short read");
        ::v37::xmr::wire::Reader r(buf);
        C(r.bytes_(16, 64, "kat").size() == 16 && r.eof(), "P6 control: an exact read succeeds");
    }

    // ── P7 the index snapshot reader: a body length in the wrap window ─────
    {
        nat::ChainIndexOptions o; o.net = nat::XmrNet::Regtest;
        nat::NoPowSource none;
        auto put64 = [](std::vector<u8>& v, std::uint64_t x) { for (int i = 0; i < 8; ++i) v.push_back(static_cast<u8>(x >> (8 * i))); };
        auto put32b = [](std::vector<u8>& v, u8 fill) { for (int i = 0; i < 32; ++i) v.push_back(fill); };
        bool all_refused = true; std::string last;
        for (std::uint64_t j = 0; j < 16; ++j) {
            std::vector<u8> body;
            put64(body, 0x3143584449433243ull);   // SNAPSHOT_MAGIC
            put64(body, 1);                        // SNAPSHOT_VERSION
            put64(body, static_cast<std::uint64_t>(o.net));
            put64(body, 10); put32b(body, 0xA1);   // anchor height, id
            put64(body, 10);                       // base height
            put64(body, 1);                        // depth: one block above
            // base row: height, id, prev, ts, major, minor, bw, ltw, d.lo, d.hi, cd.lo, cd.hi, base, fees, reward, agc, pow, own, pow_hash
            put64(body, 10); put32b(body, 0xA1); put32b(body, 0xA0);
            for (int i = 0; i < 15; ++i) put64(body, 1);
            put32b(body, 0);
            for (int i = 0; i < 6; ++i) put64(body, 0);   // nd, nst, nlt, nts, nseed, nbelow
            put64(body, 1);                        // nabove
            put64(body, 1); put64(body, 0); put32b(body, 0);   // pow, own, pow_hash
            const std::size_t off_after = body.size() + 8;     // the length field itself
            put64(body, kMax - off_after + 1 + j);             // off + len wraps to j
            for (int i = 0; i < 24; ++i) body.push_back(0x77);
            nat::anchor_hash::Sha256 hh; hh.update(body.data(), body.size());
            const auto dg = hh.finish();
            body.insert(body.end(), dg.begin(), dg.end());
            nat::ChainIndex idx(o, none);
            std::string why;
            if (idx.load_snapshot(body, why)) all_refused = false;
            last = why;
        }
        C(all_refused, "P7 a snapshot whose block length wraps the bound is refused: " + last);
    }

    return C.done("v37_xmr_parse_bounds_kat");
}
