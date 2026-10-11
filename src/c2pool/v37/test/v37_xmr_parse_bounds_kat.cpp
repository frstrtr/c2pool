// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_parse_bounds_kat -- non-wrapping bounds checks in the parsers that
// read peer data (the v3 receipt and carrier bodies, the family-C frames and
// FB_RECEIPTS v3, and the reader they share) and the index snapshot reader.
//
// Every check is written "len > size - pos" with pos <= size, never
// "pos + len > size": a varint or u64 length near SIZE_MAX would wrap the
// latter and pass. Each case below puts such a length or count at a position
// near the end of its buffer and requires a clean refusal; built with
// -fsanitize=address,undefined (the CI sanitizer leg builds this target too) a
// read past the buffer or a wrapped pointer would abort the run.
//
//   B1  decode_receipt_body_v3: a v3 receipt body truncated at every length
//   B2  decode_carrier_body_v3: n_carried (1, R_MAX, 255) above the bodies present
//   B3  decode_fc_getcarrier / decode_fc_headers / decode_fb_receipts: a count
//       above what the frame holds, at the end of the frame
//   B4  BlobReader (the reader of the v3 decoders): read_bytes / read_view /
//       skip of ~SIZE_MAX bytes at every read position; a count whose x32
//       byte size wraps
//   P7  ChainIndex::load_snapshot: a body length in the wrap window
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_caps.hpp"
#include "impl/xmr/pathb/pathb_relay_wire.hpp"
#include "impl/xmr/pathb/pathb_wire_v3.hpp"
#include "impl/xmr/pathb/test/pathb_kat_bodies.hpp"
#include "impl/xmr/native/consensus/xmr_blob_reader.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"

namespace pb = ::c2pool::xmr::pathb;
namespace nat = c2pool::xmr::native;
using u8 = std::uint8_t;

static constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

namespace {

struct Checker {
    int pass = 0, fail = 0;
    void operator()(bool ok, const std::string& what) {
        if (ok) ++pass; else ++fail;
        std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
        std::fflush(stdout);
    }
    int done(const char* name) const {
        std::printf("== %s: %s (%d/%d passed) ==\n", name, fail ? "FAIL" : "OK", pass, pass + fail);
        return fail ? 1 : 0;
    }
};

void put_varint(std::vector<u8>& b, std::uint64_t v) {
    while (v >= 0x80) { b.push_back(static_cast<u8>((v & 0x7f) | 0x80)); v >>= 7; }
    b.push_back(static_cast<u8>(v));
}

std::vector<u8> enc_body(const pb::ReceiptBodyV3& b) {
    std::vector<u8> e;
    if (pb::encode_receipt_body_v3(b, e) != pb::WireError::None) e.clear();
    return e;
}

}  // namespace

int main() {
    Checker C;
    std::printf("== v37_xmr_parse_bounds_kat ==\n");
    const std::uint64_t r_max = pb::kRuledLaneParams.r_max;
    const pb::RelayBuffers buf = pb::relay_buffers_default(16, 0, r_max).value_or(pb::RelayBuffers{});
    const std::uint32_t chain = 0x0a0b0c0du;

    // ── B1 a v3 receipt body truncated at every length ─────────────────────
    {
        const pb::ReceiptLimits lim = pb::receipt_limits(buf);
        const std::vector<u8> e = enc_body(pathb_kat::make_body(5, true, 21));
        pb::ReceiptBodyV3 got;
        C(!e.empty() && pb::decode_receipt_body_v3(e.data(), e.size(), lim, got) == pb::WireError::None,
          "B1 control: a full v3 receipt body decodes");
        bool all_refused = true;
        for (std::size_t n = 0; n < e.size(); ++n) {
            const std::vector<u8> t(e.begin(), e.begin() + static_cast<std::ptrdiff_t>(n));
            if (pb::decode_receipt_body_v3(t.data(), t.size(), lim, got) == pb::WireError::None) all_refused = false;
        }
        C(all_refused, "B1 every truncation of a v3 receipt body is refused (" + std::to_string(e.size()) + " lengths)");
    }

    // ── B2 a v3 carrier body whose n_carried is above the bodies present ───
    {
        const pb::CarrierLimits lim = pb::carrier_limits(buf, r_max);
        const std::vector<u8> own = enc_body(pathb_kat::make_body(3, true, 1));
        pb::CarrierBodyV3 got;
        std::vector<u8> c0{pb::kCarrierBodyVersion};
        c0.insert(c0.end(), own.begin(), own.end());
        c0.push_back(0);
        C(!own.empty() && pb::decode_carrier_body_v3(c0.data(), c0.size(), lim, got) == pb::WireError::None,
          "B2 control: a carrier body with 0 carried decodes");
        bool all_refused = true;
        for (const std::uint64_t n : {std::uint64_t{1}, r_max, std::uint64_t{255}}) {
            std::vector<u8> w{pb::kCarrierBodyVersion};
            w.insert(w.end(), own.begin(), own.end());
            w.push_back(static_cast<u8>(n));   // the count is the last byte: no body follows
            if (pb::decode_carrier_body_v3(w.data(), w.size(), lim, got) == pb::WireError::None) all_refused = false;
        }
        C(all_refused, "B2 n_carried 1, R_MAX and 255 with no carried body present are refused");
    }

    // ── B3 family-C frames and FB_RECEIPTS v3: a count above the frame ─────
    {
        const pb::LaneParams& lp = pb::kRuledLaneParams;
        pb::GetCarrier q;
        q.chain_id = chain;
        q.ids = {pathb_kat::seq32(0x21)};
        const std::optional<std::vector<u8>> f = pb::encode_fc_getcarrier(q, lp);
        pb::GetCarrier qo;
        C(f.has_value() && pb::decode_fc_getcarrier(*f, chain, lp, qo).ok() && qo == q,
          "B3 control: an FC_GETCARRIER frame with one id decodes");
        bool gc_refused = f.has_value();
        for (const std::uint64_t n : {1 + r_max, std::uint64_t{255}}) {
            std::vector<u8> t = *f;
            t[pb::kFrameHeaderBytes] = static_cast<u8>(n);   // one id and the flag byte follow
            if (pb::decode_fc_getcarrier(t, chain, lp, qo).ok()) gc_refused = false;
        }
        C(gc_refused, "B3 FC_GETCARRIER n = 1 + R_MAX and 255 with one id present are refused");

        pb::HeadersReply hr;
        hr.chain_id = chain;
        hr.first_pos = kMax;
        std::optional<std::vector<u8>> h = pb::encode_fc_headers(hr, buf.frame);
        bool hd_refused = h.has_value() && h->size() == pb::kHeadersFrameHeadBytes;
        if (hd_refused) {
            (*h)[h->size() - 2] = 0xff;   // u16 n = 65,535 at the end of the frame, no header present
            (*h)[h->size() - 1] = 0xff;
            pb::HeadersReply ho;
            if (pb::decode_fc_headers(*h, chain, buf.frame, lp, ho).ok()) hd_refused = false;
        }
        C(hd_refused, "B3 FC_HEADERS n = 65,535 with no header present is refused");

        const std::optional<std::vector<u8>> r =
                pb::encode_fb_receipts(chain, std::vector<pb::ReceiptBodyV3>{pathb_kat::make_body(2, false, 9)}, lp);
        bool rc_refused = r.has_value();
        for (const std::uint64_t n : {1 + r_max, std::uint64_t{255}}) {
            std::vector<u8> t = *r;
            t[pb::kFrameHeaderBytes] = static_cast<u8>(n);   // one body follows
            pb::ReceiptsFrame ro;
            if (pb::decode_fb_receipts(t, chain, buf, lp, ro).ok()) rc_refused = false;
        }
        C(rc_refused, "B3 FB_RECEIPTS n = 1 + R_MAX and 255 with one body present are refused");
    }

    // ── B4 the reader of the v3 decoders asked for ~SIZE_MAX bytes ─────────
    {
        const std::vector<u8> bytes(16, 0x11);
        bool refused_all = true;
        for (std::size_t consumed = 0; consumed <= bytes.size(); ++consumed) {
            for (std::size_t k = 0; k < 4; ++k) {
                const std::size_t n = std::numeric_limits<std::size_t>::max() - k;
                u8 dst[1] = {0};
                nat::BlobReader r1(bytes);
                if (!r1.skip(consumed) || r1.read_bytes(dst, n) || r1.offset() != consumed) refused_all = false;
                const u8* view = nullptr;
                nat::BlobReader r2(bytes);
                if (!r2.skip(consumed) || r2.read_view(view, n) || r2.offset() != consumed) refused_all = false;
                nat::BlobReader r3(bytes);
                if (!r3.skip(consumed) || r3.skip(n) || r3.offset() != consumed) refused_all = false;
            }
        }
        C(refused_all, "B4 read_bytes / read_view / skip for ~SIZE_MAX bytes at every read position are refused, cursor unmoved");
        std::vector<u8> c;
        put_varint(c, (std::uint64_t{1} << 59) + 1);   // x32 == 2^64 + 32
        for (int i = 0; i < 32; ++i) c.push_back(0x66);
        nat::BlobReader rc(c);
        std::uint64_t cnt = 0;
        C(!rc.read_count(cnt, kMax, 32) && rc.offset() == 0,
          "B4 a count whose byte size x32 wraps to 32 is refused (not read as one element)");
        nat::BlobReader re(bytes);
        u8 all[16];
        C(re.read_bytes(all, sizeof all) && re.eof(), "B4 control: an exact read succeeds");
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
