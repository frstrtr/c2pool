// SPDX-License-Identifier: AGPL-3.0-or-later
//
// TxInjectSubmitPrecheck — Qt-free, client-side prechecks + a minimal raw-tx
// decode preview for the #157 submit-raw-tx form. Kept Qt-free so the money-
// adjacent input validation is unit-testable (test_tx_inject_form_precheck.cpp)
// independent of any widget.
//
// The prechecks here are a courtesy that catches obvious operator mistakes
// BEFORE a POST — they are NOT the authority. The node re-validates every submit
// and returns named `inject-*` refusals which the UI renders verbatim; this
// header never decides a tx is acceptable, only that it is well-formed enough to
// preview and send.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace c2pool_qt {

struct FieldCheck {
    bool        ok = false;
    std::string error;   // human cause when !ok
};

// Even-length, all-hex, non-empty. (A raw tx is whole bytes -> even nibbles.)
inline FieldCheck even_hex_check(const std::string& hex) {
    if (hex.empty()) return {false, "raw tx hex is empty"};
    if (hex.size() % 2 != 0)
        return {false, "hex has an odd length (a raw tx is whole bytes)"};
    for (char c : hex) {
        const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F');
        if (!is_hex) return {false, std::string("non-hex character '") + c + "'"};
    }
    return {true, {}};
}

// A non-negative uint32 (the tx-inject `flags` bitfield). Empty is allowed and
// yields 0 (the default no-flags value); anything non-numeric or out of range
// refuses.
inline FieldCheck parse_flags_u32(const std::string& s, uint32_t& out) {
    out = 0;
    if (s.empty()) return {true, {}};
    uint64_t acc = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return {false, "flags must be a non-negative integer"};
        acc = acc * 10 + static_cast<uint64_t>(c - '0');
        if (acc > 0xffffffffull) return {false, "flags exceeds uint32 range"};
    }
    out = static_cast<uint32_t>(acc);
    return {true, {}};
}

// A non-negative expiry height (0 = no expiry). uint64, decimal.
inline FieldCheck parse_expiry_height(const std::string& s, uint64_t& out) {
    out = 0;
    if (s.empty()) return {true, {}};
    uint64_t acc = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return {false, "expiry height must be a non-negative integer"};
        const uint64_t prev = acc;
        acc = acc * 10 + static_cast<uint64_t>(c - '0');
        if (acc < prev) return {false, "expiry height overflows"};
    }
    out = acc;
    return {true, {}};
}

// ---- minimal raw-tx decode preview (DASH DIP2-aware) ----------------------
struct TxPreview {
    bool        ok = false;
    std::string error;
    uint32_t    version = 0;     // low 16 bits of the version field
    uint32_t    type    = 0;     // DIP2 special-tx type (high 16 bits)
    uint64_t    vin     = 0;
    uint64_t    vout    = 0;
    std::size_t size_bytes = 0;
    std::string txid;            // left empty (hashing is out of scope here)
};

namespace detail {

struct ByteCursor {
    const std::string& hex;
    std::size_t pos = 0;   // nibble-pair index (bytes)
    bool ok = true;

    std::size_t bytes() const { return hex.size() / 2; }

    uint8_t u8() {
        if (!ok || pos + 1 >= hex.size()) { ok = false; return 0; }
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[pos]), lo = nib(hex[pos + 1]);
        if (hi < 0 || lo < 0) { ok = false; return 0; }
        pos += 2;
        return static_cast<uint8_t>((hi << 4) | lo);
    }
    uint64_t le(int n) {
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(u8()) << (8 * i);
        return v;
    }
    uint64_t varint() {
        uint8_t p = u8();
        if (p < 0xfd) return p;
        if (p == 0xfd) return le(2);
        if (p == 0xfe) return le(4);
        return le(8);
    }
    void skip(uint64_t n) {
        // n bytes; guard against a truncated/oversized script length.
        if (!ok) return;
        if (pos + n * 2 > hex.size()) { ok = false; return; }
        pos += static_cast<std::size_t>(n * 2);
    }
};

}  // namespace detail

// Walk the raw tx far enough to report version/type/vin/vout/size. Fail-loud on
// truncation; this is a preview, so it never mutates and never signs.
inline TxPreview decode_preview(const std::string& hex) {
    TxPreview pv;
    FieldCheck hc = even_hex_check(hex);
    if (!hc.ok) { pv.error = hc.error; return pv; }

    detail::ByteCursor c{hex};
    pv.size_bytes = c.bytes();

    const uint32_t ver_field = static_cast<uint32_t>(c.le(4));
    pv.version = ver_field & 0xffff;
    pv.type    = (ver_field >> 16) & 0xffff;

    const uint64_t nin = c.varint();
    if (!c.ok) { pv.error = "truncated before input count"; return pv; }
    if (nin == 0 || nin > 100000) {
        pv.error = "implausible input count";
        return pv;
    }
    for (uint64_t i = 0; i < nin && c.ok; ++i) {
        c.skip(36);              // 32 outpoint hash + 4 index
        const uint64_t slen = c.varint();
        c.skip(slen);            // scriptSig
        c.skip(4);               // sequence
    }
    if (!c.ok) { pv.error = "truncated while walking inputs"; return pv; }
    pv.vin = nin;

    const uint64_t nout = c.varint();
    if (!c.ok) { pv.error = "truncated before output count"; return pv; }
    if (nout == 0 || nout > 100000) {
        pv.error = "implausible output count";
        return pv;
    }
    for (uint64_t i = 0; i < nout && c.ok; ++i) {
        c.skip(8);               // value
        const uint64_t plen = c.varint();
        c.skip(plen);            // scriptPubKey
    }
    if (!c.ok) { pv.error = "truncated while walking outputs"; return pv; }
    pv.vout = nout;

    c.skip(4);                   // lock_time
    if (!c.ok) { pv.error = "truncated before lock_time"; return pv; }

    pv.ok = true;
    return pv;
}

}  // namespace c2pool_qt
