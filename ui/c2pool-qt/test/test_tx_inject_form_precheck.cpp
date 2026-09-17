// SPDX-License-Identifier: AGPL-3.0-or-later
//
// test_tx_inject_form_precheck — Qt-free KAT for the #157 submit-raw-tx form
// client-side prechecks + decode preview (TxInjectSubmitPrecheck.hpp). These are
// a courtesy that catches obvious mistakes before a POST; the node stays the
// authority. Proves:
//   * even-hex precheck: rejects empty / odd-length / non-hex, accepts valid;
//   * flags parse as a non-negative uint32 (empty => 0, reject overflow/garbage);
//   * expiry height parses as a non-negative integer;
//   * decode_preview walks a real raw tx and reports version/vin/vout/size,
//     and fails loud on truncation (never a partial "looks fine").

#include "../src/TxInjectSubmitPrecheck.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

using namespace c2pool_qt;

static int failures = 0;
static void check(bool cond, const char* what) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++failures;
}

int main() {
    std::printf("test_tx_inject_form_precheck\n");

    // ---- even-hex precheck ----
    check(!even_hex_check("").ok, "empty hex rejected");
    check(!even_hex_check("abc").ok, "odd-length hex rejected");
    check(!even_hex_check("zz").ok, "non-hex chars rejected");
    check(even_hex_check("deadBEEF").ok, "valid mixed-case even hex accepted");

    // ---- flags uint32 ----
    {
        uint32_t f = 123;
        check(parse_flags_u32("", f).ok && f == 0, "empty flags => 0");
        check(parse_flags_u32("0", f).ok && f == 0, "flags 0 parses");
        check(parse_flags_u32("4294967295", f).ok && f == 0xffffffffu,
              "flags uint32 max parses");
        check(!parse_flags_u32("4294967296", f).ok, "flags > uint32 max rejected");
        check(!parse_flags_u32("-1", f).ok, "negative flags rejected");
        check(!parse_flags_u32("0x10", f).ok, "non-decimal flags rejected");
    }

    // ---- expiry height ----
    {
        uint64_t h = 5;
        check(parse_expiry_height("", h).ok && h == 0, "empty expiry => 0");
        check(parse_expiry_height("2500000", h).ok && h == 2500000ull,
              "expiry height parses");
        check(!parse_expiry_height("-3", h).ok, "negative expiry rejected");
        check(!parse_expiry_height("abc", h).ok, "non-numeric expiry rejected");
    }

    // ---- decode_preview: a hand-built minimal legacy-style tx ----
    // version=1 (00000001 LE => 01000000)
    // vin count = 1 (01)
    //   prevout hash 32 bytes (all 00), index 4 bytes (ffffffff)
    //   scriptSig len = 1 (01), script = 00, sequence = ffffffff
    // vout count = 2 (02)
    //   out0: value 8 bytes (00..), pkscript len 1 (01), script 51 (OP_TRUE)
    //   out1: value 8 bytes (00..), pkscript len 1 (01), script 51
    // locktime 4 bytes (00000000)
    {
        std::string tx =
            "01000000"                                           // version
            "01"                                                 // vin=1
            "0000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff"                                           // prevout index
            "01" "00"                                            // scriptSig len+bytes
            "ffffffff"                                           // sequence
            "02"                                                 // vout=2
            "0000000000000000" "01" "51"                         // out0
            "0000000000000000" "01" "51"                         // out1
            "00000000";                                          // locktime
        TxPreview pv = decode_preview(tx);
        check(pv.ok, "well-formed tx decodes");
        check(pv.version == 1, "decoded version == 1");
        check(pv.vin == 1, "decoded vin == 1");
        check(pv.vout == 2, "decoded vout == 2");
        check(pv.size_bytes == tx.size() / 2, "decoded size == byte length");
    }

    // ---- decode_preview: truncated tx fails loud (no partial pass) ----
    {
        std::string tx = "010000000100000000";   // version + vin=1 + partial
        TxPreview pv = decode_preview(tx);
        check(!pv.ok && !pv.error.empty(), "truncated tx rejected by name");
    }
    // odd-hex tx: even-hex gate refuses before any decode.
    {
        TxPreview pv = decode_preview("0100000");
        check(!pv.ok, "odd-length tx hex refused before decode");
    }

    std::printf(failures == 0 ? "ALL PASS\n" : "FAILURES: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
