// SPDX-License-Identifier: AGPL-3.0-or-later
#include "TxIntrospect.hpp"

#include <cstddef>

namespace c2w::artifact {

namespace {

// A bounds-checked forward reader over the raw bytes. Any overrun latches ok=false.
struct Reader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    explicit Reader(const Bytes& b) : p(b.data()), end(b.data() + b.size()) {}

    size_t remaining() const { return static_cast<size_t>(end - p); }

    uint8_t u8() {
        if (p >= end) { ok = false; return 0; }
        return *p++;
    }
    bool skip(size_t n) {
        if (remaining() < n) { ok = false; return false; }
        p += n;
        return true;
    }
    uint64_t varint() {
        if (p >= end) { ok = false; return 0; }
        uint8_t f = *p++;
        int n = 0;
        if (f < 0xfd) return f;
        else if (f == 0xfd) n = 2;
        else if (f == 0xfe) n = 4;
        else n = 8;
        if (remaining() < static_cast<size_t>(n)) { ok = false; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
        p += n;
        return v;
    }
};

} // namespace

bool has_c2wu_magic(const Bytes& raw) {
    return raw.size() >= 4 && raw[0] == 'C' && raw[1] == '2' &&
           raw[2] == 'W' && raw[3] == 'U';
}

RawTxShape inspect_raw_tx(const Bytes& raw) {
    RawTxShape sh;
    sh.has_c2wu_magic = has_c2wu_magic(raw);
    if (sh.has_c2wu_magic) { sh.error = "blob is a C2WU unsigned container, not a raw tx"; return sh; }

    Reader r(raw);
    if (!r.skip(4)) { sh.error = "truncated before version"; return sh; }

    uint64_t vin = r.varint();
    if (!r.ok) { sh.error = "truncated at input count"; return sh; }

    // BIP144 segwit marker: a zero input-count byte means {marker=0x00, flag}.
    if (vin == 0) {
        uint8_t flag = r.u8();
        if (!r.ok || flag == 0x00) { sh.error = "bad segwit marker/flag"; return sh; }
        sh.segwit = true;
        vin = r.varint();
        if (!r.ok) { sh.error = "truncated at input count (segwit)"; return sh; }
    }
    if (vin == 0) { sh.error = "transaction has no inputs"; return sh; }
    sh.vin = vin;

    // Inputs: prevout(36) | scriptSig(varint len + bytes) | sequence(4).
    // Track per-input scriptSig emptiness for the confusion guard.
    Bytes scriptsig_nonempty;
    scriptsig_nonempty.reserve(static_cast<size_t>(vin));
    for (uint64_t i = 0; i < vin; ++i) {
        if (!r.skip(36)) { sh.error = "truncated at input prevout"; return sh; }
        uint64_t slen = r.varint();
        if (!r.ok) { sh.error = "truncated at scriptSig length"; return sh; }
        if (!r.skip(static_cast<size_t>(slen))) { sh.error = "truncated at scriptSig"; return sh; }
        if (!r.skip(4)) { sh.error = "truncated at sequence"; return sh; }
        scriptsig_nonempty.push_back(slen > 0 ? 1 : 0);
    }

    // Outputs: value(8) | scriptPubKey(varint len + bytes).
    uint64_t vout = r.varint();
    if (!r.ok) { sh.error = "truncated at output count"; return sh; }
    sh.vout = vout;
    for (uint64_t i = 0; i < vout; ++i) {
        if (!r.skip(8)) { sh.error = "truncated at output value"; return sh; }
        uint64_t plen = r.varint();
        if (!r.ok) { sh.error = "truncated at scriptPubKey length"; return sh; }
        if (!r.skip(static_cast<size_t>(plen))) { sh.error = "truncated at scriptPubKey"; return sh; }
    }

    // Witness (BIP144): one stack per input; each stack is count + (len+bytes)*.
    Bytes witness_nonempty(static_cast<size_t>(vin), 0);
    if (sh.segwit) {
        for (uint64_t i = 0; i < vin; ++i) {
            uint64_t items = r.varint();
            if (!r.ok) { sh.error = "truncated at witness stack count"; return sh; }
            uint64_t total = 0;
            for (uint64_t k = 0; k < items; ++k) {
                uint64_t ilen = r.varint();
                if (!r.ok) { sh.error = "truncated at witness item length"; return sh; }
                if (!r.skip(static_cast<size_t>(ilen))) { sh.error = "truncated at witness item"; return sh; }
                total += ilen;
            }
            witness_nonempty[static_cast<size_t>(i)] = (items > 0 && total > 0) ? 1 : 0;
        }
    }

    // locktime(4). Anything after (Dash extra payload) is tolerated.
    if (!r.skip(4)) { sh.error = "truncated at locktime"; return sh; }

    sh.parsed = true;
    bool all = true, any = false;
    for (uint64_t i = 0; i < vin; ++i) {
        const bool has = scriptsig_nonempty[static_cast<size_t>(i)] ||
                         witness_nonempty[static_cast<size_t>(i)];
        all = all && has;
        any = any || has;
    }
    sh.every_input_has_sig = all;
    sh.any_input_has_sig = any;
    return sh;
}

bool accept_as_signed(const Bytes& raw, std::string& why) {
    why.clear();
    if (has_c2wu_magic(raw)) {
        why = "this is a C2WU UNSIGNED container, not a signed transaction — "
              "load it in the Unsigned slot, not the Signed slot.";
        return false;
    }
    RawTxShape sh = inspect_raw_tx(raw);
    if (!sh.parsed) {
        why = "not a well-formed transaction: " + sh.error;
        return false;
    }
    if (!sh.every_input_has_sig) {
        why = "at least one input has NO scriptSig and NO witness — this looks "
              "like an UNSIGNED transaction, refusing to treat it as signed.";
        return false;
    }
    return true;
}

} // namespace c2w::artifact
