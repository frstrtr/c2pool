// Copyright (c) 2014-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// ===========================================================================
// ui/c2wallet-qt/src/family/monero/artifact/MoneroArtifact.cpp   (see .hpp)
//
// Marshaling of the four Monero cold-signing artifacts. Field order mirrors the
// cited monero-project structs; length/integer fields use the CryptoNote LEB128
// varint (tools::write_varint), 32-byte keys are raw. The 8-byte keccak footer
// stands in for monero's chacha20 view-key MAC (parity gap; see .hpp PARITY
// NOTE) and gives universal tamper detection at parse time.
// ===========================================================================
#include "family/monero/artifact/MoneroArtifact.hpp"

#include <cstring>

#include "family/monero/scan/MoneroScanOps.hpp"   // key_derivation, derive_secret_key

namespace c2wallet::monero::artifact {

// wallet2.cpp: the trailing octet is the artifact version byte (raw, not ASCII).
const char OUTPUT_EXPORT_MAGIC[]    = "Monero output export\004";
const char KEY_IMAGE_EXPORT_MAGIC[] = "Monero key image export\002";
const char UNSIGNED_TX_MAGIC[]      = "Monero unsigned tx set\005";
const char SIGNED_TX_MAGIC[]        = "Monero signed tx set\005";

namespace {

// ── CryptoNote LEB128 varint, byte-identical to tools::write_varint and to
//    MoneroRingctBuilder's put_varint (the tx blob's own codec). ─────────────
void put_varint(std::vector<unsigned char>& b, std::uint64_t v) {
    while (v >= 0x80) { b.push_back(static_cast<unsigned char>((v & 0x7f) | 0x80)); v >>= 7; }
    b.push_back(static_cast<unsigned char>(v));
}

void put_key(std::vector<unsigned char>& b, const Bytes32& k) {
    b.insert(b.end(), k.begin(), k.end());
}

void put_bytes(std::vector<unsigned char>& b, const std::vector<std::uint8_t>& v) {
    put_varint(b, v.size());
    b.insert(b.end(), v.begin(), v.end());
}

// A bounds-checked cursor. Any over-read sets ok_=false and every subsequent
// read is a no-op, so a truncated/mauled blob is rejected, never UB.
class Reader {
public:
    Reader(const unsigned char* p, std::size_t n) : p_(p), n_(n) {}

    bool ok() const { return ok_; }
    std::size_t pos() const { return i_; }
    bool at_end() const { return i_ == n_; }

    std::uint64_t varint() {
        std::uint64_t v = 0; int shift = 0;
        for (;;) {
            if (i_ >= n_ || shift > 63) { ok_ = false; return 0; }
            unsigned char c = p_[i_++];
            v |= static_cast<std::uint64_t>(c & 0x7f) << shift;
            if (!(c & 0x80)) break;
            shift += 7;
        }
        return v;
    }

    Bytes32 key() {
        Bytes32 k{};
        if (i_ + 32 > n_) { ok_ = false; return k; }
        std::memcpy(k.data(), p_ + i_, 32); i_ += 32;
        return k;
    }

    std::vector<std::uint8_t> bytes() {
        std::vector<std::uint8_t> v;
        std::uint64_t len = varint();
        if (!ok_ || i_ + len > n_) { ok_ = false; return v; }
        v.assign(p_ + i_, p_ + i_ + len); i_ += static_cast<std::size_t>(len);
        return v;
    }

private:
    const unsigned char* p_;
    std::size_t n_;
    std::size_t i_ = 0;
    bool ok_ = true;
};

// ── envelope: [magic][payload][8-byte keccak footer over magic||payload] ────
// The footer stands in for monero's chacha20 view-key MAC (parity gap). It is
// what makes "tamper on a parsed artifact is detected" hold universally today.
constexpr std::size_t FOOTER = 8;

std::vector<unsigned char> seal(const char* magic, std::size_t magic_len,
                                std::vector<unsigned char> payload) {
    std::vector<unsigned char> out;
    out.reserve(magic_len + payload.size() + FOOTER);
    out.insert(out.end(), magic, magic + magic_len);
    out.insert(out.end(), payload.begin(), payload.end());
    const Bytes32 h = mcrypto::keccak256(out.data(), out.size());
    out.insert(out.end(), h.begin(), h.begin() + FOOTER);
    return out;
}

// Verify magic + footer; on success set [body,body_len) to the inner payload.
bool unseal(const std::vector<unsigned char>& blob, const char* magic,
            std::size_t magic_len, const unsigned char*& body,
            std::size_t& body_len, std::string& err) {
    if (blob.size() < magic_len + FOOTER) { err = "artifact too short"; return false; }
    if (std::memcmp(blob.data(), magic, magic_len) != 0) {
        err = "wrong magic prefix (not this artifact type / version)"; return false;
    }
    const std::size_t sealed = blob.size() - FOOTER;
    const Bytes32 h = mcrypto::keccak256(blob.data(), sealed);
    if (std::memcmp(h.data(), blob.data() + sealed, FOOTER) != 0) {
        err = "integrity footer mismatch (tampered or truncated)"; return false;
    }
    body     = blob.data() + magic_len;
    body_len = sealed - magic_len;
    err.clear();
    return true;
}

} // namespace

// ═══ (1) outputs export ═════════════════════════════════════════════════════
// monero exported_transfer_details field subset (public, no secret): m_pubkey P,
// m_tx_pubkey R, internal output index i, global output index, subaddr(major,
// minor), amount, and the rct mask (public to the owner; the online view-only
// wallet already recomputed it during scan).
std::vector<unsigned char> produce_outputs_export(
    const std::vector<ExportedOutput>& outs, std::uint64_t offset) {
    std::vector<unsigned char> p;
    put_varint(p, offset);
    put_varint(p, outs.size());
    for (const ExportedOutput& o : outs) {
        put_key(p, o.one_time_pub);
        put_key(p, o.tx_pubkey);
        put_varint(p, o.output_index);
        put_varint(p, o.subaddr.major);
        put_varint(p, o.subaddr.minor);
        put_varint(p, o.amount);
        put_key(p, o.amount_mask);
    }
    return seal(OUTPUT_EXPORT_MAGIC, sizeof(OUTPUT_EXPORT_MAGIC) - 1, std::move(p));
}

bool parse_outputs_export(const std::vector<unsigned char>& blob,
                          std::vector<ExportedOutput>& outs,
                          std::uint64_t& offset, std::string& err) {
    const unsigned char* body; std::size_t body_len;
    if (!unseal(blob, OUTPUT_EXPORT_MAGIC, sizeof(OUTPUT_EXPORT_MAGIC) - 1,
                body, body_len, err)) return false;
    Reader r(body, body_len);
    offset = r.varint();
    const std::uint64_t n = r.varint();
    if (!r.ok() || n > body_len /* each record >= 1 byte */) { err = "bad outputs count"; return false; }
    outs.clear();
    outs.reserve(static_cast<std::size_t>(n));
    for (std::uint64_t k = 0; k < n; ++k) {
        ExportedOutput o;
        o.one_time_pub  = r.key();
        o.tx_pubkey     = r.key();
        o.output_index  = r.varint();
        o.subaddr.major = static_cast<std::uint32_t>(r.varint());
        o.subaddr.minor = static_cast<std::uint32_t>(r.varint());
        o.amount        = r.varint();
        o.amount_mask   = r.key();
        outs.push_back(o);
    }
    if (!r.ok() || !r.at_end()) { err = "outputs export: trailing/short data"; return false; }
    return true;
}

// ═══ (2) key-image export ════════════════════════════════════════════════════
// monero: (offset, [(key_image, signature)]). We add P_i so the online side can
// bind the image to a scanned output. signature is the 64-byte c||r ring sig.
std::vector<unsigned char> produce_key_image_export(
    const std::vector<prover::ExportedKeyImage>& imgs, std::uint64_t offset) {
    std::vector<unsigned char> p;
    put_varint(p, offset);
    put_varint(p, imgs.size());
    for (const prover::ExportedKeyImage& e : imgs) {
        put_key(p, e.one_time_pub);
        put_key(p, e.image);
        p.insert(p.end(), e.signature.begin(), e.signature.end());  // 64 bytes
    }
    return seal(KEY_IMAGE_EXPORT_MAGIC, sizeof(KEY_IMAGE_EXPORT_MAGIC) - 1, std::move(p));
}

bool parse_key_image_export(const std::vector<unsigned char>& blob,
                            std::vector<prover::ExportedKeyImage>& imgs,
                            std::uint64_t& offset, std::string& err) {
    const unsigned char* body; std::size_t body_len;
    if (!unseal(blob, KEY_IMAGE_EXPORT_MAGIC, sizeof(KEY_IMAGE_EXPORT_MAGIC) - 1,
                body, body_len, err)) return false;
    Reader r(body, body_len);
    offset = r.varint();
    const std::uint64_t n = r.varint();
    if (!r.ok() || n > body_len) { err = "bad key-image count"; return false; }
    imgs.clear();
    imgs.reserve(static_cast<std::size_t>(n));
    for (std::uint64_t k = 0; k < n; ++k) {
        prover::ExportedKeyImage e;
        e.one_time_pub = r.key();
        e.image        = r.key();
        Bytes32 lo = r.key();  // signature[0..32)
        Bytes32 hi = r.key();  // signature[32..64)
        if (!r.ok()) break;
        std::memcpy(e.signature.data(),      lo.data(), 32);
        std::memcpy(e.signature.data() + 32, hi.data(), 32);
        imgs.push_back(e);
    }
    if (!r.ok() || !r.at_end()) { err = "key-image export: trailing/short data"; return false; }
    return true;
}

// ═══ (3) unsigned txset ══════════════════════════════════════════════════════
// tx_source_entry field order (subset): outputs = [(global_index, ctkey{dest,
// mask})], real_output, real_out_tx_key, real_output_in_tx_index, amount, mask.
// Then splitted_dsts (destinations), fee, tx_extra.
std::vector<unsigned char> produce_unsigned_txset(const UnsignedTxSet& u) {
    std::vector<unsigned char> p;
    put_varint(p, u.sources.size());
    for (const UnsignedTxSource& s : u.sources) {
        put_varint(p, s.ring.size());
        for (std::size_t i = 0; i < s.ring.size(); ++i) {
            const std::uint64_t gi =
                (i < s.ring_global_indices.size()) ? s.ring_global_indices[i] : i;
            put_varint(p, gi);
            put_key(p, s.ring[i].dest);
            put_key(p, s.ring[i].mask);
        }
        put_varint(p, s.real_index);
        put_key(p, s.real_out_tx_key);
        put_varint(p, s.real_output_in_tx_index);
        put_varint(p, s.amount);
        put_key(p, s.mask);
    }
    put_varint(p, u.dests.size());
    for (const prover::TxDestination& d : u.dests) {
        put_key(p, d.spend_pub);
        put_key(p, d.view_pub);
        put_varint(p, d.amount);
        put_varint(p, d.is_subaddress ? 1 : 0);
    }
    put_varint(p, u.fee);
    put_bytes(p, u.tx_extra);
    return seal(UNSIGNED_TX_MAGIC, sizeof(UNSIGNED_TX_MAGIC) - 1, std::move(p));
}

bool parse_unsigned_txset(const std::vector<unsigned char>& blob,
                          UnsignedTxSet& u, std::string& err) {
    const unsigned char* body; std::size_t body_len;
    if (!unseal(blob, UNSIGNED_TX_MAGIC, sizeof(UNSIGNED_TX_MAGIC) - 1,
                body, body_len, err)) return false;
    Reader r(body, body_len);
    u = UnsignedTxSet{};
    const std::uint64_t nsrc = r.varint();
    if (!r.ok() || nsrc > body_len) { err = "bad sources count"; return false; }
    for (std::uint64_t k = 0; k < nsrc; ++k) {
        UnsignedTxSource s;
        const std::uint64_t nring = r.varint();
        if (!r.ok() || nring > body_len) { err = "bad ring size"; return false; }
        for (std::uint64_t i = 0; i < nring; ++i) {
            s.ring_global_indices.push_back(r.varint());
            prover::CtKey ck;
            ck.dest = r.key();
            ck.mask = r.key();
            s.ring.push_back(ck);
        }
        s.real_index               = r.varint();
        s.real_out_tx_key          = r.key();
        s.real_output_in_tx_index  = r.varint();
        s.amount                   = r.varint();
        s.mask                     = r.key();
        if (!r.ok()) { err = "unsigned txset: short source"; return false; }
        if (s.real_index >= s.ring.size()) { err = "unsigned txset: real_index out of range"; return false; }
        u.sources.push_back(std::move(s));
    }
    const std::uint64_t nd = r.varint();
    if (!r.ok() || nd > body_len) { err = "bad dests count"; return false; }
    for (std::uint64_t k = 0; k < nd; ++k) {
        prover::TxDestination d;
        d.spend_pub     = r.key();
        d.view_pub      = r.key();
        d.amount        = r.varint();
        d.is_subaddress = (r.varint() != 0);
        u.dests.push_back(d);
    }
    u.fee      = r.varint();
    u.tx_extra = r.bytes();
    if (!r.ok() || !r.at_end()) { err = "unsigned txset: trailing/short data"; return false; }
    return true;
}

bool sources_to_spend_inputs(const UnsignedTxSet& u, const MoneroKeys& keys,
                             std::vector<prover::SpendInput>& out, std::string& err) {
    if (!keys.can_sign()) {
        err = "offline signer needs a full wallet: view-only cannot re-derive x_i";
        return false;
    }
    out.clear();
    out.reserve(u.sources.size());
    for (const UnsignedTxSource& s : u.sources) {
        if (s.real_index >= s.ring.size()) { err = "source real_index out of range"; return false; }
        // monero wallet2::sign_tx re-derivation: D = 8*k_v*R; x = H_s(D||i)+k_s.
        Bytes32 D{};
        if (!scanops::key_derivation(s.real_out_tx_key, keys.view_priv, D)) {
            err = "key_derivation failed on a source"; return false;
        }
        prover::SpendInput in;
        in.one_time_sec       = scanops::derive_secret_key(D, s.real_output_in_tx_index, keys.spend_priv);
        in.amount             = s.amount;
        in.amount_mask        = s.mask;
        in.ring               = s.ring;
        in.real_index         = static_cast<std::size_t>(s.real_index);
        in.ring_global_indices = s.ring_global_indices;
        // Sanity: the re-derived secret must key the real ring member's dest.
        Bytes32 P_check{};
        if (!mcrypto::secret_to_public(in.one_time_sec, P_check) ||
            P_check != s.ring[in.real_index].dest) {
            err = "re-derived one-time secret does not match the real ring member "
                  "(wrong wallet for this unsigned txset)";
            return false;
        }
        out.push_back(std::move(in));
    }
    return true;
}

// ═══ (4) signed txset ════════════════════════════════════════════════════════
// pending_tx subset: the serialized cryptonote::transaction blob (verbatim),
// its tx_hash, and the per-input key images.
std::vector<unsigned char> produce_signed_txset(const prover::RingctTx& tx) {
    std::vector<unsigned char> p;
    put_varint(p, tx.key_images.size());
    for (const Bytes32& I : tx.key_images) put_key(p, I);
    put_key(p, tx.tx_hash);
    put_varint(p, tx.blob.size());
    p.insert(p.end(), tx.blob.begin(), tx.blob.end());
    return seal(SIGNED_TX_MAGIC, sizeof(SIGNED_TX_MAGIC) - 1, std::move(p));
}

bool parse_signed_txset(const std::vector<unsigned char>& blob,
                        SignedTxSet& s, std::string& err) {
    const unsigned char* body; std::size_t body_len;
    if (!unseal(blob, SIGNED_TX_MAGIC, sizeof(SIGNED_TX_MAGIC) - 1,
                body, body_len, err)) return false;
    Reader r(body, body_len);
    s = SignedTxSet{};
    const std::uint64_t nki = r.varint();
    if (!r.ok() || nki > body_len) { err = "bad key-image count"; return false; }
    for (std::uint64_t k = 0; k < nki; ++k) s.key_images.push_back(r.key());
    s.tx_hash = r.key();
    s.tx_blob = r.bytes();
    if (!r.ok() || !r.at_end()) { err = "signed txset: trailing/short data"; return false; }
    return true;
}

} // namespace c2wallet::monero::artifact
