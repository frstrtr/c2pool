// COMPILE-CHECK SHIM ONLY -- not a deliverable. Minimal stand-in for the
// monero-primitives leg's src/impl/xmr/coin/xmr_blob.hpp so w5-coinbase can be
// syntax-checked and its exact-sum logic run WITHOUT the vendored CryptoNote
// serializer / keccak. Signatures match the real header; hashes are stubbed.
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include "xmr_crypto_types.hpp"

namespace xmr { namespace coin {

inline constexpr std::uint8_t TXIN_GEN            = 0xFF;
inline constexpr std::uint8_t TXOUT_TO_TAGGED_KEY = 0x03;
inline constexpr std::uint64_t TX_VERSION_2       = 2;
inline constexpr std::uint64_t MINER_REWARD_UNLOCK_TIME = 60;
inline constexpr std::uint8_t TX_EXTRA_TAG_PADDING       = 0x00;
inline constexpr std::uint8_t TX_EXTRA_TAG_PUBKEY        = 0x01;
inline constexpr std::uint8_t TX_EXTRA_TAG_NONCE         = 0x02;
inline constexpr std::uint8_t TX_EXTRA_TAG_MERGE_MINING  = 0x03;
inline constexpr std::uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;

class BlobWriter {
public:
    void put_byte(std::uint8_t b) { buf_.push_back(b); }
    void put_bytes(const void* p, std::size_t n) {
        const auto* c = static_cast<const unsigned char*>(p);
        buf_.insert(buf_.end(), c, c + n);
    }
    void put_key(const Bytes32& k) { put_bytes(k.data(), 32); }
    void put_varint(std::uint64_t v) {           // LEB128 (shim impl)
        while (v >= 0x80) { put_byte(static_cast<std::uint8_t>(v) | 0x80); v >>= 7; }
        put_byte(static_cast<std::uint8_t>(v));
    }
    void put_u32_le(std::uint32_t v) {
        for (int i = 0; i < 4; ++i) put_byte(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    const std::vector<unsigned char>& bytes() const { return buf_; }
    std::size_t size() const { return buf_.size(); }
    void clear() { buf_.clear(); }
private:
    std::vector<unsigned char> buf_;
};

inline void write_tagged_key_output(BlobWriter& w, std::uint64_t amount,
                                    const PublicKey& one_time_key, ViewTag vt) {
    w.put_varint(amount); w.put_byte(TXOUT_TO_TAGGED_KEY);
    w.put_key(one_time_key); w.put_byte(vt.tag);
}

inline std::vector<unsigned char> write_coinbase_prefix_head(
        std::uint64_t height, const std::uint64_t* amounts,
        const PublicKey* keys, const ViewTag* vtags, std::size_t n_outputs) {
    BlobWriter w;
    w.put_varint(TX_VERSION_2);
    w.put_varint(height + MINER_REWARD_UNLOCK_TIME);   // unlock_time
    w.put_varint(1); w.put_byte(TXIN_GEN); w.put_varint(height); // vin: txin_gen
    w.put_varint(n_outputs);
    for (std::size_t i = 0; i < n_outputs; ++i)
        write_tagged_key_output(w, amounts[i], keys[i], vtags[i]);
    return std::vector<unsigned char>(w.bytes());
}

inline Hash256 tx_prefix_hash(const std::vector<unsigned char>&) { return Hash256{}; }
inline Hash256 coinbase_tx_hash(const Hash256&) { return Hash256{}; }
inline Hash256 tree_root(const std::vector<Hash256>&) { return Hash256{}; }

struct TreeBranch { std::vector<Hash256> branch; std::uint32_t path = 0; std::size_t depth = 0; };
inline bool make_coinbase_branch(const std::vector<Hash256>&, TreeBranch&) { return true; }
inline bool verify_branch(const Hash256&, const TreeBranch&, const Hash256&) { return true; }

}} // namespace xmr::coin
