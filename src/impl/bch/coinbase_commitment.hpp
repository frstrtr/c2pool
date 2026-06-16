#pragma once
//
// coinbase_commitment.hpp -- Coinbase / template commitment construction and
// validation for BCH p2pool shares (M3->M4 seam).
//
// BCH is a STANDALONE PARENT in V36 (no merged-mining aux module), so the
// coinbase commitment is the BTC c2pool layout MINUS the AuxPoW segment. The
// pinned commitment scriptSig layout (verified vs BCHN reference, 2026-06-16):
//
//   [ BIP34 block-height push ] [ "/c2pool/" tag ] [ state_root (32B) ] [ TheMetadata ]
//
//   * BIP34 height is CONSENSUS-REQUIRED and the first scriptSig push. BCHN
//     enforces it in ContextualCheckBlock ("bad-cb-height", validation.cpp
//     ~L3870); the template builder MUST emit it or BCHN rejects the block.
//   * NO witness commitment -- SegWit is struck from BCH consensus. The BTC
//     OP_RETURN witness-commitment output has no analog here.
//   * CTOR (canonical tx ordering, Nov 2018) is a SEPARATE concern handled by
//     the template builder's tx sort, NOT part of the coinbase commitment.
//   * CashTokens outputs are transparent -- carried unchanged; they do not
//     alter the coinbase commitment bytes.
//   * state_root is the c2pool sharechain commitment (32 bytes, SHA256d-domain).
//   * TheMetadata is the trailing p2pool metadata blob (variable length).
//
// This is the construction the M4 GBT template builder will emit and the share
// validator will check; both must agree, hence a single shared module. Layout
// matches frstrtr/p2pool-merged-v36 -- standalone-parent path, AuxPoW segment
// absent -> NO [decision-needed] (V36 master-compat preserved).
//
// Mirrors the BCH module convention of src/impl/bch/donation_consensus.hpp:
// self-contained, std-typed, header-only, source-only (NOT yet CMake-registered
// on bch/m3-coin-node).
//
// Reference: frstrtr/p2pool-merged-v36 p2pool/bitcoin/data.py (coinbase build),
//            BCHN validation.cpp ContextualCheckBlock (BIP34 enforcement).
//

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace bch::consensus
{

// The c2pool coinbase tag pushed immediately after the BIP34 height.
inline constexpr char     COINBASE_TAG[]   = "/c2pool/";
inline constexpr size_t   COINBASE_TAG_LEN = sizeof(COINBASE_TAG) - 1;  // exclude NUL
inline constexpr size_t   STATE_ROOT_LEN   = 32;                        // SHA256d digest

// ---------------------------------------------------------------------------
// BIP34 height serialization
//
// BIP34 requires the block height as the first item of the coinbase scriptSig,
// minimally encoded as a CScriptNum (signed, little-endian, with the canonical
// sign-byte rule), preceded by its length as a direct push opcode. Heights are
// always positive and small enough to fit a direct (<=0x4b) push.
// ---------------------------------------------------------------------------

// Encode `height` as a minimal little-endian CScriptNum byte vector (no opcode).
inline std::vector<unsigned char> encode_script_num(int64_t height)
{
    std::vector<unsigned char> out;
    if (height == 0)
        return out;  // BIP34: height is never 0 (genesis has no BIP34), but be total

    const bool neg = height < 0;
    uint64_t    abs = neg ? static_cast<uint64_t>(-height) : static_cast<uint64_t>(height);

    while (abs)
    {
        out.push_back(static_cast<unsigned char>(abs & 0xff));
        abs >>= 8;
    }

    // If the MSB of the top byte is set, the number would read as negative, so
    // append a sign byte (0x00 for positive, 0x80 for negative).
    if (out.back() & 0x80)
        out.push_back(neg ? 0x80 : 0x00);
    else if (neg)
        out.back() |= 0x80;

    return out;
}

// Build the full BIP34 height push: [len opcode][little-endian height bytes].
inline std::vector<unsigned char> build_bip34_height_push(int64_t height)
{
    if (height < 0)
        throw std::invalid_argument("bch::consensus: BIP34 height must be non-negative");

    std::vector<unsigned char> num = encode_script_num(height);
    if (num.size() > 0x4b)
        throw std::invalid_argument("bch::consensus: BIP34 height push too large");

    std::vector<unsigned char> push;
    push.reserve(num.size() + 1);
    push.push_back(static_cast<unsigned char>(num.size()));  // direct push opcode
    push.insert(push.end(), num.begin(), num.end());
    return push;
}

// Decode a BIP34 CScriptNum (no opcode) back to an integer. Used by the
// validator to confirm the height encoded in a received coinbase.
inline int64_t decode_script_num(const std::vector<unsigned char>& num)
{
    if (num.empty())
        return 0;
    if (num.size() > 8)
        throw std::invalid_argument("bch::consensus: scriptnum too large");

    int64_t result = 0;
    for (size_t i = 0; i < num.size(); ++i)
        result |= static_cast<int64_t>(num[i]) << (8 * i);

    // Apply sign from the top byte's high bit.
    if (num.back() & 0x80)
    {
        const int64_t mask = static_cast<int64_t>(1) << (8 * num.size() - 1);
        return -(result & ~mask);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Commitment construction
// ---------------------------------------------------------------------------

// Build the BCH coinbase commitment scriptSig payload:
//   [BIP34 height push] || "/c2pool/" || state_root(32B) || metadata
// `state_root` must be exactly 32 bytes. `metadata` may be empty.
inline std::vector<unsigned char> build_coinbase_commitment(
    int64_t                           height,
    const std::vector<unsigned char>& state_root,
    const std::vector<unsigned char>& metadata = {})
{
    if (state_root.size() != STATE_ROOT_LEN)
        throw std::invalid_argument("bch::consensus: state_root must be 32 bytes");

    std::vector<unsigned char> out = build_bip34_height_push(height);
    out.insert(out.end(), COINBASE_TAG, COINBASE_TAG + COINBASE_TAG_LEN);
    out.insert(out.end(), state_root.begin(), state_root.end());
    out.insert(out.end(), metadata.begin(), metadata.end());
    return out;
}

// ---------------------------------------------------------------------------
// Commitment validation
// ---------------------------------------------------------------------------

struct CommitmentValidationResult
{
    bool                       ok{false};
    std::string                error;          // human-readable reason when !ok
    int64_t                    height{0};      // parsed BIP34 height
    std::vector<unsigned char> state_root;     // parsed 32B sharechain commitment
    std::vector<unsigned char> metadata;       // parsed trailing TheMetadata blob
};

// Parse and validate a coinbase scriptSig against the expected (height,
// state_root). On success, the parsed fields are returned for the caller to
// cross-check. `expected_height` < 0 means "do not enforce a specific height"
// (still parses and returns it).
inline CommitmentValidationResult validate_coinbase_commitment(
    const std::vector<unsigned char>& script_sig,
    int64_t                           expected_height,
    const std::vector<unsigned char>& expected_state_root = {})
{
    CommitmentValidationResult r;
    size_t                     pos = 0;

    // 1. BIP34 height push: [len][bytes].
    if (script_sig.empty())
    {
        r.error = "empty coinbase scriptSig (BIP34 height missing)";
        return r;
    }
    const size_t hlen = script_sig[0];
    if (hlen == 0 || hlen > 0x4b || 1 + hlen > script_sig.size())
    {
        r.error = "malformed BIP34 height push";
        return r;
    }
    pos = 1;
    std::vector<unsigned char> hbytes(script_sig.begin() + pos,
                                      script_sig.begin() + pos + hlen);
    pos += hlen;
    r.height = decode_script_num(hbytes);

    if (expected_height >= 0 && r.height != expected_height)
    {
        r.error = "BIP34 height mismatch (bad-cb-height)";
        return r;
    }

    // 2. "/c2pool/" tag.
    if (pos + COINBASE_TAG_LEN > script_sig.size() ||
        std::memcmp(script_sig.data() + pos, COINBASE_TAG, COINBASE_TAG_LEN) != 0)
    {
        r.error = "missing or wrong /c2pool/ commitment tag";
        return r;
    }
    pos += COINBASE_TAG_LEN;

    // 3. state_root (32B).
    if (pos + STATE_ROOT_LEN > script_sig.size())
    {
        r.error = "truncated state_root commitment";
        return r;
    }
    r.state_root.assign(script_sig.begin() + pos, script_sig.begin() + pos + STATE_ROOT_LEN);
    pos += STATE_ROOT_LEN;

    if (!expected_state_root.empty() && r.state_root != expected_state_root)
    {
        r.error = "state_root commitment mismatch";
        return r;
    }

    // 4. Trailing TheMetadata blob (may be empty).
    r.metadata.assign(script_sig.begin() + pos, script_sig.end());

    r.ok = true;
    return r;
}

}  // namespace bch::consensus
