// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vendored from dashcore/src/evo/simplifiedmns.{h,cpp} @ develop cfad414
// (Dash Core v23.1-dev).
//
// Adaptations from upstream:
//
//   1. Wire-format mode is hard-coded to "current Dash mainnet at our
//      advertised proto version (70230)". Specifically:
//        - SMNLE_VERSIONED_PROTO_VERSION (70228): we ARE past it →
//          nVersion is always serialized as the first wire field.
//        - DMN_TYPE_PROTO_VERSION (70227): we ARE past it →
//          the early-return "skip nType for old peers" branch is
//          dropped from our SERIALIZE_METHODS body.
//      Per-entry nVersion still controls which fields exist (BLS scheme,
//      ExtAddr, Evo type extras) — that gating is preserved verbatim.
//      If c2pool-dash ever advertises a proto < 70228, this will break;
//      we'd then need to multiplex on a serialization-mode tag like
//      dashcore's CHashWriter. Not relevant pre-Phase L.
//
//   2. NetInfoInterface / NetInfoSerWrapper is replaced by an inline
//      18-byte legacy CService (16-byte raw IPv6 + 2-byte BE port).
//      MnNetInfo (DIP-0028 ExtAddr multi-addr) is NOT supported yet —
//      ExtAddr is gated behind `DEPLOYMENT_V24` (EHF) which has not
//      activated on Dash mainnet. We log+drop entries with
//      nVersion >= ExtAddr (==3) so the absence is visible. Re-vendor
//      with NetInfo support once DEPLOYMENT_V24 activates.
//
//   3. CBLSLazyPublicKey is replaced by a 48-byte std::array (pass-
//      through-correct wire bytes; legacy/basic BLS scheme-flag is
//      invisible at the wire layer — it only affects how the impl
//      decompresses the curve point, which we never do at MVP).
//
//   4. CKeyID = uint160. Same wire bytes (20 raw).
//
//   5. CScript scriptPayout / scriptOperatorPayout are upstream's
//      "mem-only" fields — never serialized into mnlistdiff or the
//      merkle-leaf hash. We omit them entirely.
//
//   6. CalcHash() is hand-written to mirror dashcore's SER_GETHASH
//      path bit-for-bit:
//        - SKIP nVersion (the SER_NETWORK guard zeros it out)
//        - SKIP the "early return for old peers" guard
//        - HONOUR per-entry nVersion-conditional branches
//      Bit-exact match to dashcore is THE acceptance criterion; this is
//      where Phase C-SML lives or dies. Step 7 verifies against the
//      CBTX merkleRootMNList we already parse in step 1.
//
//   7. ComputeMerkleRoot reuses ltc::coin::compute_merkle_root() which
//      is the standard SHA256d-pairwise / duplicate-last-on-odd
//      algorithm — wire-identical to dashcore's consensus/merkle.cpp.

// IMPORTANT include order: pack.hpp via shim.hpp BEFORE anything that
// might transitively pull in btclibs/serialize.h. Specifically we used
// to include impl/ltc/coin/template_builder.hpp here for its
// compute_merkle_root helper, but that header pulls in mweb_builder.hpp
// → btclibs/serialize.h → 2-arg SERIALIZE_METHODS macro that collides
// with pack.hpp's 1-arg form (landmine #1, see
// project_dash_spv_embedded_landmines.md). Inlining the 12-line
// compute_merkle_root helper below keeps this header self-contained.

#include <impl/dash/coin/vendor/shim.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/hash.hpp>   // CHash256 (this version, not btclibs/hash.h —
                            // the latter pulls btclibs/serialize.h via its
                            // own #include and triggers landmine #1)
#include <core/log.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <sstream>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

struct CSimplifiedMNListEntry
{
    static constexpr uint16_t VER_LEGACY_BLS = 1;
    static constexpr uint16_t VER_BASIC_BLS  = 2;
    static constexpr uint16_t VER_EXT_ADDR   = 3;

    static constexpr uint16_t TYPE_REGULAR = 0;
    static constexpr uint16_t TYPE_EVO     = 1;

    static constexpr size_t BLS_PUBKEY_SIZE = 48;
    static constexpr size_t NETADDR_SIZE    = 16;

    uint16_t                              nVersion{VER_BASIC_BLS};
    uint256                               proRegTxHash;
    uint256                               confirmedHash;
    std::array<uint8_t, NETADDR_SIZE>     netAddress{};   // raw IPv6 (v4 = ::ffff:...)
    uint16_t                              netPort{0};      // BE on the wire (CService)
    std::array<uint8_t, BLS_PUBKEY_SIZE>  pubKeyOperator{};
    uint160                               keyIDVoting;
    bool                                  isValid{false};
    uint16_t                              nType{TYPE_REGULAR};
    // LE on the wire — a PLAIN uint16 member upstream (READWRITE(obj.
    // platformHTTPPort)), unlike netPort which rides CService's BE port.
    // (Was mis-annotated/mis-coded BE here: symmetric read+write made every
    // FROM-WIRE round-trip byte-identical — the proven root parity was
    // unaffected — but the in-memory value was byte-swapped and any entry
    // CONSTRUCTED from a numeric port hashed wrong. Verified against real
    // testnet Evo entries: LE reproduces cbTx.merkleRootMNList.)
    uint16_t                              platformHTTPPort{0};
    uint160                               platformNodeID;

    // c2pool pack.hpp uses explicit Serialize/Unserialize members (the
    // Serializable concept = `a.Serialize(s)`), NOT dashcore's
    // SERIALIZE_METHODS/READWRITE macro (which is not mapped in our pack
    // layer and would leave the type non-serializable). Field order and
    // the per-entry nVersion-conditional gating are preserved verbatim.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << nVersion
          << proRegTxHash
          << confirmedHash
          << Using<RawBytesFormat<NETADDR_SIZE>>(netAddress)
          << Using<BigEndianFormat<2>>(netPort)
          << Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(pubKeyOperator)
          << keyIDVoting
          << isValid;
        if (nVersion >= VER_BASIC_BLS) {
            s << nType;
            if (nType == TYPE_EVO) {
                if (nVersion < VER_EXT_ADDR) {
                    s << platformHTTPPort;   // plain uint16 => LE (upstream)
                }
                s << platformNodeID;
            }
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> nVersion
          >> proRegTxHash
          >> confirmedHash
          >> Using<RawBytesFormat<NETADDR_SIZE>>(netAddress)
          >> Using<BigEndianFormat<2>>(netPort)
          >> Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(pubKeyOperator)
          >> keyIDVoting
          >> isValid;
        if (nVersion >= VER_BASIC_BLS) {
            s >> nType;
            if (nType == TYPE_EVO) {
                if (nVersion < VER_EXT_ADDR) {
                    s >> platformHTTPPort;   // plain uint16 => LE (upstream)
                }
                s >> platformNodeID;
            }
        }
    }

    // Mirrors dashcore CSimplifiedMNListEntry::CalcHash() with SER_GETHASH
    // semantics: nVersion is OMITTED, the old-peer early-return is
    // OMITTED, per-entry nVersion-conditional fields are HONOURED.
    uint256 CalcHash() const
    {
        ::PackStream s;
        s << proRegTxHash;
        s << confirmedHash;
        s.write(std::as_bytes(std::span{netAddress}));
        // CService port: 2 bytes big-endian
        uint8_t port_be[2] = {
            static_cast<uint8_t>((netPort >> 8) & 0xff),
            static_cast<uint8_t>(netPort & 0xff)
        };
        s.write(std::as_bytes(std::span{port_be}));
        s.write(std::as_bytes(std::span{pubKeyOperator}));
        s << keyIDVoting;
        s << isValid;
        if (nVersion >= VER_BASIC_BLS) {
            s << nType;
            if (nType == TYPE_EVO) {
                if (nVersion < VER_EXT_ADDR) {
                    s << platformHTTPPort;   // plain uint16 => LE (upstream)
                }
                s << platformNodeID;
            }
        }

        auto bytes = s.get_span();
        uint256 hash;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(bytes.data()),
                bytes.size()))
            .Finalize(std::span<unsigned char>(hash.data(), 32));
        return hash;
    }

    bool operator==(const CSimplifiedMNListEntry& r) const
    {
        return nVersion == r.nVersion
            && proRegTxHash == r.proRegTxHash
            && confirmedHash == r.confirmedHash
            && netAddress == r.netAddress
            && netPort == r.netPort
            && pubKeyOperator == r.pubKeyOperator
            && keyIDVoting == r.keyIDVoting
            && isValid == r.isValid
            && nType == r.nType
            && platformHTTPPort == r.platformHTTPPort
            && platformNodeID == r.platformNodeID;
    }

    std::string short_str() const
    {
        std::ostringstream os;
        os << "v" << nVersion
           << " t" << nType
           << " proreg=" << proRegTxHash.GetHex().substr(0, 12)
           << " port=" << netPort
           << (isValid ? " VALID" : " INVALID");
        return os.str();
    }
};

// Holds the CURRENT SML at a given block. Entries are kept sorted by
// proRegTxHash ascending — required for both equality comparisons and
// for the merkle-root calculation to match dashcore bit-for-bit.
class CSimplifiedMNList
{
public:
    std::vector<CSimplifiedMNListEntry> mnList;

    CSimplifiedMNList() = default;

    // Sort on construction; mirrors dashcore's
    // CSimplifiedMNList(std::vector<...>&&) constructor.
    explicit CSimplifiedMNList(std::vector<CSimplifiedMNListEntry>&& entries)
        : mnList(std::move(entries))
    {
        sort();
    }

    void sort()
    {
        // CRITICAL: dashcore sorts by `proRegTxHash.Compare(other) < 0`
        // where Compare is `std::memcmp(m_data.data(), other.data(), 32)`
        // — i.e., LITTLE-endian-byte-order ascending (the order bytes
        // sit in memory). c2pool's uint256 operator< uses CompareTo
        // which iterates uint32 limbs from MSB-first → BIG-endian-
        // INTEGER ascending. These are DIFFERENT orderings, and using
        // the wrong one produces a different merkle leaf order →
        // different merkle root → CBTX root mismatch on every block
        // (Bug A surfaced live 2026-04-24 against Dash mainnet).
        // memcmp matches dashcore's wire semantics; do NOT change.
        std::sort(mnList.begin(), mnList.end(),
            [](const CSimplifiedMNListEntry& a,
               const CSimplifiedMNListEntry& b) {
                return std::memcmp(a.proRegTxHash.data(),
                                   b.proRegTxHash.data(), 32) < 0;
            });
    }

    uint256 CalcMerkleRoot() const
    {
        if (mnList.empty()) return uint256::ZERO;
        std::vector<uint256> leaves;
        leaves.reserve(mnList.size());
        for (const auto& e : mnList) leaves.push_back(e.CalcHash());
        return compute_merkle_root_local(std::move(leaves));
    }

    size_t size() const { return mnList.size(); }

private:
    // Standard Bitcoin/Dash SHA256d-pairwise merkle root with
    // duplicate-last-on-odd. Inlined from
    // ltc::coin::compute_merkle_root() to keep this header free of
    // mweb_builder.hpp's btclibs/serialize.h transitive include —
    // see preamble re landmine #1.
    static uint256 merkle_pair_hash(const uint256& a, const uint256& b)
    {
        uint256 out;
        CHash256()
            .Write(std::span<const unsigned char>(a.data(), 32))
            .Write(std::span<const unsigned char>(b.data(), 32))
            .Finalize(std::span<unsigned char>(out.data(), 32));
        return out;
    }

    static uint256 compute_merkle_root_local(std::vector<uint256> hashes)
    {
        if (hashes.empty()) return uint256::ZERO;
        while (hashes.size() > 1) {
            if (hashes.size() & 1u)
                hashes.push_back(hashes.back());
            std::vector<uint256> next;
            next.reserve(hashes.size() / 2);
            for (size_t i = 0; i < hashes.size(); i += 2)
                next.push_back(merkle_pair_hash(hashes[i], hashes[i + 1]));
            hashes = std::move(next);
        }
        return hashes[0];
    }
};

} // namespace vendor
} // namespace coin
} // namespace dash