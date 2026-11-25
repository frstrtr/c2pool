// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Masternode network info, ported from Dash Core v24.0.0:
//
//   src/evo/netinfo.{h,cpp}   NetInfoPurpose, DomainPort, NetInfoEntry,
//                             ExtNetInfo (the "extended addresses" of
//                             ProTx / SML entry version 3) and the MnNetInfo
//                             rules of versions 1 and 2
//   src/netaddress.{h,cpp}    the ADDRv2 (BIP155) CService codec a
//                             NetInfoEntry carries, CNetAddr::IsValid,
//                             IsRoutable and the RFC range predicates
//   src/netbase.cpp           IsBadPort
//   src/evo/providertx.cpp    CheckProviderNetworkFields and its helpers,
//                             with Core's reject reasons
//
// Wire formats:
//   * version 1/2 netInfo (MnNetInfo): the legacy 18-byte CService, 16 raw
//     IPv6 bytes and a big-endian port. Kept as LegacyNetService, byte for
//     byte as before; nothing here changes how a v1/v2 payload or SML entry
//     is read, written or hashed.
//   * version 3 netInfo (ExtNetInfo):
//       u8 version (=1) | CompactSize n_purposes |
//       { u8 purpose | CompactSize n | NetInfoEntry * n } * n_purposes
//     with purposes strictly ascending (CORE_P2P=0, PLATFORM_P2P=1,
//     PLATFORM_HTTPS=2), so one object has exactly one encoding.
//     NetInfoEntry = u8 type | Service (0x01): ADDRv2 CService
//                                (u8 BIP155 net, CompactSize len, addr, BE port)
//                            | Domain (0x02): CompactSize len (<= 253), name, BE port
//                            | Invalid (0xff)
//
// Re-serialization is canonical, exactly as Core's: Core never keeps the
// received bytes, it re-encodes the parsed object (for the SML leaf hash as
// well). For every object Core accepts that canonical form equals the wire
// bytes (purposes ascending, CompactSize canonical, domains lower case), and
// the KATs assert it for every captured payload.
//
// Adaptations:
//   1. Core's CNetAddr/CService is reduced to what NetInfoEntry needs
//      (NetService below). The scope id and the address-manager parts are
//      not ported.
//   2. ToStringAddr() is exact for IPv4, IPv6 and CJDNS (RFC 5952, as Core
//      prints them). For Tor v3 and I2P it returns a tagged hex form instead
//      of the base32 name; Core compares these strings to find duplicate
//      addresses, so the only difference is the reject reason for a domain
//      entry that spells the same .onion/.i2p name as a service entry in
//      the same list (Core: duplicate, here: bad input). Both reject.
//   3. MaybeFlipIPv6toCJDNS depends on the node's -onlynet configuration in
//      Core; the legacy-to-extended conversion below therefore refuses an
//      fc00::/8 IPv6 address instead of guessing (MnNetInfo only ever holds
//      IPv4, so this cannot occur for a state Core accepted).
//   4. Chain parameters (mainnet or not, RequireRoutableExternalIP) come in
//      through NetInfoRules instead of a global Params().

#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ios>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

inline constexpr size_t NETADDR_SIZE = 16;

// ── Legacy 18-byte CService (MnNetInfo wire form, versions 1 and 2) ────────
struct LegacyNetService
{
    std::array<uint8_t, NETADDR_SIZE> ip{};
    uint16_t                          port_be{0};

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(std::as_bytes(std::span{ip}));
        uint8_t pb[2] = {
            static_cast<uint8_t>((port_be >> 8) & 0xff),
            static_cast<uint8_t>(port_be & 0xff)
        };
        s.write(std::as_bytes(std::span{pb}));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::array<uint8_t, NETADDR_SIZE> raw{};
        s.read(std::as_writable_bytes(std::span{raw}));
        ip = raw;
        uint8_t pb[2];
        s.read(std::as_writable_bytes(std::span{pb}));
        port_be = (uint16_t(pb[0]) << 8) | uint16_t(pb[1]);
    }

    bool operator==(const LegacyNetService&) const = default;

    /// Core's MnNetInfo::IsEmpty() for this service: an address that does
    /// not survive CNetAddr::SetLegacyIPv6 + IsValid, whatever the port
    /// (legacy_service_address_valid, below NetService).
    bool IsEmpty() const;

    /// The service as Core holds and re-serializes it: an empty MnNetInfo is
    /// written as CService{} -- 16 zero bytes and port 0 -- which is also what
    /// the SML leaf of such a masternode hashes. Unchanged when not empty.
    LegacyNetService canonical() const;
};

// ── Purposes and status codes (netinfo.h) ──────────────────────────────────
namespace NetInfoPurpose {
inline constexpr uint8_t CORE_P2P       = 0;
inline constexpr uint8_t PLATFORM_P2P   = 1;
inline constexpr uint8_t PLATFORM_HTTPS = 2;
constexpr bool is_valid(uint8_t p) { return p <= PLATFORM_HTTPS; }
} // namespace NetInfoPurpose

/// Maximum entries per purpose in an ExtNetInfo.
inline constexpr size_t MAX_ENTRIES_EXTNETINFO = 4;
/// Maximum ASCII FQDN length (RFC 1035), enforced at deserialization.
inline constexpr size_t DOMAIN_MAX_LEN = 253;

enum class NetInfoStatus : uint8_t {
    BadInput, Duplicate, MaxLimit,
    BadAddress, BadPort, BadType, NotRoutable, Malformed,
    Success
};

/// Chain parameters the netinfo rules read (Core: Params(), MainParams()).
struct NetInfoRules
{
    bool is_mainnet{true};                    ///< IsNodeOnMainnet()
    bool require_routable_external_ip{true};  ///< false on regtest only

    // Core compares against MainParams() whatever network it runs on.
    static constexpr uint16_t kMainCoreP2PPort        = 9999;
    static constexpr uint16_t kMainPlatformP2PPort    = 26656;
    static constexpr uint16_t kMainPlatformHTTPSPort  = 443;

    static constexpr NetInfoRules mainnet() { return {true, true}; }
    static constexpr NetInfoRules testnet() { return {false, true}; }
    static constexpr NetInfoRules devnet()  { return {false, true}; }
    static constexpr NetInfoRules regtest() { return {false, false}; }
};

/// netbase.cpp IsBadPort.
constexpr bool is_bad_port(uint16_t port)
{
    if (port > 0 && port <= 1023) return true;   // PRIVILEGED_PORTS_THRESHOLD
    switch (port) {
    case 1719: case 1720: case 1723: case 2049: case 3659: case 4045:
    case 5060: case 5061: case 6000: case 6566: case 6665: case 6666:
    case 6667: case 6668: case 6669: case 6697: case 8332: case 8333:
    case 10080: case 18332: case 18333:
        return true;
    }
    return false;
}

// ── NetService: CService in ADDRv2 form (netaddress.h) ─────────────────────
struct NetService
{
    // Core's Network enum (NET_UNROUTABLE is never stored).
    enum Net : uint8_t { IPV4 = 1, IPV6 = 2, ONION = 3, I2P = 4, CJDNS = 5, INTERNAL = 6 };
    // BIP155 network ids.
    static constexpr uint8_t BIP155_IPV4 = 1, BIP155_IPV6 = 2, BIP155_TORV2 = 3,
                             BIP155_TORV3 = 4, BIP155_I2P = 5, BIP155_CJDNS = 6;
    static constexpr size_t  MAX_ADDRV2_SIZE = 512;

    static constexpr std::array<uint8_t, 12> kIPv4InIPv6Prefix{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    static constexpr std::array<uint8_t, 6>  kTorV2InIPv6Prefix{0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43};
    static constexpr std::array<uint8_t, 6>  kInternalInIPv6Prefix{0xFD, 0x6B, 0x88, 0xC0, 0x87, 0x24};

    // Default = a default-constructed Core CService: IPv6 "::", port 0 (invalid).
    Net                  net{IPV6};
    std::vector<uint8_t> addr = std::vector<uint8_t>(16, 0);
    uint16_t             port{0};

    bool operator==(const NetService&) const = default;

    static NetService ipv4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
    {
        NetService s;
        s.net = IPV4;
        s.addr = {a, b, c, d};
        s.port = port;
        return s;
    }

    static NetService make(Net net, std::vector<uint8_t> addr, uint16_t port)
    {
        NetService s;
        s.net = net;
        s.addr = std::move(addr);
        s.port = port;
        return s;
    }

    /// CNetAddr::SetLegacyIPv6 + port: the reading of a legacy 18-byte CService.
    static NetService from_legacy(const LegacyNetService& l)
    {
        NetService s;
        s.port = l.port_be;
        const auto& ip = l.ip;
        if (std::equal(kIPv4InIPv6Prefix.begin(), kIPv4InIPv6Prefix.end(), ip.begin())) {
            s.net = IPV4;
            s.addr.assign(ip.begin() + 12, ip.end());
        } else if (std::equal(kTorV2InIPv6Prefix.begin(), kTorV2InIPv6Prefix.end(), ip.begin())) {
            s.net = IPV6;                         // TORv2 unsupported: !IsValid()
            s.addr.assign(16, 0);
        } else if (std::equal(kInternalInIPv6Prefix.begin(), kInternalInIPv6Prefix.end(), ip.begin())) {
            s.net = INTERNAL;
            s.addr.assign(ip.begin() + 6, ip.end());
        } else {
            s.net = IPV6;
            s.addr.assign(ip.begin(), ip.end());
        }
        return s;
    }

    bool IsIPv4() const     { return net == IPV4; }
    bool IsIPv6() const     { return net == IPV6; }
    bool IsTor() const      { return net == ONION; }
    bool IsI2P() const      { return net == I2P; }
    bool IsCJDNS() const    { return net == CJDNS; }
    bool IsInternal() const { return net == INTERNAL; }

    template <size_t N>
    bool has_prefix(const std::array<uint8_t, N>& p) const
    {
        return addr.size() >= N && std::equal(p.begin(), p.end(), addr.begin());
    }

    /// CNetAddr::IsValid.
    bool IsValid() const
    {
        if (IsIPv6() && std::all_of(addr.begin(), addr.end(), [](uint8_t b) { return b == 0; }))
            return false;
        if (IsCJDNS() && (addr.empty() || addr[0] != 0xFC)) return false;
        if (IsRFC3849()) return false;
        if (IsInternal()) return false;
        if (IsIPv4()) {
            const uint32_t a = (uint32_t(addr[0]) << 24) | (uint32_t(addr[1]) << 16)
                             | (uint32_t(addr[2]) << 8) | uint32_t(addr[3]);
            if (a == 0x00000000u || a == 0xFFFFFFFFu) return false;   // INADDR_ANY / INADDR_NONE
        }
        return true;
    }

    bool IsRFC1918() const
    {
        return IsIPv4() && (addr[0] == 10 || (addr[0] == 192 && addr[1] == 168)
                            || (addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31));
    }
    bool IsRFC2544() const { return IsIPv4() && addr[0] == 198 && (addr[1] == 18 || addr[1] == 19); }
    bool IsRFC3927() const { return IsIPv4() && addr[0] == 169 && addr[1] == 254; }
    bool IsRFC6598() const { return IsIPv4() && addr[0] == 100 && addr[1] >= 64 && addr[1] <= 127; }
    bool IsRFC5737() const
    {
        return IsIPv4() && ((addr[0] == 192 && addr[1] == 0 && addr[2] == 2)
                            || (addr[0] == 198 && addr[1] == 51 && addr[2] == 100)
                            || (addr[0] == 203 && addr[1] == 0 && addr[2] == 113));
    }
    bool IsRFC3849() const { return IsIPv6() && has_prefix(std::array<uint8_t, 4>{0x20, 0x01, 0x0D, 0xB8}); }
    bool IsRFC4862() const
    {
        return IsIPv6() && has_prefix(std::array<uint8_t, 8>{0xFE, 0x80, 0, 0, 0, 0, 0, 0});
    }
    bool IsRFC4193() const { return IsIPv6() && (addr[0] & 0xFE) == 0xFC; }
    bool IsRFC4843() const
    {
        return IsIPv6() && has_prefix(std::array<uint8_t, 3>{0x20, 0x01, 0x00}) && (addr[3] & 0xF0) == 0x10;
    }
    bool IsRFC7343() const
    {
        return IsIPv6() && has_prefix(std::array<uint8_t, 3>{0x20, 0x01, 0x00}) && (addr[3] & 0xF0) == 0x20;
    }
    bool IsLocal() const
    {
        if (IsIPv4() && (addr[0] == 127 || addr[0] == 0)) return true;
        if (IsIPv6()) {
            static constexpr std::array<uint8_t, 16> kLocal{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
            if (std::equal(kLocal.begin(), kLocal.end(), addr.begin())) return true;
        }
        return false;
    }
    /// CNetAddr::IsRoutable with the default -allowprivatenet=0.
    bool IsRoutable() const
    {
        if (!IsValid()) return false;
        if (IsRFC1918()) return false;
        return !(IsRFC2544() || IsRFC3927() || IsRFC4862() || IsRFC6598() || IsRFC5737()
                 || IsRFC4193() || IsRFC4843() || IsRFC7343() || IsLocal() || IsInternal());
    }

    uint8_t bip155_network() const
    {
        switch (net) {
        case IPV4: return BIP155_IPV4;
        case IPV6: return BIP155_IPV6;
        case ONION: return BIP155_TORV3;
        case I2P: return BIP155_I2P;
        case CJDNS: return BIP155_CJDNS;
        case INTERNAL: break;   // serialized as embedded IPv6 below
        }
        return BIP155_IPV6;
    }

    /// CService serialization with ADDRV2_FORMAT (CNetAddr::SerializeV2Stream + BE port).
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (IsInternal()) {
            write_u8(s, BIP155_IPV6);
            WriteCompactSize(s, 16);
            s.write(std::as_bytes(std::span{kInternalInIPv6Prefix}));
            s.write(std::as_bytes(std::span{addr}));
        } else {
            write_u8(s, bip155_network());
            WriteCompactSize(s, addr.size());
            if (!addr.empty()) s.write(std::as_bytes(std::span{addr}));
        }
        const uint8_t pb[2] = {static_cast<uint8_t>(port >> 8), static_cast<uint8_t>(port & 0xff)};
        s.write(std::as_bytes(std::span{pb}));
    }

    /// CNetAddr::UnserializeV2Stream + BE port, including Core's handling of
    /// unknown network ids (skipped, read as an invalid address), known ids
    /// with the wrong length (throws) and IPv4/TORv2 embedded in an IPv6
    /// record (read as an invalid address).
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t netid{0};
        s >> netid;
        const uint64_t size = ReadCompactSize(s);
        if (size > MAX_ADDRV2_SIZE)
            throw std::ios_base::failure("Address too long");
        bool known = true;
        switch (netid) {
        case BIP155_IPV4:  expect_size(size, 4);  net = IPV4;  break;
        case BIP155_IPV6:  expect_size(size, 16); net = IPV6;  break;
        case BIP155_TORV3: expect_size(size, 32); net = ONION; break;
        case BIP155_I2P:   expect_size(size, 32); net = I2P;   break;
        case BIP155_CJDNS: expect_size(size, 16); net = CJDNS; break;
        default: known = false; break;
        }
        bool invalid = false;
        if (known) {
            addr.assign(size, 0);
            if (size) s.read(std::as_writable_bytes(std::span{addr}));
            if (net == IPV6) {
                if (has_prefix(kInternalInIPv6Prefix)) {
                    net = INTERNAL;
                    addr.erase(addr.begin(), addr.begin() + kInternalInIPv6Prefix.size());
                } else if (has_prefix(kIPv4InIPv6Prefix) || has_prefix(kTorV2InIPv6Prefix)) {
                    invalid = true;
                }
            }
        } else {
            std::vector<uint8_t> skip(size);
            if (size) s.read(std::as_writable_bytes(std::span{skip}));
            invalid = true;
        }
        if (invalid) {
            net = IPV6;
            addr.assign(16, 0);
        }
        uint8_t pb[2];
        s.read(std::as_writable_bytes(std::span{pb}));
        port = static_cast<uint16_t>((uint16_t(pb[0]) << 8) | pb[1]);
    }

    /// CNetAddr::ToStringAddr (see adaptation 2 for Tor and I2P).
    std::string ToStringAddr() const
    {
        char buf[64];
        switch (net) {
        case IPV4:
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
            return buf;
        case IPV6:
        case CJDNS:
            return ipv6_to_string();
        case ONION: return "onion:" + hex();
        case I2P:   return "i2p:" + hex();
        case INTERNAL: return "internal:" + hex();
        }
        return {};
    }

    /// CService::ToStringAddrPort.
    std::string ToStringAddrPort() const
    {
        const std::string p = std::to_string(port);
        if (IsIPv4() || IsTor() || IsI2P() || IsInternal()) return ToStringAddr() + ":" + p;
        return "[" + ToStringAddr() + "]:" + p;
    }

private:
    static void expect_size(uint64_t size, uint64_t want)
    {
        if (size != want) throw std::ios_base::failure("BIP155 address with the wrong length");
    }

    template <typename Stream>
    static void write_u8(Stream& s, uint8_t v)
    {
        s.write(std::as_bytes(std::span{&v, 1}));
    }

    std::string hex() const
    {
        static constexpr char d[] = "0123456789abcdef";
        std::string out;
        for (uint8_t b : addr) { out += d[b >> 4]; out += d[b & 15]; }
        return out;
    }

    // RFC 5952, as Core's IPv6ToString (longest run of >= 2 zero groups, first wins).
    std::string ipv6_to_string() const
    {
        uint16_t g[8];
        for (int i = 0; i < 8; ++i) g[i] = static_cast<uint16_t>((addr[2 * i] << 8) | addr[2 * i + 1]);
        size_t best_start = 0, best_len = 0, cur_start = 0, cur_len = 0;
        for (size_t i = 0; i < 8; ++i) {
            if (g[i] != 0) { cur_start = i + 1; cur_len = 0; continue; }
            if (++cur_len > best_len) { best_len = cur_len; best_start = cur_start; }
        }
        std::string r;
        char buf[8];
        for (size_t i = 0; i < 8; ++i) {
            if (best_len >= 2 && i >= best_start && i < best_start + best_len) {
                if (i == best_start) r += "::";
                continue;
            }
            std::snprintf(buf, sizeof(buf), "%s%x", (!r.empty() && r.back() != ':') ? ":" : "", g[i]);
            r += buf;
        }
        return r;
    }
};

/// Does the 16-byte address of a legacy CService survive Dash Core's reading
/// of it (CNetAddr::SetLegacyIPv6 + CNetAddr::IsValid, identical in v23.1.7
/// and v24.0.0)? Core turns a service whose address is not valid into an
/// EMPTY MnNetInfo (MnNetInfo::Unserialize), whatever its port.
inline bool legacy_service_address_valid(const std::array<uint8_t, NETADDR_SIZE>& ip)
{
    LegacyNetService l;
    l.ip = ip;
    return NetService::from_legacy(l).IsValid();
}

inline bool LegacyNetService::IsEmpty() const { return !legacy_service_address_valid(ip); }

inline LegacyNetService LegacyNetService::canonical() const
{
    return IsEmpty() ? LegacyNetService{} : *this;
}

// ── DomainPort (netinfo.h) ─────────────────────────────────────────────────
struct DomainPort
{
    enum class Status : uint8_t {
        BadChar, BadCharPos, BadDotless, BadLabelCharPos, BadLabelLen, BadLen, BadPort, Malformed,
        Success
    };

    std::string addr;
    uint16_t    port{0};

    bool operator==(const DomainPort&) const = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, addr.size());
        if (!addr.empty()) s.write(std::as_bytes(std::span{addr}));
        const uint8_t pb[2] = {static_cast<uint8_t>(port >> 8), static_cast<uint8_t>(port & 0xff)};
        s.write(std::as_bytes(std::span{pb}));
    }

    /// LIMITED_STRING(m_addr, DOMAIN_MAX_LEN) + BigEndianFormatter<2>.
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint64_t size = ReadCompactSize(s);
        if (size > DOMAIN_MAX_LEN) throw std::ios_base::failure("String length limit exceeded");
        addr.assign(size, '\0');
        if (size) s.read(std::as_writable_bytes(std::span{addr.data(), addr.size()}));
        uint8_t pb[2];
        s.read(std::as_writable_bytes(std::span{pb}));
        port = static_cast<uint16_t>((uint16_t(pb[0]) << 8) | pb[1]);
    }

    static std::string to_lower(std::string_view in)
    {
        std::string out(in);
        for (auto& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        return out;
    }

    static std::vector<std::string> split(const std::string& s, char sep)
    {
        std::vector<std::string> out{std::string{}};
        for (char c : s) {
            if (c == sep) out.emplace_back();
            else out.back() += c;
        }
        return out;
    }

    static bool chars_in(std::string_view in, std::string_view filter)
    {
        return std::all_of(in.begin(), in.end(), [&](char c) { return filter.find(c) != std::string_view::npos; });
    }

    /// DomainPort::ValidateDomain.
    static Status validate_domain(const std::string& a)
    {
        static constexpr std::string_view kRFC1035 =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-";
        if (a.length() > DOMAIN_MAX_LEN || a.length() < 3) return Status::BadLen;
        if (!chars_in(a, kRFC1035)) return Status::BadChar;
        if (a.front() == '.' || a.back() == '.') return Status::BadCharPos;
        const auto labels = split(a, '.');
        if (labels.size() < 2) return Status::BadDotless;
        for (const auto& l : labels) {
            if (l.empty() || l.length() > 63) return Status::BadLabelLen;
            if (l.front() == '-' || l.back() == '-') return Status::BadLabelCharPos;
        }
        return Status::Success;
    }

    /// DomainPort::Validate.
    Status Validate() const
    {
        if (addr.empty() || addr != to_lower(addr)) return Status::Malformed;
        if (port == 0) return Status::BadPort;
        return validate_domain(addr);
    }
    bool IsValid() const { return Validate() == Status::Success; }

    std::string ToStringAddrPort() const { return addr + ":" + std::to_string(port); }
};

// ── NetInfoEntry (netinfo.h) ───────────────────────────────────────────────
struct NetInfoEntry
{
    static constexpr uint8_t TYPE_SERVICE = 0x01;
    static constexpr uint8_t TYPE_DOMAIN  = 0x02;
    static constexpr uint8_t TYPE_INVALID = 0xff;

    uint8_t type{TYPE_INVALID};
    std::variant<std::monostate, NetService, DomainPort> data{std::monostate{}};

    NetInfoEntry() = default;
    explicit NetInfoEntry(const NetService& s)
    {
        if (!s.IsValid()) return;
        type = TYPE_SERVICE;
        data = s;
    }
    explicit NetInfoEntry(const DomainPort& d)
    {
        if (!d.IsValid()) return;
        type = TYPE_DOMAIN;
        data = d;
    }

    bool operator==(const NetInfoEntry&) const = default;

    void Clear()
    {
        type = TYPE_INVALID;
        data = std::monostate{};
    }

    const NetService* service() const
    {
        const auto* p = std::get_if<NetService>(&data);
        return (type == TYPE_SERVICE && p) ? p : nullptr;
    }
    const DomainPort* domain() const
    {
        const auto* p = std::get_if<DomainPort>(&data);
        return (type == TYPE_DOMAIN && p) ? p : nullptr;
    }

    uint16_t GetPort() const
    {
        if (const auto* p = std::get_if<NetService>(&data)) return p->port;
        if (const auto* p = std::get_if<DomainPort>(&data)) return p->port;
        return 0;
    }

    bool IsTriviallyValid() const
    {
        if (type == TYPE_INVALID) return false;
        if (const auto* p = std::get_if<NetService>(&data)) return type == TYPE_SERVICE && p->IsValid();
        if (const auto* p = std::get_if<DomainPort>(&data)) return type == TYPE_DOMAIN && p->IsValid();
        return false;
    }

    std::string ToStringAddr() const
    {
        if (const auto* p = std::get_if<NetService>(&data)) return p->ToStringAddr();
        if (const auto* p = std::get_if<DomainPort>(&data)) return p->addr;
        return "[invalid entry]";
    }
    std::string ToStringAddrPort() const
    {
        if (const auto* p = std::get_if<NetService>(&data)) return p->ToStringAddrPort();
        if (const auto* p = std::get_if<DomainPort>(&data)) return p->ToStringAddrPort();
        return "[invalid entry]";
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (const auto* p = service(); p && p->IsValid()) {
            write_type(s, TYPE_SERVICE);
            s << *p;
        } else if (const auto* p = domain(); p && p->IsValid()) {
            write_type(s, TYPE_DOMAIN);
            s << *p;
        } else {
            write_type(s, TYPE_INVALID);
        }
    }

    /// Core keeps reading after a malformed service (the entry is marked
    /// invalid) but propagates a domain failure; an unknown type code
    /// consumes only its own byte.
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> type;
        if (type == TYPE_SERVICE) {
            try {
                NetService svc;
                s >> svc;
                data = svc;
                if (!svc.IsValid()) Clear();
            } catch (const std::ios_base::failure&) {
                Clear();
            }
        } else if (type == TYPE_DOMAIN) {
            DomainPort d;
            s >> d;
            data = d;
            if (!d.IsValid()) Clear();
        } else {
            Clear();
        }
    }

private:
    template <typename Stream>
    static void write_type(Stream& s, uint8_t t)
    {
        s.write(std::as_bytes(std::span{&t, 1}));
    }
};

// ── ExtNetInfo (netinfo.h) ─────────────────────────────────────────────────
struct ExtNetInfo
{
    static constexpr uint8_t CURRENT_VERSION = 1;

    uint8_t version{CURRENT_VERSION};
    /// Purpose -> entries, ascending by purpose (Core: std::map).
    std::vector<std::pair<uint8_t, std::vector<NetInfoEntry>>> purposes;

    bool operator==(const ExtNetInfo&) const = default;

    bool IsEmpty() const { return version == CURRENT_VERSION && purposes.empty(); }

    const std::vector<NetInfoEntry>* find(uint8_t purpose) const
    {
        for (const auto& [p, e] : purposes)
            if (p == purpose) return &e;
        return nullptr;
    }

    bool HasEntries(uint8_t purpose) const
    {
        if (!NetInfoPurpose::is_valid(purpose)) return false;
        const auto* e = find(purpose);
        return e && !e->empty();
    }

    std::vector<NetInfoEntry> GetEntries(uint8_t purpose) const
    {
        const auto* e = find(purpose);
        return e ? *e : std::vector<NetInfoEntry>{};
    }

    std::vector<NetInfoEntry> GetAllEntries() const
    {
        std::vector<NetInfoEntry> out;
        for (const auto& [p, e] : purposes) out.insert(out.end(), e.begin(), e.end());
        return out;
    }

    /// First CORE_P2P entry's service, else an invalid default service.
    NetService GetPrimary() const
    {
        if (const auto* e = find(NetInfoPurpose::CORE_P2P); e && !e->empty())
            if (const auto* svc = (*e)[0].service()) return *svc;
        return NetService{};
    }

    /// Adds `entries` under `purpose` (keeps the ascending order).
    void set(uint8_t purpose, std::vector<NetInfoEntry> entries)
    {
        for (auto& [p, e] : purposes)
            if (p == purpose) { e = std::move(entries); return; }
        purposes.emplace_back(purpose, std::move(entries));
        std::sort(purposes.begin(), purposes.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(std::as_bytes(std::span{&version, 1}));
        if (version == 0 || version > CURRENT_VERSION) return;   // unknown version: nothing else
        WriteCompactSize(s, purposes.size());
        for (const auto& [p, e] : purposes) {
            s.write(std::as_bytes(std::span{&p, 1}));
            s << e;
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> version;
        purposes.clear();
        if (version == 0 || version > CURRENT_VERSION) return;   // Core: "don't bother"
        const uint64_t n = ReadCompactSize(s);
        for (uint64_t i = 0; i < n; ++i) {
            uint8_t p{0};
            s >> p;
            if (!NetInfoPurpose::is_valid(p) || (!purposes.empty() && p <= purposes.back().first))
                throw std::ios_base::failure("ExtNetInfo: purpose unknown or out of order");
            purposes.emplace_back(p, std::vector<NetInfoEntry>{});
            s >> purposes.back().second;
        }
    }

    /// purpose=addr:port,...;... in purpose order (the shape of Core's
    /// ProTx JSON `addresses`).
    std::string to_string() const
    {
        static constexpr const char* kNames[] = {"core_p2p", "platform_p2p", "platform_https"};
        std::string out;
        for (const auto& [p, e] : purposes) {
            if (!out.empty()) out += ';';
            out += NetInfoPurpose::is_valid(p) ? kNames[p] : "?";
            out += '=';
            for (size_t i = 0; i < e.size(); ++i) {
                if (i) out += ',';
                out += e[i].ToStringAddrPort();
            }
        }
        return out;
    }
};

// ── Validation (netinfo.cpp) ───────────────────────────────────────────────
namespace netinfo_detail {

template <size_t N>
inline bool match_suffix(const std::string& s, const std::array<std::string_view, N>& list)
{
    if (s.empty()) return false;
    for (auto suffix : list)
        if (suffix.size() <= s.size() && std::string_view{s}.ends_with(suffix)) return true;
    return false;
}

inline constexpr std::array<std::string_view, 13> kTldsBad = {
    ".mail", ".arpa", ".example", ".invalid", ".localhost", ".test", ".local",
    ".corp", ".home", ".internal", ".intranet", ".lan", ".private"};
inline constexpr std::array<std::string_view, 2> kTldsPrivacy = {".i2p", ".onion"};

inline uint16_t main_primary_port(uint8_t purpose)
{
    switch (purpose) {
    case NetInfoPurpose::CORE_P2P:       return NetInfoRules::kMainCoreP2PPort;
    case NetInfoPurpose::PLATFORM_P2P:   return NetInfoRules::kMainPlatformP2PPort;
    case NetInfoPurpose::PLATFORM_HTTPS: return NetInfoRules::kMainPlatformHTTPSPort;
    }
    return 0;
}

/// ValidateMainnetPrimaryPort.
inline NetInfoStatus validate_mainnet_primary_port(uint8_t purpose, const NetInfoEntry& primary,
                                                   const NetInfoRules& rules)
{
    if (!rules.is_mainnet || primary.GetPort() == main_primary_port(purpose)) return NetInfoStatus::Success;
    return NetInfoStatus::BadPort;
}

/// ExtNetInfo::ValidateService.
inline NetInfoStatus validate_ext_service(uint8_t purpose, const NetService& svc, const NetInfoRules& rules)
{
    if (!svc.IsValid()) return NetInfoStatus::BadAddress;
    if (!svc.IsCJDNS() && !svc.IsI2P() && !svc.IsIPv4() && !svc.IsIPv6() && !svc.IsTor())
        return NetInfoStatus::BadType;
    if (rules.require_routable_external_ip && (svc.IsRFC1918() || !svc.IsRoutable()))
        return NetInfoStatus::NotRoutable;
    if (svc.IsI2P()) {
        if (svc.port != 0) return NetInfoStatus::BadPort;   // I2P_SAM31_PORT
    } else {
        const bool https_443 = purpose == NetInfoPurpose::PLATFORM_HTTPS && svc.port == 443;
        if (svc.port == 0 || (is_bad_port(svc.port) && !https_443)) return NetInfoStatus::BadPort;
    }
    return NetInfoStatus::Success;
}

/// ExtNetInfo::ValidateDomainPort.
inline NetInfoStatus validate_domain_port(const DomainPort& d)
{
    if (!d.IsValid()) return NetInfoStatus::BadInput;
    if (d.port == 0 || (is_bad_port(d.port) && d.port != 443)) return NetInfoStatus::BadPort;
    if (match_suffix(d.addr, kTldsBad) || match_suffix(d.addr, kTldsPrivacy)) return NetInfoStatus::BadInput;
    const auto labels = DomainPort::split(d.addr, '.');
    if (!DomainPort::chars_in(labels.back(), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        return NetInfoStatus::BadInput;
    return NetInfoStatus::Success;
}

} // namespace netinfo_detail

/// ExtNetInfo::Validate.
inline NetInfoStatus validate_ext_netinfo(const ExtNetInfo& ni, const NetInfoRules& rules)
{
    using namespace netinfo_detail;
    if (ni.version == 0 || ni.version > ExtNetInfo::CURRENT_VERSION || ni.purposes.empty())
        return NetInfoStatus::Malformed;
    {   // HasAddrPortDuplicates: equal type and equal service/domain, across all purposes
        const auto all = ni.GetAllEntries();
        for (size_t i = 0; i < all.size(); ++i)
            for (size_t j = i + 1; j < all.size(); ++j)
                if (all[i] == all[j]) return NetInfoStatus::Duplicate;
    }
    for (const auto& [purpose, entries] : ni.purposes) {
        if (entries.empty()) return NetInfoStatus::Malformed;
        if (entries.size() > MAX_ENTRIES_EXTNETINFO) return NetInfoStatus::MaxLimit;
        for (size_t i = 0; i < entries.size(); ++i)          // HasAddrDuplicates (by address string)
            for (size_t j = i + 1; j < entries.size(); ++j)
                if (entries[i].ToStringAddr() == entries[j].ToStringAddr()) return NetInfoStatus::Duplicate;
        for (const auto& e : entries) {
            NetInfoStatus ret{NetInfoStatus::Malformed};
            if (const auto* svc = e.service()) {
                ret = validate_ext_service(purpose, *svc, rules);
            } else if (const auto* d = e.domain()) {
                if (purpose != NetInfoPurpose::PLATFORM_HTTPS) return NetInfoStatus::BadInput;
                ret = validate_domain_port(*d);
            }
            if (ret != NetInfoStatus::Success) return ret;
        }
    }
    for (const auto& [purpose, entries] : ni.purposes)
        if (auto ret = validate_mainnet_primary_port(purpose, entries.front(), rules);
            ret != NetInfoStatus::Success)
            return ret;
    return NetInfoStatus::Success;
}

/// MnNetInfo::Validate over the legacy 18-byte service (versions 1 and 2).
inline NetInfoStatus validate_mn_netinfo(const LegacyNetService& l, const NetInfoRules& rules)
{
    const NetService svc = NetService::from_legacy(l);
    if (!svc.IsValid()) return NetInfoStatus::Malformed;   // the entry did not survive reading
    if (!svc.IsIPv4()) return NetInfoStatus::BadType;
    if (rules.require_routable_external_ip && (svc.IsRFC1918() || !svc.IsRoutable()))
        return NetInfoStatus::NotRoutable;
    if (rules.is_mainnet != (svc.port == NetInfoRules::kMainCoreP2PPort)) return NetInfoStatus::BadPort;
    return NetInfoStatus::Success;
}

/// CheckNetInfo: the reject reason for a failed Validate().
inline std::optional<std::string> netinfo_status_refusal(NetInfoStatus st)
{
    switch (st) {
    case NetInfoStatus::BadAddress:  return "bad-protx-netinfo-addr";
    case NetInfoStatus::BadPort:     return "bad-protx-netinfo-port";
    case NetInfoStatus::BadType:     return "bad-protx-netinfo-addr-type";
    case NetInfoStatus::NotRoutable: return "bad-protx-netinfo-addr-unroutable";
    case NetInfoStatus::Malformed:   return "bad-protx-netinfo-bad";
    case NetInfoStatus::BadInput:    return "bad-protx-netinfo-entry";
    case NetInfoStatus::Duplicate:   return "bad-protx-dup-netinfo-entry";
    case NetInfoStatus::MaxLimit:    return "bad-protx-netinfo-maxlimit";
    case NetInfoStatus::Success:     return std::nullopt;
    }
    return "bad-protx-netinfo-bad";
}

/// A ProTx payload's netInfo, whichever form its version carries.
struct NetInfoRef
{
    const LegacyNetService* legacy{nullptr};   ///< versions 1/2 (MnNetInfo)
    const ExtNetInfo*       ext{nullptr};      ///< version 3 (ExtNetInfo)

    bool CanStorePlatform() const { return ext != nullptr; }

    bool IsEmpty() const
    {
        if (ext) return ext->IsEmpty();
        return !legacy || !NetService::from_legacy(*legacy).IsValid();
    }

    bool HasEntries(uint8_t purpose) const
    {
        if (ext) return ext->HasEntries(purpose);
        return purpose == NetInfoPurpose::CORE_P2P && !IsEmpty();
    }

    NetService GetPrimary() const
    {
        if (ext) return ext->GetPrimary();
        if (legacy) {
            NetService s = NetService::from_legacy(*legacy);
            if (s.IsValid()) return s;
        }
        return NetService{};
    }

    std::vector<NetInfoEntry> GetEntries(uint8_t purpose) const
    {
        if (ext) return ext->GetEntries(purpose);
        if (purpose == NetInfoPurpose::CORE_P2P && !IsEmpty())
            return {NetInfoEntry{NetService::from_legacy(*legacy)}};
        return {};
    }

    NetInfoStatus Validate(const NetInfoRules& rules) const
    {
        if (ext) return validate_ext_netinfo(*ext, rules);
        if (!legacy) return NetInfoStatus::Malformed;
        return validate_mn_netinfo(*legacy, rules);
    }
};

/// IsNetInfoTriviallyValid (providertx.cpp): mandatory purposes per MN type.
inline std::optional<std::string> netinfo_trivial_refusal(const NetInfoRef& ni, uint16_t mn_type)
{
    if (!ni.HasEntries(NetInfoPurpose::CORE_P2P)) return "bad-protx-netinfo-empty";
    if (mn_type == 0 /* Regular */) {
        if (ni.HasEntries(NetInfoPurpose::PLATFORM_HTTPS) || ni.HasEntries(NetInfoPurpose::PLATFORM_P2P))
            return "bad-protx-netinfo-bad";
    }
    if (ni.CanStorePlatform() && mn_type == 1 /* Evo */) {
        if (!ni.HasEntries(NetInfoPurpose::PLATFORM_HTTPS) || !ni.HasEntries(NetInfoPurpose::PLATFORM_P2P))
            return "bad-protx-netinfo-empty";
    }
    return std::nullopt;
}

/// CheckIPv4Primaries: the first Core P2P entry is IPv4, and the first
/// Platform entries are IPv4 on that same address.
inline std::optional<std::string> ipv4_primaries_refusal(const NetInfoRef& ni)
{
    const NetService core = ni.GetPrimary();
    if (!core.IsIPv4()) return "bad-protx-netinfo-addr-type";
    for (uint8_t purpose : {NetInfoPurpose::PLATFORM_P2P, NetInfoPurpose::PLATFORM_HTTPS}) {
        const auto entries = ni.GetEntries(purpose);
        if (entries.empty()) continue;
        const auto* svc = entries.front().service();
        if (!svc || !svc->IsIPv4()) return "bad-protx-netinfo-addr-type";
        if (svc->addr != core.addr) return "bad-protx-netinfo-addr";
    }
    return std::nullopt;
}

/// CheckProviderNetworkFields (providertx.cpp). `version` is the payload's
/// ProTx version, `ipv4_optional` is DEPLOYMENT_IPV4_OPTIONAL for the block
/// (never on mainnet, from genesis on testnet and devnet).
inline std::optional<std::string>
check_provider_network_fields(const NetInfoRef& ni, uint16_t mn_type, uint16_t version,
                              const uint160* platform_node_id, uint16_t platform_p2p_port,
                              uint16_t platform_http_port, bool allow_empty, bool ipv4_optional,
                              const NetInfoRules& rules)
{
    if ((!ni.legacy && !ni.ext) || ni.CanStorePlatform() != (version >= 3))
        return "bad-protx-netinfo-version";
    if (ni.IsEmpty()) {
        if (!allow_empty) return "bad-protx-netinfo-empty";
    } else {
        if (auto why = netinfo_trivial_refusal(ni, mn_type)) return why;
        if (auto why = netinfo_status_refusal(ni.Validate(rules))) return why;
        if (!ipv4_optional)
            if (auto why = ipv4_primaries_refusal(ni)) return why;
    }

    if (mn_type != 1 /* Evo */) return std::nullopt;
    if (platform_node_id && platform_node_id->IsNull()) return "bad-protx-platform-nodeid";
    if (version >= 3) {
        if (platform_p2p_port != 0) return "bad-protx-platform-p2p-port";
        if (platform_http_port != 0) return "bad-protx-platform-http-port";
        return std::nullopt;
    }
    if (rules.is_mainnet) {
        if (platform_p2p_port != NetInfoRules::kMainPlatformP2PPort) return "bad-protx-platform-p2p-port";
        if (platform_http_port != NetInfoRules::kMainPlatformHTTPSPort) return "bad-protx-platform-http-port";
    }
    if (platform_p2p_port == NetInfoRules::kMainCoreP2PPort) return "bad-protx-platform-p2p-port";
    if (platform_http_port == NetInfoRules::kMainCoreP2PPort) return "bad-protx-platform-http-port";
    const uint16_t core_port = ni.GetPrimary().port;
    if (platform_p2p_port == platform_http_port || platform_p2p_port == core_port
        || platform_http_port == core_port)
        return "bad-protx-platform-dup-ports";
    return std::nullopt;
}

/// SetStateVersion's MnNetInfo -> ExtNetInfo conversion (specialtxman.cpp):
/// the CORE_P2P entry is re-added through ExtNetInfo::AddEntry, so it must
/// pass the ExtNetInfo service rules (and, on mainnet, the primary-port
/// rule). An empty MnNetInfo converts to an empty ExtNetInfo. nullopt is
/// Core's "bad-protx-netinfo-version" (an EvoNode carrying platform ports
/// cannot be raised this way: Core requires a ProUpServTx that spells its
/// Platform entries out; the caller checks that case).
inline std::optional<ExtNetInfo> ext_netinfo_from_legacy(const LegacyNetService& l, const NetInfoRules& rules)
{
    ExtNetInfo out;
    const NetService svc = NetService::from_legacy(l);
    if (!svc.IsValid()) return out;                        // MnNetInfo empty: no entries to carry
    if (svc.IsIPv6() && svc.addr[0] == 0xFC) return std::nullopt;   // adaptation 3
    if (netinfo_detail::validate_ext_service(NetInfoPurpose::CORE_P2P, svc, rules) != NetInfoStatus::Success)
        return std::nullopt;
    const NetInfoEntry e{svc};
    if (netinfo_detail::validate_mainnet_primary_port(NetInfoPurpose::CORE_P2P, e, rules) != NetInfoStatus::Success)
        return std::nullopt;
    out.set(NetInfoPurpose::CORE_P2P, {e});
    return out;
}

} // namespace vendor
} // namespace coin
} // namespace dash
