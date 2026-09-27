// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Miner-offline alert relay over the sharechain p2p mesh (D-MINER.7) --
// CRYPTO + WIRE-SHAPE + PER-PEER / NODE-LEVEL POLICY STATE (pure, header-only,
// KAT-able, no sockets).
//
// WHY THIS EXISTS: a c2pool node behind an ISP DPI box (TSPU-class per-flow
// latch after ~13-16 KB of unclassified outbound payload) cannot reach
// api.telegram.org, but it DOES keep an established sharechain peer socket to
// our public nodes. A miner-offline alert is a few hundred bytes, so it rides
// that socket as a NON-CONSENSUS pool-protocol message (`alert`) to a node
// with clean connectivity, which hands it to a Telegram sidecar and answers
// with a signed `alertack`.
//
// CONSENSUS / MONEY SAFETY: nothing here touches shares, share hashes, the
// sharechain, block templates, coinbase, PPLNS or payouts. Two additive
// pool-protocol commands only; with every --alert-relay-* flag OFF no alert is
// ever sent and inbound alert/alertack frames are ignored (never a disconnect),
// exactly like tx_inject with its sink unset.
//
// SECURITY MODEL
//   * Every alert is ECDSA-signed (RFC6979 nonces via libsecp256k1) by the
//     origin node's own alert key; the relay only delivers alerts from an
//     operator-configured allowlist of origin pubkeys.
//   * The body (label / worker / detail) is sealed for ONE relay with a static
//     ECDH secret: shared = SHA256(compressed(relay_pub * origin_sec)); a
//     per-message random 16-byte nonce keys a counter-mode SHA256 stream and an
//     encrypt-then-MAC HMAC-SHA256 tag (the share_messages.hpp primitives with
//     a domain-separation label). Forwarders see ciphertext only.
//   * hops_left is deliberately OUTSIDE the signature (forwarders decrement
//     it); it is range-checked on receive.
//   * Replay: +/- kReplayWindowSec timestamp window, a node-level seen set,
//     and the relay persists the ids it accepted so a restart cannot page
//     twice for the same frame.
//   * Acks are signed by the relay key; an origin only accepts an ack from the
//     relay it addressed, so an intermediate cannot silence retransmits.
//
// Randomness: getrandom(2) (fallback /dev/urandom). NEVER a seeded PRNG.

#include "share_messages.hpp"   // hmac_sha256, generate_stream, ecdsa_sign/verify, hash160, secp ctx

#include <btclibs/crypto/sha256.h>
#include <secp256k1.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace dash::alert {

using Bytes = std::vector<unsigned char>;

// ── Wire constants ──────────────────────────────────────────────────────────
constexpr uint32_t    kWireVersion     = 1;
constexpr uint8_t     kDefaultHops     = 2;    // origin -> fwd -> fwd -> relay
constexpr uint8_t     kMaxHops         = 4;    // anything larger is malformed
constexpr std::size_t kPubkeyLen       = 33;   // compressed secp256k1
constexpr std::size_t kKeyIdLen        = 8;    // first 8 bytes of hash160(relay pubkey)
constexpr std::size_t kSealOverhead    = 1 + 16 + 32;   // [ver][nonce16][mac32]
constexpr std::size_t kMaxBodyBytes    = 400;  // sealed body cap (plaintext <= ~235)
constexpr std::size_t kMinSigBytes     = 8;
constexpr std::size_t kMaxSigBytes     = 72;   // DER
constexpr int64_t     kReplayWindowSec = 900;  // +/- 15 min
constexpr std::size_t kMaxLabel        = 32;
constexpr std::size_t kMaxWorker       = 64;
constexpr std::size_t kMaxDetail       = 128;
constexpr unsigned char kSealVersion   = 0x01;

enum class Kind : uint8_t { Offline = 1, BackOnline = 2, Digest = 3, Test = 4 };

inline const char* kind_name(uint8_t k)
{
    switch (k) {
    case 1: return "offline";
    case 2: return "back_online";
    case 3: return "digest";
    case 4: return "test";
    }
    return "unknown";
}

enum class AckStatus : uint8_t {
    Delivered         = 1,   // the relay's sidecar reported Telegram ok:true
    RefusedNotAllowed = 2,   // origin pubkey not on the relay allowlist
    RefusedInvalid    = 3,   // stale timestamp / undecryptable body
    Queued            = 4,   // accepted into the relay outbox, sidecar not done yet
};

inline const char* ack_status_name(uint8_t s)
{
    switch (s) {
    case 1: return "delivered";
    case 2: return "refused_not_allowlisted";
    case 3: return "refused_invalid";
    case 4: return "queued_at_relay";
    }
    return "unknown";
}

// Plain mirrors of the two wire messages (messages.hpp). The policy layer works
// on these so it needs no message/sharechain include; alert_wire.hpp converts.
struct AlertFrame {
    uint32_t version{kWireVersion};
    uint8_t  hops_left{kDefaultHops};
    uint32_t timestamp{0};
    uint64_t nonce{0};
    Bytes    origin_pubkey;   // 33
    Bytes    to_key_id;       // 8
    Bytes    body;            // sealed
    Bytes    signature;       // DER

    bool operator==(const AlertFrame&) const = default;
};

struct AckFrame {
    uint32_t version{kWireVersion};
    Bytes    origin_pubkey;   // 33 -- which origin's alert this acks
    uint64_t nonce{0};
    uint8_t  status{0};
    Bytes    relay_pubkey;    // 33 -- the signer
    Bytes    signature;       // DER

    bool operator==(const AckFrame&) const = default;
};

// ── Hex helpers ─────────────────────────────────────────────────────────────
inline std::string to_hex(const unsigned char* p, std::size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xf]);
    }
    return s;
}
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }

inline std::optional<Bytes> from_hex(const std::string& in)
{
    std::string s;
    for (char c : in)
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') s.push_back(c);
    if (s.size() % 2) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

// ── Randomness (OS CSPRNG only) ─────────────────────────────────────────────
inline bool fill_random(unsigned char* out, std::size_t n)
{
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::getrandom(out + got, n - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        got += static_cast<std::size_t>(r);
    }
    if (got == n) return true;
    // Fallback: /dev/urandom (getrandom unavailable, e.g. very old kernel).
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    while (got < n) {
        ssize_t r = ::read(fd, out + got, n - got);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        got += static_cast<std::size_t>(r);
    }
    ::close(fd);
    return true;
}

// ── Keys ────────────────────────────────────────────────────────────────────
struct KeyPair {
    std::array<unsigned char, 32> seckey{};
    Bytes pubkey;   // 33, compressed

    // Wipe the secret on destruction (best effort).
    ~KeyPair() { volatile unsigned char* p = seckey.data(); for (std::size_t i = 0; i < 32; ++i) p[i] = 0; }

    static std::optional<KeyPair> from_seckey(const unsigned char* sec32)
    {
        const auto* ctx = dash::get_secp256k1_context();
        if (!secp256k1_ec_seckey_verify(ctx, sec32)) return std::nullopt;
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, sec32)) return std::nullopt;
        KeyPair kp;
        std::memcpy(kp.seckey.data(), sec32, 32);
        kp.pubkey.resize(kPubkeyLen);
        std::size_t len = kPubkeyLen;
        secp256k1_ec_pubkey_serialize(ctx, kp.pubkey.data(), &len, &pk, SECP256K1_EC_COMPRESSED);
        return kp;
    }

    static std::optional<KeyPair> generate()
    {
        for (int tries = 0; tries < 16; ++tries) {
            std::array<unsigned char, 32> sec{};
            if (!fill_random(sec.data(), sec.size())) return std::nullopt;
            auto kp = from_seckey(sec.data());
            volatile unsigned char* p = sec.data();
            for (std::size_t i = 0; i < 32; ++i) p[i] = 0;
            if (kp) return kp;
        }
        return std::nullopt;
    }
};

inline bool is_valid_pubkey(const Bytes& pub)
{
    if (pub.size() != kPubkeyLen || (pub[0] != 0x02 && pub[0] != 0x03)) return false;
    secp256k1_pubkey pk;
    return secp256k1_ec_pubkey_parse(dash::get_secp256k1_context(), &pk, pub.data(), pub.size()) == 1;
}

// First 8 bytes of hash160(pubkey): names the relay an alert is sealed for.
inline Bytes key_id(const Bytes& pubkey)
{
    auto h = dash::hash160(pubkey.data(), pubkey.size());
    return Bytes(h.begin(), h.begin() + kKeyIdLen);
}

// Load a 32-byte hex secret from PATH, or create one (0600, O_EXCL) when the
// file does not exist. `created` reports which. `warning` is set (non-fatal)
// when an existing file is group/other accessible. The secret is never logged.
inline std::optional<KeyPair> load_or_create_key_file(const std::string& path,
                                                      bool& created,
                                                      std::string& err,
                                                      std::string& warning)
{
    created = false;
    struct stat st{};
    if (::stat(path.c_str(), &st) == 0) {
        if ((st.st_mode & 077) != 0)
            warning = "alert key file " + path + " is group/other accessible (chmod 600 it)";
        std::ifstream f(path);
        if (!f) { err = "cannot read alert key file " + path; return std::nullopt; }
        std::string line;
        std::getline(f, line);
        auto raw = from_hex(line);
        if (!raw || raw->size() != 32) { err = "alert key file " + path + " must hold 64 hex chars (32-byte secp256k1 secret)"; return std::nullopt; }
        auto kp = KeyPair::from_seckey(raw->data());
        std::fill(raw->begin(), raw->end(), 0);
        if (!kp) { err = "alert key file " + path + " holds an invalid secp256k1 secret"; return std::nullopt; }
        return kp;
    }
    auto kp = KeyPair::generate();
    if (!kp) { err = "OS randomness unavailable; cannot generate an alert key"; return std::nullopt; }
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { err = "cannot create alert key file " + path + ": " + std::strerror(errno); return std::nullopt; }
    std::string hex = to_hex(kp->seckey.data(), 32) + "\n";
    bool ok = ::write(fd, hex.data(), hex.size()) == static_cast<ssize_t>(hex.size());
    ok = (::fsync(fd) == 0) && ok;
    ::close(fd);
    std::fill(hex.begin(), hex.end(), '0');
    if (!ok) { err = "short write creating alert key file " + path; return std::nullopt; }
    created = true;
    return kp;
}

// ── ECDH + body seal/open ───────────────────────────────────────────────────
// shared = SHA256(compressed(peer_pub * my_sec)); symmetric in (a, B) / (b, A).
inline std::optional<std::array<unsigned char, 32>> ecdh_shared(const unsigned char* my_sec32,
                                                                const Bytes& peer_pub)
{
    const auto* ctx = dash::get_secp256k1_context();
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(ctx, &pk, peer_pub.data(), peer_pub.size())) return std::nullopt;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, my_sec32)) return std::nullopt;
    unsigned char ser[33];
    std::size_t len = sizeof(ser);
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &pk, SECP256K1_EC_COMPRESSED);
    std::array<unsigned char, 32> out{};
    CSHA256().Write(ser, len).Finalize(out.data());
    return out;
}

inline std::array<unsigned char, 32> derive_enc_key(const std::array<unsigned char, 32>& shared,
                                                    const unsigned char* nonce16)
{
    static const char kLabel[] = "c2pool-alert-v1/body";
    unsigned char data[sizeof(kLabel) - 1 + 16];
    std::memcpy(data, kLabel, sizeof(kLabel) - 1);
    std::memcpy(data + sizeof(kLabel) - 1, nonce16, 16);
    return dash::hmac_sha256(shared.data(), shared.size(), data, sizeof(data));
}

// Sealed layout: [0x01][nonce16][mac32][ciphertext]. `nonce16` may be supplied
// for KATs; production passes nullptr and a fresh OS-random nonce is drawn.
inline std::optional<Bytes> seal_body(const std::array<unsigned char, 32>& shared,
                                      const Bytes& plaintext,
                                      const unsigned char* nonce16 = nullptr)
{
    std::array<unsigned char, 16> nonce{};
    if (nonce16) std::memcpy(nonce.data(), nonce16, 16);
    else if (!fill_random(nonce.data(), nonce.size())) return std::nullopt;
    auto enc_key = derive_enc_key(shared, nonce.data());
    Bytes ct(plaintext.size());
    dash::generate_stream(enc_key.data(), ct.data(), ct.size());
    for (std::size_t i = 0; i < ct.size(); ++i) ct[i] ^= plaintext[i];
    auto mac = dash::hmac_sha256(enc_key.data(), enc_key.size(), ct.data(), ct.size());
    Bytes out;
    out.reserve(kSealOverhead + ct.size());
    out.push_back(kSealVersion);
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), mac.begin(), mac.end());
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

inline std::optional<Bytes> open_body(const std::array<unsigned char, 32>& shared, const Bytes& sealed)
{
    if (sealed.size() < kSealOverhead || sealed[0] != kSealVersion) return std::nullopt;
    const unsigned char* nonce = sealed.data() + 1;
    const unsigned char* mac = sealed.data() + 17;
    const unsigned char* ct = sealed.data() + kSealOverhead;
    const std::size_t ct_len = sealed.size() - kSealOverhead;
    auto enc_key = derive_enc_key(shared, nonce);
    auto want = dash::hmac_sha256(enc_key.data(), enc_key.size(), ct, ct_len);
    unsigned char diff = 0;
    for (std::size_t i = 0; i < 32; ++i) diff |= static_cast<unsigned char>(want[i] ^ mac[i]);
    if (diff != 0) return std::nullopt;
    Bytes pt(ct_len);
    dash::generate_stream(enc_key.data(), pt.data(), pt.size());
    for (std::size_t i = 0; i < ct_len; ++i) pt[i] ^= ct[i];
    return pt;
}

// ── Body plaintext ──────────────────────────────────────────────────────────
// [kind:1][event_ts:4 LE][label_len:1][label][worker_len:1][worker][detail_len:1][detail]
struct AlertBody {
    uint8_t     kind{static_cast<uint8_t>(Kind::Offline)};
    uint32_t    event_ts{0};
    std::string label;
    std::string worker;
    std::string detail;

    bool operator==(const AlertBody&) const = default;
};

inline std::string clip(const std::string& s, std::size_t n) { return s.size() > n ? s.substr(0, n) : s; }

inline Bytes encode_body(const AlertBody& b)
{
    const std::string label = clip(b.label, kMaxLabel);
    const std::string worker = clip(b.worker, kMaxWorker);
    const std::string detail = clip(b.detail, kMaxDetail);
    Bytes out;
    out.push_back(b.kind);
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<unsigned char>(b.event_ts >> (8 * i)));
    auto put = [&](const std::string& s) {
        out.push_back(static_cast<unsigned char>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    };
    put(label);
    put(worker);
    put(detail);
    return out;
}

inline std::optional<AlertBody> decode_body(const Bytes& in)
{
    if (in.size() < 8) return std::nullopt;
    AlertBody b;
    std::size_t p = 0;
    b.kind = in[p++];
    if (b.kind < 1 || b.kind > 4) return std::nullopt;
    b.event_ts = 0;
    for (int i = 0; i < 4; ++i) b.event_ts |= static_cast<uint32_t>(in[p++]) << (8 * i);
    auto get = [&](std::string& s, std::size_t cap) -> bool {
        if (p >= in.size()) return false;
        std::size_t n = in[p++];
        if (n > cap || p + n > in.size()) return false;
        s.assign(reinterpret_cast<const char*>(in.data() + p), n);
        p += n;
        return true;
    };
    if (!get(b.label, kMaxLabel) || !get(b.worker, kMaxWorker) || !get(b.detail, kMaxDetail)) return std::nullopt;
    if (p != in.size()) return std::nullopt;
    return b;
}

// ── Signatures ──────────────────────────────────────────────────────────────
inline void put_u32(CSHA256& h, uint32_t v) { unsigned char b[4]; for (int i = 0; i < 4; ++i) b[i] = static_cast<unsigned char>(v >> (8 * i)); h.Write(b, 4); }
inline void put_u64(CSHA256& h, uint64_t v) { unsigned char b[8]; for (int i = 0; i < 8; ++i) b[i] = static_cast<unsigned char>(v >> (8 * i)); h.Write(b, 8); }
inline void put_var(CSHA256& h, const Bytes& v) { put_u32(h, static_cast<uint32_t>(v.size())); h.Write(v.data(), v.size()); }

inline std::array<unsigned char, 32> sha256d_finish(CSHA256& h)
{
    unsigned char first[32];
    h.Finalize(first);
    std::array<unsigned char, 32> out{};
    CSHA256().Write(first, 32).Finalize(out.data());
    return out;
}

// hops_left is NOT covered (forwarders decrement it in flight).
inline std::array<unsigned char, 32> alert_sighash(const AlertFrame& f)
{
    static const char kTag[] = "c2pool-alert-v1";
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
    put_u32(h, f.version);
    put_u32(h, f.timestamp);
    put_u64(h, f.nonce);
    put_var(h, f.origin_pubkey);
    put_var(h, f.to_key_id);
    put_var(h, f.body);
    return sha256d_finish(h);
}

inline std::array<unsigned char, 32> ack_sighash(const AckFrame& a)
{
    static const char kTag[] = "c2pool-alertack-v1";
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(kTag), sizeof(kTag) - 1);
    put_u32(h, a.version);
    put_var(h, a.origin_pubkey);
    put_u64(h, a.nonce);
    unsigned char st = a.status;
    h.Write(&st, 1);
    put_var(h, a.relay_pubkey);
    return sha256d_finish(h);
}

inline bool verify_alert_sig(const AlertFrame& f)
{
    auto h = alert_sighash(f);
    return dash::ecdsa_verify(f.origin_pubkey.data(), f.origin_pubkey.size(), h.data(),
                              f.signature.data(), f.signature.size());
}

inline bool verify_ack_sig(const AckFrame& a)
{
    auto h = ack_sighash(a);
    return dash::ecdsa_verify(a.relay_pubkey.data(), a.relay_pubkey.size(), h.data(),
                              a.signature.data(), a.signature.size());
}

// Build + seal + sign one alert from `origin` for `relay_pub`.
inline std::optional<AlertFrame> build_alert(const KeyPair& origin, const Bytes& relay_pub,
                                             const AlertBody& body, uint32_t ts, uint64_t nonce,
                                             uint8_t hops = kDefaultHops,
                                             const unsigned char* seal_nonce16 = nullptr)
{
    auto shared = ecdh_shared(origin.seckey.data(), relay_pub);
    if (!shared) return std::nullopt;
    auto sealed = seal_body(*shared, encode_body(body), seal_nonce16);
    if (!sealed || sealed->size() > kMaxBodyBytes) return std::nullopt;
    AlertFrame f;
    f.version = kWireVersion;
    f.hops_left = hops;
    f.timestamp = ts;
    f.nonce = nonce;
    f.origin_pubkey = origin.pubkey;
    f.to_key_id = key_id(relay_pub);
    f.body = std::move(*sealed);
    auto h = alert_sighash(f);
    f.signature = dash::ecdsa_sign(h.data(), origin.seckey.data());
    if (f.signature.empty()) return std::nullopt;
    return f;
}

inline std::optional<AckFrame> build_ack(const KeyPair& relay, const Bytes& origin_pub,
                                         uint64_t nonce, AckStatus status)
{
    AckFrame a;
    a.version = kWireVersion;
    a.origin_pubkey = origin_pub;
    a.nonce = nonce;
    a.status = static_cast<uint8_t>(status);
    a.relay_pubkey = relay.pubkey;
    auto h = ack_sighash(a);
    a.signature = dash::ecdsa_sign(h.data(), relay.seckey.data());
    if (a.signature.empty()) return std::nullopt;
    return a;
}

// Decrypt a frame addressed to `relay` (the relay side of ECDH).
inline std::optional<AlertBody> open_alert(const KeyPair& relay, const AlertFrame& f)
{
    auto shared = ecdh_shared(relay.seckey.data(), f.origin_pubkey);
    if (!shared) return std::nullopt;
    auto pt = open_body(*shared, f.body);
    if (!pt) return std::nullopt;
    return decode_body(*pt);
}

// ── Shape checks (cheap, before any crypto) ─────────────────────────────────
inline const char* alert_shape_error(const AlertFrame& f)
{
    if (f.version != kWireVersion) return "unsupported-version";
    if (f.hops_left > kMaxHops) return "hops-out-of-range";
    if (f.origin_pubkey.size() != kPubkeyLen || (f.origin_pubkey[0] != 0x02 && f.origin_pubkey[0] != 0x03))
        return "bad-origin-pubkey";
    if (f.to_key_id.size() != kKeyIdLen) return "bad-key-id";
    if (f.body.size() < kSealOverhead + 8 || f.body.size() > kMaxBodyBytes) return "bad-body-size";
    if (f.signature.size() < kMinSigBytes || f.signature.size() > kMaxSigBytes) return "bad-signature-size";
    return nullptr;
}

inline const char* ack_shape_error(const AckFrame& a)
{
    if (a.version != kWireVersion) return "unsupported-version";
    if (a.origin_pubkey.size() != kPubkeyLen) return "bad-origin-pubkey";
    if (a.relay_pubkey.size() != kPubkeyLen || (a.relay_pubkey[0] != 0x02 && a.relay_pubkey[0] != 0x03))
        return "bad-relay-pubkey";
    if (a.status < 1 || a.status > 4) return "bad-status";
    if (a.signature.size() < kMinSigBytes || a.signature.size() > kMaxSigBytes) return "bad-signature-size";
    return nullptr;
}

// ── Per-peer DoS guard (lives on dash::Peer) ────────────────────────────────
// Sliding 60 s windows, separately for alerts and acks. Every inbound frame is
// charged (duplicates included) so a peer cannot make us do unbounded lookups;
// signature checks only run on first-see frames that passed the window.
//
// TRUSTED windows: a frame that CLAIMS a key this node already trusts (on a
// relay: an allowlisted origin; on an origin: an ack for itself from a
// configured relay) is charged to its own, larger window. Junk minted under
// fresh keys -- which any peer can sign, and which forwarders legitimately pass
// on because its signature is valid -- therefore cannot exhaust the budget a
// genuine alert arriving over the same link needs. A peer that forges the
// trusted key only burns the trusted window of ITS OWN link (windows are per
// peer, and a forwarder drops a forged signature before forwarding).
struct PeerAlertGuard {
    static constexpr std::size_t kMaxAlertsPerWindow        = 30;
    static constexpr std::size_t kMaxAcksPerWindow          = 30;
    static constexpr std::size_t kMaxTrustedAlertsPerWindow = 120;
    static constexpr std::size_t kMaxTrustedAcksPerWindow   = 120;
    static constexpr int64_t     kWindowSeconds             = 60;

    std::deque<int64_t> alert_window;
    std::deque<int64_t> ack_window;
    std::deque<int64_t> trusted_alert_window;
    std::deque<int64_t> trusted_ack_window;

    static bool admit(std::deque<int64_t>& w, std::size_t cap, int64_t now)
    {
        while (!w.empty() && w.front() + kWindowSeconds <= now) w.pop_front();
        if (w.size() >= cap) return false;
        w.push_back(now);
        return true;
    }
    bool admit_alert(int64_t now) { return admit(alert_window, kMaxAlertsPerWindow, now); }
    bool admit_ack(int64_t now) { return admit(ack_window, kMaxAcksPerWindow, now); }
    bool admit_trusted_alert(int64_t now) { return admit(trusted_alert_window, kMaxTrustedAlertsPerWindow, now); }
    bool admit_trusted_ack(int64_t now) { return admit(trusted_ack_window, kMaxTrustedAcksPerWindow, now); }
};

// ── Node-level seen set (IO-thread-confined) ────────────────────────────────
using AlertId = std::pair<Bytes, uint64_t>;   // (origin pubkey, nonce)

inline std::string alert_id_string(const Bytes& origin_pub, uint64_t nonce)
{
    return to_hex(origin_pub) + ":" + std::to_string(nonce);
}

struct SeenEntry {
    AlertFrame frame;                  // the VERIFIED frame as first received
    uint64_t   from_peer{0};           // peer nonce we last received it from (ack reverse path)
    int64_t    first_seen{0};
    int64_t    last_forward{0};        // 0 = never forwarded
    bool       for_me{false};
    std::optional<AckFrame> ack;       // freshest verified ack seen for this id
};

struct NodeAlertSeen {
    static constexpr std::size_t kMaxEntries = 4096;

    std::map<AlertId, SeenEntry> entries;
    std::deque<AlertId> order;
    uint64_t evicted{0};

    SeenEntry* find(const Bytes& origin, uint64_t nonce)
    {
        auto it = entries.find(AlertId{origin, nonce});
        return it == entries.end() ? nullptr : &it->second;
    }

    // INVARIANT: `order` holds each key of `entries` exactly once (so
    // order.size() == entries.size()). Every removal goes through erase() or
    // the eviction below, which keep both in step.
    SeenEntry& insert(const AlertFrame& f, uint64_t from, int64_t now)
    {
        AlertId id{f.origin_pubkey, f.nonce};
        auto [it, fresh] = entries.try_emplace(id);
        if (fresh) {
            order.push_back(id);
            it->second.frame = f;
            it->second.from_peer = from;
            it->second.first_seen = now;
            // FIFO eviction of the OLDEST ids. By the invariant the fresh id
            // occurs once in `order`, at the back, so it is never the one
            // erased and `it` stays valid (std::map::erase invalidates only
            // the erased element).
            while (order.size() > kMaxEntries) {
                entries.erase(order.front());
                order.pop_front();
                ++evicted;
            }
        }
        return it->second;
    }

    // Remove one id from BOTH the map and the FIFO. (Erasing only from the
    // map would leave a ghost slot in `order`; a re-insert of the same id
    // would then own two slots and the ghost, on reaching the front, would
    // evict the live entry -- possibly the one insert() just returned.)
    bool erase(const Bytes& origin, uint64_t nonce)
    {
        AlertId id{origin, nonce};
        if (entries.erase(id) == 0) return false;
        for (auto it = order.begin(); it != order.end(); ++it)
            if (*it == id) { order.erase(it); break; }
        return true;
    }

    std::size_t size() const { return entries.size(); }
};

} // namespace dash::alert
