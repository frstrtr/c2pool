// SPDX-License-Identifier: AGPL-3.0-or-later
// MessageModel — the Sign tab's state machine (design A.4). Lives in
// c2wallet-dash-common on the btclibs closure: it reaches the key loaders
// (DashInjectModel.cpp) and the message signer (DashMessage.cpp), never a
// dashscript / signer header.
#include "MessageModel.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// btclibs SHA-256 for the message fingerprint; hdkeys hex. NO dashscript headers.
#include <crypto/sha256.h>

#include "../hdkeys/HexUtil.hpp"

#include <utility>

namespace c2w::dash {

namespace {

bool ascii_ws(uint8_t c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

// Strict UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF.
bool valid_utf8(const std::vector<uint8_t>& b)
{
    size_t i = 0;
    const size_t n = b.size();
    while (i < n) {
        const uint8_t c = b[i];
        if (c < 0x80) { ++i; continue; }
        size_t len = 0;
        uint32_t cp = 0, min = 0;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((b[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (b[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

std::string network_name(bool testnet) { return testnet ? "testnet" : "mainnet"; }

// "<path> (compressed|uncompressed)"; the importers already append
// " (uncompressed)" to an uncompressed key's path, so it is not said twice.
std::string key_label(std::string path, bool compressed)
{
    const std::string tag = " (uncompressed)";
    if (path.size() >= tag.size() && path.compare(path.size() - tag.size(), tag.size(), tag) == 0)
        path.erase(path.size() - tag.size());
    return path + (compressed ? " (compressed)" : " (uncompressed)");
}

} // namespace

const char* message_stage_name(MessageStage s)
{
    switch (s) {
    case MessageStage::Empty: return "empty";
    case MessageStage::Targeted: return "targeted";
    case MessageStage::KeyBound: return "key bound";
    case MessageStage::Signed: return "signed";
    }
    return "?";
}

MessageFlags message_flags(const std::vector<uint8_t>& m)
{
    MessageFlags f;
    f.bytes = m.size();
    f.empty = m.empty();
    for (uint8_t c : m) {
        if (c == '\n') ++f.lines;
        if (c == '\r') f.has_cr = true;
        if (c >= 0x80) ++f.non_ascii;
    }
    if (!m.empty()) {
        f.leading_ws = ascii_ws(m.front());
        f.trailing_newline = m.back() == '\n';
        f.trailing_ws = m.back() != '\n' && ascii_ws(m.back());
    }
    f.invalid_utf8 = !valid_utf8(m);
    f.long_form = m.size() >= 0xFD;
    return f;
}

std::string message_sha256_hex(const std::vector<uint8_t>& m)
{
    unsigned char h[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(m.data(), m.size()).Finalize(h);
    return hdkeys::to_hex(h, sizeof h);
}

// ── housekeeping ─────────────────────────────────────────────────────────────

MessageModel::MessageModel(bool testnet) : testnet_(testnet) {}

MessageModel::~MessageModel() { wipe_key(); }

void MessageModel::wipe_key()
{
    if (key_) {
        key_.reset(); // ~FoundKey -> ~SecureBytes zeroizes the scalar
        ++keys_wiped_;
    }
}

void MessageModel::clear_gate()
{
    reviewed_ = false;
    typed_.clear();
}

// Everything after Targeted: the key, the gate and the signature.
void MessageModel::drop_signed()
{
    wipe_key();
    clear_gate();
    signature_.clear();
    verified_ = VerifyReport{};
    key_path_.clear();
    key_compressed_ = true;
    if (stage_ > MessageStage::Targeted) stage_ = MessageStage::Targeted;
}

bool MessageModel::testnet() const { return testnet_; }
MessageStage MessageModel::stage() const { return stage_; }

void MessageModel::reset()
{
    drop_signed();
    ticker_.clear();
    address_.clear();
    message_set_ = false;
    message_.clear();
    stage_ = MessageStage::Empty;
}

// ── 1. target ────────────────────────────────────────────────────────────────

void MessageModel::set_target(const std::string& ticker, const std::string& address)
{
    // Validate everything before touching the model: a refusal changes nothing.
    const MessageCoin& coin = message_coin(ticker);
    if (!coin.kat_proven)
        throw DashAbort(std::string(coin.ticker) + " message signing is refused: no node vector proves its "
                                                   "magic yet. Only DASH is enabled in this build.");
    if (address.empty()) throw DashAbort("the address is empty");
    p2pkh_to_h160(address, testnet_ ? coin.p2pkh_testnet : coin.p2pkh_mainnet);

    drop_signed();
    ticker_ = coin.ticker;
    address_ = address;
    stage_ = MessageStage::Targeted;
}

const std::string& MessageModel::ticker() const { return ticker_; }
const std::string& MessageModel::address() const { return address_; }

std::string MessageModel::target_card() const
{
    if (stage_ < MessageStage::Targeted) return "no target set";
    const MessageCoin& coin = message_coin(ticker_);
    const uint8_t version = testnet_ ? coin.p2pkh_testnet : coin.p2pkh_mainnet;
    const std::array<uint8_t, 20> h = p2pkh_to_h160(address_, version);
    static const char* hexd = "0123456789abcdef";
    std::string magic;
    for (const char* p = coin.magic; *p; ++p) magic += *p == '\n' ? std::string("\\n") : std::string(1, *p);
    std::string s;
    s += "coin:     " + ticker_ + " (" + network_name(testnet_) + "), magic \"" + magic + "\"\n";
    s += "address:  " + address_ + "\n";
    s += std::string("version:  0x") + hexd[version >> 4] + hexd[version & 15] + " (P2PKH)\n";
    s += "hash160:  " + hdkeys::to_hex(h.data(), h.size()) + "\n";
    return s;
}

// ── 2. message ───────────────────────────────────────────────────────────────

void MessageModel::set_message(std::vector<uint8_t> bytes)
{
    drop_signed(); // a new message after the key is bound wipes the key
    message_ = std::move(bytes);
    message_set_ = true;
}

bool MessageModel::has_message() const { return message_set_; }
const std::vector<uint8_t>& MessageModel::message() const { return message_; }
MessageFlags MessageModel::flags() const { return message_flags(message_); }
std::string MessageModel::message_sha256_hex() const { return c2w::dash::message_sha256_hex(message_); }

// ── 3. key ───────────────────────────────────────────────────────────────────

void MessageModel::load_key(const KeyInput& in)
{
    if (stage_ < MessageStage::Targeted)
        throw DashAbort("load_key: set the target address first (no stage can be skipped)");
    if (!message_set_)
        throw DashAbort("load_key: set the message first, so the exact bytes are fixed before any key is loaded");
    drop_signed(); // replaces (and wipes) any key held
    // load_funding_key is DASH-only (DASH WIF version, coin type 5) and refuses
    // an address with any other version byte; set_target admits proven coins
    // only, and DASH is the only proven one.
    FoundKey k = load_funding_key(in, address_, testnet_);
    key_ = std::make_unique<FoundKey>(std::move(k));
    key_source_ = in.source;
    key_path_ = key_->path;
    key_compressed_ = key_->compressed;
    stage_ = MessageStage::KeyBound;
}

bool MessageModel::has_key() const { return static_cast<bool>(key_); }

std::string MessageModel::key_card() const
{
    if (!key_)
        return stage_ == MessageStage::Signed ? "no key held (wiped after signing)" : "no key bound";
    return "key: " + key_label(key_path_, key_compressed_) + " via " + key_source_name(key_source_) +
           "\nbound to " + address_ +
           " (on the address AND hash160(pubkey))\n";
}

size_t MessageModel::keys_wiped() const { return keys_wiped_; }

// ── 4. gate + sign ───────────────────────────────────────────────────────────

void MessageModel::set_gate(bool reviewed, const std::string& typed_word)
{
    reviewed_ = reviewed;
    typed_ = typed_word;
}

bool MessageModel::armed() const
{
    return stage_ == MessageStage::KeyBound && key_ && message_set_ && reviewed_ && typed_ == kSignWord;
}

void MessageModel::sign()
{
    if (stage_ != MessageStage::KeyBound || !key_)
        throw DashAbort(std::string("sign: no key is bound (the model is at stage \"") +
                        message_stage_name(stage_) + "\") — bind the key first");
    if (!armed())
        throw DashAbort(std::string("not armed: tick \"reviewed\" and type ") + kSignWord +
                        ". Nothing was signed.");

    // From here the key is single-use: it is wiped when this scope ends, whether
    // signing succeeds or throws. A refusal leaves the model at Targeted, so the
    // operator binds the key again to retry.
    struct KeyWipe {
        MessageModel& m;
        ~KeyWipe() { m.wipe_key(); }
    } wipe_on_exit{*this};
    clear_gate();
    stage_ = MessageStage::Targeted;

    const MessageCoin& coin = message_coin(ticker_);
    std::string sig = sign_message(coin, *key_, message_, testnet_); // self-verifies twice before it returns
    wipe_key(); // as soon as the signature exists

    // The visible verify leg: the emitted base64 through verify_message again,
    // recorded for the card.
    VerifyReport vr;
    if (!verify_message(coin, address_, message_, sig, testnet_, &vr))
        throw DashAbort("verify of the emitted signature FAILED (" + vr.why + ") — nothing was emitted");
    signature_ = std::move(sig);
    verified_ = vr;
    stage_ = MessageStage::Signed;
}

const std::string& MessageModel::signature_b64() const { return signature_; }

std::string MessageModel::sign_card() const
{
    if (stage_ != MessageStage::Signed) return "not signed";
    std::string s;
    s += "coin:        " + ticker_ + " (" + network_name(testnet_) + ")\n";
    s += "address:     " + address_ + "\n";
    s += "message:     " + std::to_string(message_.size()) + " bytes, sha256 " + message_sha256_hex() + "\n";
    s += "key:         " + key_label(key_path_, key_compressed_) + ", wiped after signing\n";
    s += "signature:   " + signature_ + "\n";
    s += "self-verify: OK (recovered " + verified_.recovered_address + ", " +
         (verified_.header_compressed ? "compressed" : "uncompressed") + ", recid " +
         std::to_string(verified_.recid) + ")\n";
    s += "domain:      the signed digest carries the coin's message magic, so this signature can never be "
         "replayed as a transaction signature\n";
    return s;
}

std::string MessageModel::export_text() const
{
    if (stage_ != MessageStage::Signed) return {};
    std::string s = "address:   " + address_ + "\nmessage:   ";
    s.append(message_.begin(), message_.end());
    s += "\nsignature: " + signature_ + "\n";
    return s;
}

} // namespace c2w::dash
