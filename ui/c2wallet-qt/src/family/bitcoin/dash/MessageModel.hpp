// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// MessageModel — the std-only, Qt-free state machine behind PageSignMessage's
// Sign tab (design A.4). The page is a thin binding; every rule lives here so
// c2wallet-dash-test KATs it without Qt.
//
//   1 target   coin (only a node-vector-proven row) + P2PKH address  -> Targeted
//   2 message  the exact bytes to sign; never trimmed (any stage before
//              Signed; a re-set after the key is bound wipes the key)
//   3 key      mnemonic / WIF / BIP38 / descriptor / JSON keystore, bound on
//              BOTH the address and hash160(pub) (needs a message)   -> KeyBound
//   4 sign     reviewed + literal SIGN; sign, verify the emitted signature,
//              wipe the key                                          -> Signed
//
// The literal is SIGN, not SPEND: a message signature moves no money, and the
// money word keeps its meaning. It is still a typed literal so a stray click
// cannot sign. The coin's magic prefix is domain separation: a message
// signature can never be replayed as a transaction signature.
//
// Secret rules are DashInjectModel's: the scalar lives only in the model's
// FoundKey (zeroizing SecureBytes) and is destroyed on sign (success or
// refusal), on re-target, on re-message, on reset() and on destruction. No
// card, error or export carries a secret; keys_wiped() is the test sentinel.
// A refused call leaves the model as it was, except that a refused load_key
// has already dropped any previously bound key.

#include "DashInjectModel.hpp" // KeyInput, load_funding_key
#include "DashMessage.hpp"
#include "KeyScan.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace c2w::dash {

enum class MessageStage : uint8_t { Empty, Targeted, KeyBound, Signed };
const char* message_stage_name(MessageStage s);

inline constexpr const char* kSignWord = "SIGN"; // the literal confirmation

// What the page shows next to the byte count. Informational: nothing is ever
// trimmed or rewritten, the bytes are signed exactly as given.
struct MessageFlags {
    size_t bytes = 0;              // byte length
    size_t lines = 1;              // 1 + number of LF bytes
    bool empty = false;
    bool leading_ws = false;       // first byte is ASCII whitespace
    bool trailing_ws = false;      // last byte is ASCII whitespace other than LF
    bool trailing_newline = false; // last byte is LF
    bool has_cr = false;           // a CR byte (cannot come from the text widget; only from a file)
    bool invalid_utf8 = false;     // only possible from a file; the bytes are signed as-is
    size_t non_ascii = 0;          // bytes >= 0x80: a pasted no-break space or a look-alike letter
    bool long_form = false;        // >= 253 bytes: compactsize 0xfd prefix
};

MessageFlags message_flags(const std::vector<uint8_t>& message);
// Lowercase hex sha256 of the exact message bytes (for cross-gap comparison).
std::string message_sha256_hex(const std::vector<uint8_t>& message);

class MessageModel {
public:
    explicit MessageModel(bool testnet = false);
    ~MessageModel();
    MessageModel(const MessageModel&) = delete;
    MessageModel& operator=(const MessageModel&) = delete;

    bool testnet() const;
    MessageStage stage() const;

    // ── 1. target ──────────────────────────────────────────────────────────
    // Validates first and changes nothing on a refusal (unknown or unproven
    // coin, bad checksum, wrong network, not P2PKH). On success drops any key
    // and signature; a message already set is kept.
    void set_target(const std::string& ticker, const std::string& address);
    const std::string& ticker() const;
    const std::string& address() const;
    std::string target_card() const;   // coin, network, version byte, hash160

    // ── 2. message ─────────────────────────────────────────────────────────
    void set_message(std::vector<uint8_t> bytes);   // exact bytes, never trimmed
    bool has_message() const;                       // set at least once (may be empty)
    const std::vector<uint8_t>& message() const;
    MessageFlags flags() const;
    std::string message_sha256_hex() const;

    // ── 3. key (>= Targeted, message set) ──────────────────────────────────
    void load_key(const KeyInput& in);   // load_funding_key(in, address) -> KeyBound
    bool has_key() const;
    std::string key_card() const;
    size_t keys_wiped() const;           // sentinel: how many held keys this model destroyed

    // ── 4. gate + sign (KeyBound) ──────────────────────────────────────────
    void set_gate(bool reviewed, const std::string& typed_word);
    bool armed() const;                  // KeyBound && reviewed && typed == "SIGN"
    void sign();                         // sign -> verify the emitted sig -> wipe the key -> Signed
    const std::string& signature_b64() const;
    std::string sign_card() const;       // address, bytes, sha256, signature, self-verify line
    // "address:   X\nmessage:   <bytes>\nsignature: S\n" — exactly the python
    // stopgap's stdout for the same input. Empty unless Signed.
    std::string export_text() const;

    void reset();

private:
    void wipe_key();
    void drop_signed();
    void clear_gate();

    bool testnet_ = false;
    MessageStage stage_ = MessageStage::Empty;
    // 1. target
    std::string ticker_;
    std::string address_;
    // 2. message
    bool message_set_ = false;
    std::vector<uint8_t> message_;
    // 3. key: the only secret the model holds
    std::unique_ptr<FoundKey> key_;
    KeySource key_source_ = KeySource::Mnemonic;
    std::string key_path_;     // public: kept for the sign card after the key is wiped
    bool key_compressed_ = true;
    size_t keys_wiped_ = 0;
    // 4. gate + output
    bool reviewed_ = false;
    std::string typed_;
    std::string signature_;
    VerifyReport verified_;
};

} // namespace c2w::dash
