// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Slice-2 key-path vectors (S2-K5). PUBLIC test keys only: every key below is
// derived from the public BIP39 test mnemonic "abandon x11 about". They were
// produced by the python reference tools/c2wallet/c2wallet.py (stdlib) plus
// the openssl CLI for the AES-256 block of the BIP38 encryptor; before use, that
// encryptor reproduced the published BIP38 vectors 6PYNKZ1E... and 6PRVWUbk...
// and the descriptor checksum reproduced Bitcoin Core's pkh(02c6...)#8fhd9pwu.
//
// K7 key = m/44'/5'/0'/0/0 of the mnemonic with passphrase "TREZOR",
// compressed, address Xn9KtWHuvMBuSbpzPFTzYG2bC9Wp2ZZJJG (testvec::kPyParity*).
// Every format below must yield that key and sign kPyParitySignedHex
// byte-exact through the model.

namespace c2w::dash::testvec {

// DASH mainnet WIF (version 0xcc), compressed.
inline const char* const kK7Wif = "XH9QRA2nnr1X5nuQEPKbUHupdjmri24fR6HpUjm2WQRjZEaQEkvb";
// The same scalar under the BTC WIF version 0x80 (refused: not a DASH WIF).
inline const char* const kK7WifBtcVersion = "L35UxteRVAP52Tu2CdKiy4ioiiWHGDTR3WwuxDRqC39eA5YLZ9iC";
// BIP38 non-EC-multiply, compressed, passphrase kBip38Pass. Address hash over
// the DASH address (what a DASH encryptor writes) and over the BTC address (what
// BIP38 itself specifies).
inline const char* const kBip38Pass = "TestingOneTwoThree";
inline const char* const kK7Bip38Dash = "6PYXf2RvPZcncbcnpPNC4yQxSAp9WaDnb6fEaFuRa1T9aGJ8S7UgUcZKEn";
inline const char* const kK7Bip38BtcHash = "6PYNUrbopx2w4wdVsJyj13dnyT4ZCwdhWBfqZNhns3BwbAEWZGVBG69dMh";
// Account-level xprv m/44'/5'/0' of the TREZOR seed with its key origin
// (master fingerprint b4e3f5ed) and Core descriptor checksum.
inline const char* const kK7Descriptor =
    "pkh([b4e3f5ed/44'/5'/0']xprv9zUwecf3TjfmaeR6LkfC8LhRUAHgddJ4UkuNDpLQyCxucM7SbvN7h6GDxkfW8Zwx6yGrvdAao4EvjJoMPM5ModJbcqR3AE5yUwEZoAZtVFd/0/*)#z5c8zxwc";
// The account xprv alone (for the keystore-xprv path).
inline const char* const kK7AccountXprv =
    "xprv9zUwecf3TjfmaeR6LkfC8LhRUAHgddJ4UkuNDpLQyCxucM7SbvN7h6GDxkfW8Zwx6yGrvdAao4EvjJoMPM5ModJbcqR3AE5yUwEZoAZtVFd";
// The 32-byte scalar of the K7 key is never spelled out here; S2-K9 derives
// the hex it greps for from the WIF.

// A second compressed key (passphrase "", m/44'/5'/0'/0/1): a keystore decoy.
inline const char* const kDecoyWif = "XESkaBCCst7GbZP78jtciTKFcztnyLUWQ7tv5SH93o5CsMEycUcB";

// Uncompressed: m/44'/5'/0'/0/1, passphrase "", pub65 -> kUncompressedAddr001
// (Xu3x5QkR...). Its own python-signed parity vector: Tx(2, [33x32:0, 44x32:2]
// seq ffffffff, [90000 -> P2PKH(Xu3x5QkR...)], 0) signed by c2wallet.py
// sign_one. Input 1's s is 31 bytes (minimal DER), a length edge case.
inline const char* const kUncompWif = "7rGMJ2rfVJ1y6ZiFz31pWnPG6SMLvzt6JUPdwvkz756V4iX3MCU";
inline const char* const kUncompUnsignedHex =
    "020000000233333333333333333333333333333333333333333333333333333333333333330000000000ffffffff4444"
    "4444444444444444444444444444444444444444444444444444444444440200000000ffffffff01905f01000000000019"
    "76a914c970362ba77107435d58b38b13b5d9062f2f73aa88ac00000000";
inline const char* const kUncompSignedHex =
    "02000000023333333333333333333333333333333333333333333333333333333333333333000000008b483045022100"
    "fbd16994a63f7cfeac516dbfa9f253e9096cfa9c498fe600e579fbf7eb21176602200ed29e44e84f20a8b4ea878f40f7"
    "f2c0a4cbf55b19f4379d7d591e83cc563bd00141048f34569f115a9b6d5f4dc7d1150b396e2413b904c68a64d918ba54"
    "f37da38f22ec8937394988b1f004d70d2e3e2a070a47b0421dda154ff0741fa7a50841a10fffffffff44444444444444"
    "44444444444444444444444444444444444444444444444444020000008a473044022100ee8dfd2562f5b8acfaed9eab"
    "686a5c70b7ff1b9603d811e8c628e2070c29ff1a021f402b5a153194d22351547d5c9334f4ed32f690be3a5f2a0b8d89"
    "ed11ddbf0e0141048f34569f115a9b6d5f4dc7d1150b396e2413b904c68a64d918ba54f37da38f22ec8937394988b1f0"
    "04d70d2e3e2a070a47b0421dda154ff0741fa7a50841a10fffffffff01905f0100000000001976a914c970362ba77107"
    "435d58b38b13b5d9062f2f73aa88ac00000000";
inline const char* const kUncompTxid = "04a89f3af117d734d9d87e6ca81657bd708fc6e09d2d1736a22fba65dc316174";

} // namespace c2w::dash::testvec
