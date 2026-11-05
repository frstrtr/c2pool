// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Vectors for the zero-fee inject builder KATs (public data only; no real key).
//
// K1 — the on-chain governance collateral tx
//   3d8fd96eae63e65c8723bbc20f40d26c0976658d71a897d94d3e8753565c81cd
// for gobject fa758340f1bd2391d17bb43667f76c5d9070d737b68e018e42ed75b09c6ba631,
// funded from and with change to the c2pool donation address
// XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u (dash::DONATION_SCRIPT). Version 2,
// locktime 0, 8 inputs at sequence ffffffff (NOT sorted by outpoint),
// out0 = 1.00000000 DASH OP_RETURN, out1 = 0.01627675 DASH change.
// The chain tx was NOT zero-fee: it was built by the Relay tool at 1000
// duffs/kB, its inputs sum to 101628946 duffs, and it paid a 1271-duff fee.
// Legacy sighash commits no input amounts, so the unsigned skeleton (input
// order, OP_RETURN, change script) does not depend on them: the KAT feeds
// amounts that sum to the outputs (kOnchainSumOut) and the zero-fee inject
// planner reproduces the identical unsigned bytes.
// The raw bytes are the mainnet transaction as served by getrawtransaction; the
// KAT re-derives its txid before trusting them.
//
// K7 — python parity: the synthetic 2-input spend of tools/c2wallet
// test_c2wallet.py section 7, signed by c2wallet.py sign_one (python3, stdlib
// only) with m/44'/5'/0'/0/0 of the public BIP39 vector "abandon x11 about" +
// passphrase "TREZOR". RFC6979 makes the signature deterministic, so the C++
// signer must reproduce these bytes exactly.

namespace c2w::dash::testvec {

struct OnchainPrevout {
    const char* txid; // display order
    unsigned vout;
};

inline const char* const kOnchainCollateralTxid =
    "3d8fd96eae63e65c8723bbc20f40d26c0976658d71a897d94d3e8753565c81cd";
inline const char* const kOnchainGovHash =
    "fa758340f1bd2391d17bb43667f76c5d9070d737b68e018e42ed75b09c6ba631";
inline const char* const kOnchainOpReturn =
    "6a2031a66b9cb075ed428e018eb637d770905d6cf76736b47bd19123bdf1408375fa";
inline const char* const kDonationAddress = "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u";
inline const char* const kDonationSpk = "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac";
inline const long long kOnchainChange = 1627675;
inline const long long kOnchainSumOut = 101627675; // out0 + out1; the chain inputs were 101628946

inline const char* const kOnchainCollateralHex =
    "02000000089e37dd515ffb4eea8497e3d82363b2ac18296d871773463ad0258cefb5836e5900"
    "0000006b483045022100dbc33dc38c176b05d5af6b4b5d6279c54a682353d562fb84285c67cf"
    "169ac3e20220513eeade4b7773ed3545004c932e581725cde0f1f919161a4e40363c07172f39"
    "012102fe6578f8021a7d466787827b3f26437aef88279ef380af326f87ec362633293affffff"
    "ff540c4f6b73c1747d92115265eb975fa1df56221d6a874cef648510ab6d265d96000000006a"
    "473044022049af6f0d8acc1da2536965e30cf0309a65e2f91f68d80cdbf031d12bb748003802"
    "2075be8f349258c3780d0b6b6df8f22ae7755c8d06301c697f12bc49f34ad01a6b012102fe65"
    "78f8021a7d466787827b3f26437aef88279ef380af326f87ec362633293affffffff23aa5de2"
    "09eec541a927f3103bcf1742a61dafef2fb905e2fda5b64cabbbcb96000000006a4730440220"
    "4e2e9464b7295f59f31cb69477ffe6ae9c7a5ac0ac50b5758711b8278187bc060220053c7167"
    "81a4224194e4badb87b2defc86686d9060462a0ce457b35a1e7e0f18012102fe6578f8021a7d"
    "466787827b3f26437aef88279ef380af326f87ec362633293affffffffc1eb6578071b9e20f5"
    "1f21d5d7808df8e28980310dda5d853ea388ecefd92195000000006a47304402206f7173afe2"
    "9662d4a8f7aba334c29710ff51f346c0f5e0f34940e4c0125430b502206d796c29e93ac01585"
    "238decbdf54af617a740e3f5ac1d0162875346b3661c60012102fe6578f8021a7d466787827b"
    "3f26437aef88279ef380af326f87ec362633293afffffffffbe95c874ff1ce322264a17d5029"
    "d32f59b7c0223387b330fe348c9f9fce3ba4070000006b483045022100de12a04b0f9b725871"
    "9a737fd437708300a37bc2d4e09eb71180685fcfd8193602204c1272dfc4b72e1d62bbf83aa5"
    "c85cef1f2241a50f07f78d92ee3dc11234d945012102fe6578f8021a7d466787827b3f26437a"
    "ef88279ef380af326f87ec362633293affffffffb3bc359075c1678fe690aaf24b1d770159d8"
    "1ebe690589d3ba2ca24105a7aa7d070000006b483045022100e7714cf997862622c9d18fc1b3"
    "9c9b24db289deeec007e2c90b67a8e20491dcd022009e4d46dbc16fa39893a75b93880ab5703"
    "66f91b41fceb3939811fab873bf99c012102fe6578f8021a7d466787827b3f26437aef88279e"
    "f380af326f87ec362633293affffffff609f6b6d9554376f6d06288cb5cf9314f2d98e99e05e"
    "a05c9ff28e9e01091d67070000006a47304402203db80fbfa844abfed6660c7a26eed01b2ea1"
    "933aeeeea4961a5c69d6cb49d44a02203e625e3211d5ded5d8eee6876a3e801a2ca5030b73e0"
    "67286f0c322218c1ffda012102fe6578f8021a7d466787827b3f26437aef88279ef380af326f"
    "87ec362633293affffffffe6a4aeb3507dcd6d48b78e5cb496a1ca7b76c087577514e28724ee"
    "5a7334cafd070000006b4830450221009d27ff236fb52a28197a51105b3a4b6f64abe14a324c"
    "5e6a4ec077941ebfdd36022020ac6b68cc10e58f8c31394ffe11ddcd1eea697ad0db4b529ffc"
    "7be240ddbd28012102fe6578f8021a7d466787827b3f26437aef88279ef380af326f87ec3626"
    "33293affffffff0200e1f50500000000226a2031a66b9cb075ed428e018eb637d770905d6cf7"
    "6736b47bd19123bdf1408375fa1bd61800000000001976a91420cb5c22b1e4d5947e5c112c76"
    "96b51ad9af3c6188ac00000000";

inline const OnchainPrevout kOnchainCollateralPrevouts[] = {
    {"596e83b5ef8c25d03a467317876d2918acb26323d8e39784ea4efb5f51dd379e", 0},
    {"965d266dab108564ef4c876a1d2256dfa15f97eb655211927d74c1736b4f0c54", 0},
    {"96cbbbab4cb6a5fde205b92fefaf1da64217cf3b10f327a941c5ee09e25daa23", 0},
    {"9521d9efec88a33e855dda0d318089e2f88d80d7d5211ff5209e1b077865ebc1", 0},
    {"a43bce9f9f8c34fe30b3873322c0b7592fd329507da1642232cef14f875ce9fb", 7},
    {"7daaa70541a22cbad3890569be1ed85901771d4bf2aa90e68f67c1759035bcb3", 7},
    {"671d09019e8ef29f5ca05ee0998ed9f21493cfb58c28066d6f3754956d6b9f60", 7},
    {"fdca34735aee2487e214755787c0767bcaa196b45c8eb7486dcd7d50b3aea4e6", 7},
};
inline const char* const kPyParityUnsignedHex =
    "0200000002111111111111111111111111111111111111111111111111111111111111111100"
    "00000000ffffffff222222222222222222222222222222222222222222222222222222222222"
    "22220100000000ffffffff01a0860100000000001976a9147dab9e608970702ddcb713478297"
    "91e059129f9488ac00000000";

inline const char* const kPyParitySignedHex =
    "0200000002111111111111111111111111111111111111111111111111111111111111111100"
    "0000006b48304502210087fb44fb6446a0d105fb1e5f91c7ef18cf27c9f01c16f76b017c716e"
    "4e6568ef02207560567cee2af72daad9baf2ed85911a1b1847ad67eb7bf8ca713ce1353badb4"
    "0121034aeeebe4512c6ae6635df74b39b40079ef2dd6f5d2c7a0ff3c37cf4b67681795ffffff"
    "ff2222222222222222222222222222222222222222222222222222222222222222010000006a"
    "4730440220345944d37e22becef5a182dc081d42f5938b542ac2a948141246bf0cfe125a2c02"
    "20658ca77cf160f0d16e9486bb22a2ea75d61e99d2ecf4e0443bf76c72d6f617db0121034aee"
    "ebe4512c6ae6635df74b39b40079ef2dd6f5d2c7a0ff3c37cf4b67681795ffffffff01a08601"
    "00000000001976a9147dab9e608970702ddcb71347829791e059129f9488ac00000000";

inline const char* const kPyParityPassphrase = "TREZOR";
inline const char* const kPyParityAddress = "Xn9KtWHuvMBuSbpzPFTzYG2bC9Wp2ZZJJG"; // m/44'/5'/0'/0/0
inline const char* const kPyParityTxid =
    "0a1c9227574debb59b9171ea6d38f9d142a6637e9c9448b292efe379fa3e0f70";

// K8 — addresses of the "abandon x11 about" mnemonic, passphrase "", from the
// same python reference (c2wallet.py p2pkh_address over pub_bytes).
inline const char* const kUncompressedAddr001 = "Xu3x5QkRmD8WeFpcH2mfuLhyAWUw2CZZMC"; // m/44'/5'/0'/0/1, pub65
inline const char* const kAccount1Addr000 = "XfoXRyRePBFFhg7fKbsGRQBixHipJSGqNf";     // m/44'/5'/1'/0/0

} // namespace c2w::dash::testvec
