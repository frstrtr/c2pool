// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// Litecoin mainnet vectors for the hybrid MWEB extension KATs (#2137 S3),
// read from the same litecoind 0.21.4 captures as ltc_mweb_tx_fixtures.hpp
// (getblock <hash> 0|2, 2026-10-24): /home/ubuntu/drafts/ltc-mweb/vectors
// ltc_3200603_block_with_mweb.hex, ltc_3200604_block_with_mweb.hex,
// l3/block_3200601.hex and l3/block_3200601.json.
//
// Headers are the 80 wire bytes; txids and block hashes are RPC (reversed)
// hex. Do not hand-edit.
// ---------------------------------------------------------------------------

#include <cstdint>

namespace ltc_mweb_ext_fixture {

// ─── block headers ─────────────────────────────────────────────────────────
// 3200604: prev 3200603 (310f1628..), an empty MWEB body.
inline constexpr uint32_t kHeight3200604 = 3200604;
inline constexpr const char* kHeader3200604Hex =
    "00000020e2a73c0fec95e5d6f7655ada1f8d5f81b443d2977e5aaf381fcb296c28160f31"
    "c3def99117e0a20e7a2298499862707b46e5b8d5d241d2c5351c0fbfd058f6cfbb48dc6a"
    "2fd12e193a1b087c";
inline constexpr const char* kHash3200604 = "33f03dc230a5a652e05f2cbe9feabd524459409f565ac7ddd7238dfb67f7a297";
inline constexpr const char* kHash3200603 = "310f16286c29cb1f38af5a7e97d243b4815f8d1fda5a65f7d6e595ec0f3ca7e2";

// 3200603: prev 3200602 (63697e48..); 6 inputs, 2 outputs, 2 kernels.
inline constexpr uint32_t kHeight3200603 = 3200603;
inline constexpr const char* kHeader3200603Hex =
    "14000020e8080491df52cf13e9656570f063b49b61ab7aa800e4ca97621415c6487e6963"
    "a5a6a5cf9600901f0c04e23c76c3244165cbbfefb3a8b81937679f4d24f48d188848dc6a"
    "2fd12e19163c713d";
inline constexpr const char* kHash3200602 = "63697e48c615146297cae400a87aab619bb463f0706565e913cf52df910408e8";
// vin[0] of 3200603's HogEx: the HogEx of 3200602.
inline constexpr const char* kHogexTxid3200602 = "32db86861df4b05f5e64273d9dbd7b3e183edee06d30088e27ebe1511eff3872";
// Kernel fees of 3200603's body (50000 + 2262) and its peg-out.
inline constexpr int64_t kKernelFees3200603 = 52262;
inline constexpr int64_t kPegout3200603 = 2500000000LL;

// 3200601: prev 3200600 (232e08fa..); 1 input, 2 outputs, 2 kernels (a
// peg-in 570771880 fee 2100, a peg-out 30000000 fee 2540).
inline constexpr uint32_t kHeight3200601 = 3200601;
inline constexpr const char* kHeader3200601Hex =
    "14000020f5adc7be944e858194f3986c13771064d614ab7e88694e5d62e75562fa082e23"
    "0985a009779b75244009b920dea082f2318f2da7b0ae27df6cbc5bb3d17548c0c446dc6a"
    "2fd12e19d5d90815";
inline constexpr const char* kHash3200601 = "018dae26d9bf9bc69716054894a8e70620f37ade434ee955f0a81a38813718c3";
inline constexpr const char* kHash3200600 = "232e08fa6255e7625d4e69887eab14d6641077136c98f39481854e94bec7adf5";
// vin[0] of 3200601's HogEx: the HogEx of 3200600.
inline constexpr const char* kHogexTxid3200600 = "cf0368d3fd76e35991f3900ad930379a852805c77d57123e805890749eafb896";
inline constexpr int64_t kHogaddrValue3200601 = 44661362115013LL;
inline constexpr int64_t kPegin3200601 = 570771880LL;
inline constexpr int64_t kPegout3200601 = 30000000LL;
inline constexpr int64_t kKernelFees3200601 = 4640;      // 2100 + 2540
inline constexpr int64_t kPeginKernelFee3200601 = 2100;
inline constexpr int64_t kPegoutKernelFee3200601 = 2540;  // the MWEB-only peg-out tx
inline constexpr uint64_t kTxos3200601 = 381307;

// The peg-in of 3200601 (block index 52) as the block carries it, its MWEB
// part stripped: 3 inputs, vout[0] the pegin script 5920 <79005b1f..> of
// 570771880, nLockTime 3200600.
inline constexpr const char* kPeginTx3200601Hex =
    "02000000000103bf9d8d12a566792a1d6f8bdc2d62d644abfcf9b247f0413a8b2afd6abc"
    "1eb47d0000000000fdffffff5b59c59b66640a6ca0d885fcd3eac8da441b3a71111365ac"
    "f5d4cee486d543cf0000000000fdffffff5b59c59b66640a6ca0d885fcd3eac8da441b3a"
    "71111365acf5d4cee486d543cf0100000000fdffffff01a84905220000000022592079005b"
    "1f1cd58cb48c0da1df5e7a02048d988eff68107cd09f2113c157e4bebe0247304402203eb9"
    "98e4f3931c6b5cf3eb91ccb3bb5ece415e3c4fad53d606376b682e39c5fe0220211378ccbf"
    "bd9ae2c931fc56fd3979ba73d00c24aca03afa3ea1e40a3743d785012102589f6d7709d795"
    "753d7672ad64d8ee7285dd254cbfe47a95503f033f70d1073a024730440220104c73d9d925"
    "e6e5ab66003ab1c4a2bf5aad2a93a4aae07e9912f7bf19195899022007e07572076b84ea4a"
    "c618dae47b0f3eab56ffd6c330a4ba6b04d36d040bbe4701210222259e98c17987177cc33d"
    "54c6a7821d68206c12f91828ab9147bbf758d9eea20247304402201535c2ead06f36f4fe2a"
    "95bd6e6c4cc27475e1b4cc1077f9edfa6317991a5d9b022016abb4731b04811049f51eaa81"
    "eb2c0b3d7ec8f204a0e80f680accbe54a9de05012103452b54263702aff0cfbd297db5b536"
    "0cb02ca41a79dd4a48a9fafccf4da16d5b58d63000";
inline constexpr const char* kPeginTx3200601Txid = "92dd3109f8e1c0e7a0bb3e96960f1c9c0706cf76d15d980c4c76ba95bafeafe1";
inline constexpr const char* kPeginTx3200601Wtxid = "3b9bd3341fc33815ae81777ff6980809ffecec9ae2500527b37eaa0142fc0b3c";

} // namespace ltc_mweb_ext_fixture
