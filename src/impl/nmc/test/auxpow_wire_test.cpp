// ---------------------------------------------------------------------------
// nmc::coin::AuxPow wire-vector KAT (P1 / card 237 — real mainnet round-trip).
//
// Pins the canonical Namecoin CAuxPow wire layout (AuxPow::Serialize /
// Unserialize in coin/header_chain.hpp) against a GENUINE Namecoin MAINNET
// block, pulled with `namecoin-cli getblock <hash> 0` from a pruned mainnet
// node (block 757000, hash 47589169f94e3e77bf4da8067e76b4417b021f0eb107609956
// 71856f21b8d4b4). The block carries a real merge-mined AuxPow proof against a
// BTC (AntPool) parent coinbase.
//
// The test deserializes the 80-byte NMC header, asserts the auxpow header bits
// (base version 4, auxpow flag 0x100, chain_id 1), deserializes the AuxPow,
// then re-serializes it and requires the bytes to reproduce the exact mainnet
// region [80, 80+len) byte-for-byte. A field-order / width / witness-handling
// bug in our hand-written CAuxPow serializer would diverge against the real
// daemon-produced blob rather than be mirrored — the vector is external truth,
// not a self-derived fixture.
//
// Per-coin isolation: src/impl/nmc/ only; consumes core/* + nmc::coin types,
// no btc/ or bitcoin_family/ include. MUST appear in BOTH test/CMakeLists.txt
// AND the build.yml --target allowlist or it becomes a NOT_BUILT sentinel that
// reds master (cf. DGB #137).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstring>
#include <cstdint>
#include <string>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/block.hpp"
#include "../coin/header_chain.hpp"

namespace {

using nmc::coin::AuxPow;
using nmc::coin::BlockHeaderType;

// Raw `getblock 47589169...b8d4b4 0` hex — Namecoin mainnet block 757000.
static const std::string NMC_BLOCK_757000_HEX =
    "040101001e2c42dd32015447b727df935d1744081950656d2163413e2f2068e698fcc96b8f53"
    "d20b1c0763db01b5c863c153608c6e0b10acdd21c66d91a0257dac324d838c379c67b5870417"
    "0000000001000000010000000000000000000000000000000000000000000000000000000000"
    "000000ffffffff5703af730d1a4d696e656420627920416e74506f6f6c206c025b03c8bfeefe"
    "01fabe6d6d3c78225bac22384a7f2abf4d741a6f11594908a4911200ab916851ab35b5744e10"
    "0000000000000000000f6c2655030000000000ffffffff06220200000000000017a91442402a"
    "28dd61f2718a4b27ae72a4791d5bbdade78723a61b130000000017a9145249bdf2c131d43995"
    "cff42e8feee293f79297a8870000000000000000266a24aa21a9ed306670ae3d122a55b3dd30"
    "186f716efe233809103922a2ad44e898e3f5c44e8400000000000000002f6a2d434f524501a3"
    "7cf4faa0758b26dca666f3e36d42fa15cc01064e3ecda72cb7961caa4b541b1e322bcfe0b5a0"
    "300000000000000000146a12455853415401000d130f0e0e0b041f1200130000000000000000"
    "2b6a2952534b424c4f434b3ad5af3c5f8756ab1121c080488d8b7600c668ccf0936fa7307fd4"
    "1311006db9cb0000000000000000000000000000000000000000000000000000000000000000"
    "000000000cb80b31b143f911d52c06ff92555ca2b26ce0793d23ca39aaa818ccf1f048b97d5b"
    "6db8fc24a1a057e12900c3c2f05145549f6769e756b221e6558d443485d4ff0439fe68b0fa3b"
    "fb92b666bb0d403184647530b01f0636d01995bf6ebe3bced9b4623aa33b2055b73105504c23"
    "784f7978803663485b86a5d5f82813fb34271a206287e6ab37fae575d5d5c1958bbaaaac1052"
    "c9334d13704a5c46435e92f2f592abea750651982e52cdc91ab648346810061cce59a860a47d"
    "ecc7c828abc27718be3a1c59ad5d53df1bb9ff9e40bd72abd5a1b8855009db97262ecfd8d509"
    "e79b6c070e36de4279260893a7de67af838d1bc71e5231c583b6aecbbb9168170f5e3181ca70"
    "d6b378e64bfa06551f0ac5a83aa489bd199b6deee754aa30ff0e5dc2bfc237ee13569b4c4aa5"
    "2507e2fb20e980356d03e060ace2c1240142f96a21d27b95543dbbe59e8985448a6cedd194ff"
    "e29ebff301f9386b4042093ee8447a28ca7c26e0ce116838ab45afaf769dd73db4a66300b81c"
    "710e198b808639370b00000000040a0000000000000000000000000000000000000000000000"
    "00000000000000007c71725c72079f0be81d299020c14a7cb6da9fb4306c1c4e1c5608c163c2"
    "cf8c2f4b0e0ef73baea80bef8a8bd0dc987cd5dc2090760cdc839ab1b78999d632dcec50b7df"
    "0c8357554d94c008137c0b7d890aed4c7f20873fd4180f54921a9d5e0b00000000c00d2054f9"
    "f3994d7b40fde93c13e6fc37ea18e7f93a3c920102000000000000000000cdad494e5894c2bd"
    "d1bdef14fb04286c1f4d477c50b0ae91448b2b781b6dc19f6c3e9c678a9a021776f4a7ce0501"
    "0000000001010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff0603088d0b0101ffffffff02291147250000000016001456fe57d24cf20cf69c544f"
    "adf547a97b16395ab20000000000000000266a24aa21a9edf4a64f10fc4b94ba98f7ebc26e2a"
    "38fb72393010830ac717cdc3bb9bd31c564b0120000000000000000000000000000000000000"
    "00000000000000000000000000000000000001000000013c03338412838c87cf1acbfad418f8"
    "4b2a49ae8bd0822d169dc188fb60446eaa000000006a4730440220453a782aa5f3406ff28d46"
    "c8f11909ba1841685252b50c19ca1d52cab9c8e487022046cadd74f4eb7e876272c611c0afe8"
    "6b964945c730091b7e2857c4bc08036cf7012103a3af913c31e47f8a37ab5c734cef39534396"
    "b4ea916c7aecaecd019b69e6d263ffffffff01e65c3f25000000001976a9143018a3de0de6ee"
    "e9a3996c98a740148404f3f35f88ac00000000010000000910e555d10517fd522c4110d5f13e"
    "e32826027e9a300e36baffaa638690625627010000006a473044022034a1312293c979774fb9"
    "ba2509426fa9bbe819cba8b264270ee4a5e2092c0be9022072005badd0c3ac0682221d0c1e11"
    "f4eaf8a6268531479a2ae8c990796fe63e44012103cc12ccd00272f1a875593048e0070daac3"
    "6dcd557744ab1e6cbde03d8f9d413affffffff09e90ab262f0f3e3fd75e3abc288c5696de8be"
    "b9dd92127d32f441072973939c010000006a47304402207bcf202252cca68ef1208c6d353dbf"
    "3708edc6e77b8c49140f642923c6db63a6022037d148d099ad1fd524d60d87e8f5d6decf0450"
    "2f4ba2aefb922755aaeb23c87d0121038876dae5f722296b06f00ab6ab46d28cb0988254c21d"
    "1a21fb390a946c94c890ffffffff1a8313be9d9fb9861b86870841fe035f2835dbf93a1e99c1"
    "6edbcce4b406aa8f010000006a4730440220715c186110c6bd350bd7f87cdc9c8ade0ff16397"
    "8dba6fad45f747f35318633402201b1bdb5d2fe33c810a4a8da97ae34018196fc0054328570b"
    "d5c01e628e2b080e0121021720ac8a6abff49a22b9d4b049fa7a922e65741fc9781198de9fd7"
    "2b86feef6effffffff9d978db61dc429224f3b5f9efb8ad7735cc653d0353eeb753aa250f3d9"
    "ae71f0010000006a47304402201676aab31c6d65c8f9927af5745aed27b15b5fd7d3cc03c2d0"
    "24c8f73e038c9002206b52f7bee645e4169ec42043924d808aaaf33c20a05dca8ec2d0bbe877"
    "4a741a01210355c5829fa470307f54bab243f667b8cd2dd1fdd0d98c7774dd1aa5c45256c199"
    "ffffffffb86fdfe9b8f16f233ef02eaf89fcfaa28745c092634716abd49f373649884e390100"
    "00006a473044022066d5197bb78efd8028131cb88e8b3f8af36efb8f9406441316fc1cbd5ea4"
    "79d7022049d19aa73233e1eb4cc14663b33f447c25af0fb74718e0cd7e2529c24c2738e60121"
    "0397eb96b2e555398d0ae7cedf319d4a2e20a045902b33f288abe3a698e84deaefffffffff33"
    "9ee0d76f0b15af47d231dc4b64febfe10cd57b84965fdafae142875c6974f3010000006a4730"
    "4402203876fc1f4e6686a4dd2781af0e728fe2fdf1885e49ac8b271a7566367840ff4902206b"
    "239a109ee8a840293fd9ad929c3585872fd7b98ffa59f10a211246942370840121038b2ad67b"
    "35f42935f0b585dcc6376b47534848c59439624f02b8dbbc2dd2f290ffffffffd9e2f734471c"
    "3c725ac3e7744a492126e2bd71828a03150b5474c1878106f92701000000694630430220704d"
    "6d9066647d6a988c2c79c5342b0bc513e8ec79846680e0ca8b2764033132021f57e5e3886b5c"
    "160e61816b4b8f699ef83140bbf2fd6f12386ed72623ca5181012103b187c8d994253603dfd1"
    "3e389b9648e0160f4c6c32d90e86bdbd17070103a352ffffffff7f617b9747a65e9d7ffee8ab"
    "39a58db98054abeb9a9d787120ec7289cba488f6050000006946304302202f9e2bd66f56851a"
    "f19aad03aa166294de16b22defcb9af518a89601fd5199b5021f38d6453663916d58821e6226"
    "fe29d7654316b46088ff4e7a63d6982c648cde012103362aa4f5c32bc2989276b92ae06cee12"
    "599925a5ff04573aa43e068b48b8b971ffffffff1a8313be9d9fb9861b86870841fe035f2835"
    "dbf93a1e99c16edbcce4b406aa8f000000006a47304402201cca5f5fdce3d7ef99ed39b48fbc"
    "bf6f7bcf23bb61ee3b8f1c980b089cf5c1690220063a0a7f8561fd92acdcf7a46ee2f9e998e8"
    "11e88c38881914d0ffaa1bda3fd0012102e2dc925e7b125b1255eac3d1ff482f2685eb17f6b5"
    "89c7307bb8b84e68d37d37ffffffff0770fa3973000000001976a9142afb39673f8657227b67"
    "2abd1c41572bcf23fe1388ac08859507000000001976a9141428759c26980752f231d1207bea"
    "58f48b98849488acad80200f000000001976a9146889379f34c56289c4ba614397fd84c55784"
    "ecf288ac57e90002000000001976a91476c3b49ddb2d7aa7eb1573dc32e832d2e2075ea888ac"
    "7c27b614000000001976a914ef31f0bed77de4f59d49a618560c1931029d896a88aca7789900"
    "000000001976a9144135b2614ed11e49d9fe3993232eb825792d800188ac93c9022a00000000"
    "1976a9144b0f620c1f404badcdfe5b07e69a639852db9a6888ac0000000002000000018ef1d7"
    "38804346f02d7423a480dadbe8a7366b15529d93ed057f52f825c8e99301000000db00483045"
    "022100c4cc6a19ac492081f1e4960908ad58ac4075d1d8237adf5d37cb24164978b573022076"
    "79bee5533f8f6c417475169bbe4ff60a3fa3dc73bd95e7c00fafdb0bd906f001483045022100"
    "8ef67433c0251a89d2a82a62a85f93a409491577639295f09e29ea44d63c483802203c5383b3"
    "7493455dbe246ff11537b4261370b8689cf87c88a2e28f9ea50921350147522103d40b1741da"
    "0fd448bd75b061b9a3d9afbf506ace4a61c5022116dda510861649210293844d5d24812dda76"
    "87aaf8f6282114d4dea54781e6d9b9c64e0635484e64f552aeffffffff02283d330900000000"
    "1976a9140040a8f5cc10e7aae8c0d40c596a8b5ce8701f3b88ac5e04b8600000000017a91435"
    "b75104b63305d5df86bc4887f6bb31e67b4b6e87000000000100000001ea906ab2d446f3e0f6"
    "741d2924912d79561cc325caa0155e1e296ef49ac7b3ed010000006b483045022100c44266c9"
    "1eb93962c62fba32ca73f6e078530acf6d5c98fc135a36dfc240c7cb022002a5e2fad87076c7"
    "ff2d154dbf87147d173a157176cfc2eb86ca86c944f6fa0d0121039bc9afdb66122a724e006c"
    "a1ac599aac7cfcaf99f210eb33ba766d55b5d2a23effffffff0245770401000000001976a914"
    "08fb4caf2c30dd62f7dca7be9bf0118ed5011f7b88acbaa1a248000000001976a914658064f8"
    "3e1d7d0ca38598452c3125a1b4b9affb88ac00000000"    ;

TEST(NmcP1AuxPowWire, MainnetBlock757000RoundTrip)
{
    PackStream ps;
    ps.from_hex(NMC_BLOCK_757000_HEX);

    const std::byte* const base = ps.data();
    const size_t total = ps.size();
    ASSERT_EQ(total, NMC_BLOCK_757000_HEX.size() / 2);

    // --- 80-byte NMC block header -----------------------------------------
    BlockHeaderType hdr;
    ps >> hdr;
    const uint32_t version = static_cast<uint32_t>(hdr.m_version);
    EXPECT_EQ(version & 0xffu, 0x04u);     // base block version 4
    EXPECT_NE(version & 0x100u, 0u);       // auxpow flag bit set
    EXPECT_EQ(version >> 16, 1u);          // chain_id == 1 (Namecoin)
    EXPECT_FALSE(hdr.IsNull());

    // --- CAuxPow blob ------------------------------------------------------
    AuxPow ap;
    ps >> ap;
    EXPECT_FALSE(ap.parent_header.IsNull());      // real BTC parent header
    // The parent coinbase is tx 0 of the parent block, so its CMerkleTx
    // nIndex is always 0. (The embedded CMerkleTx hashBlock is legitimately
    // left null in real auxpow blobs -- parent linkage is carried by the
    // separate parent_header field below -- and the round-trip memcmp proves
    // we preserve that zero verbatim.)
    EXPECT_EQ(ap.parent_coinbase_index, 0);

    // Re-serialize and require byte-for-byte reproduction of the mainnet
    // auxpow region [80, 80+auxlen). External-truth round-trip: any deviation
    // in field order / int width / witness stripping diverges here.
    PackStream out;
    out << ap;
    const size_t auxlen = out.size();
    ASSERT_LE(80 + auxlen, total);
    EXPECT_EQ(0, std::memcmp(out.data(), base + 80, auxlen));

    // The auxpow must consume exactly up to the block tx vector: at least one
    // more byte (the CompactSize tx-count) follows the auxpow region.
    EXPECT_LT(80 + auxlen, total);
}

}  // namespace
