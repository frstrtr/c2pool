// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BCH CTOR order vs a real mainnet block (rides
// bch_g2_block_assembly_roundtrip_test).
//
// Block 000000000000000000d6288d26aa2a7ed30a0d1cb8f7a87025bd1c427b294bf9
// (height 957699): 14 body txs, 4 inputs spending txs of the same block (one
// child sorts before its parent). Fixture = the 80-byte header, the coinbase
// txid, and each body tx (txid + raw bytes) in block order.
//
//   0. fixture: SHA256d(header) is the block hash, txid == SHA256d(raw), and
//      merkle_root([coinbase, body...]) is the header root;
//   1. the block order is ascending under uint256 operator<, a sort of a
//      reversed + rotated copy reproduces it, and a memcmp over the internal
//      bytes does not;
//   2. the txs fed to the Mempool in REVERSE order come out of TemplateBuilder
//      in block order: m_hashes, transactions[].txid and transactions[].data;
//   3. the fold of the real coinbase txid over
//      stratum_merkle_siblings(m_hashes) is the real header root.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/merkle.hpp"
#include "../coin/template_builder.hpp"
#include "../coin/transaction.hpp"

namespace {

int g_fails = 0;
#define CTOR_CHECK(c) do { if (!(c)) { \
    std::cerr << "  FAIL: " #c " @ ctor_real_block_kat_test.cpp:" << __LINE__ << "\n"; \
    ++g_fails; } } while (0)

const char* kBlockHash = "000000000000000000d6288d26aa2a7ed30a0d1cb8f7a87025bd1c427b294bf9";
const char* kHeader =
    "00a09d212104c157b629340b1900f7635d4424ff8e86e24e2b2573010000000000000000bcaae488c9a19d77f05ebd4399abed9c7a682b82abf44f61116e5e18de7a1bba21e9446a6b6002184a295570";
const char* kCoinbaseTxid = "db2ca21db29b0fe3cbff499eea61891b676e0c89f2e6a636d1ff75ab6ebf813f";

struct BodyTx { const char* txid; const char* raw; };
const BodyTx kBody[] = {
    {"27fc84967965aa9efd36f960e72a966f8b6ab12f8f66a753ab1d332f4ed11bae",
     "020000000149e100e2ae4e1eb17627abb9ace0a42137a45c8f693fbaf715e146a43da4cb17010000006a47304402202e0bef936d39f22e71aba8d45118eb3fa6ce72a5acc1eac75fcd4a445a77c8830220454f9e766840a25a802e945e579bb050d148dd85a65bcb39ba084d33c7b2795641210228adaada81fde5c958a0a8a059438da7952dafd3bc87d6a1c044cc67d10098a3ffffffff028c513b03000000001976a914855e04d684d2691f5524ce56b6c3e4929b63c5cc88ac2b60db01000000001976a914224cc1ab658861ecedb3cbcab07f07797a770e3e88ac00000000"},
    {"4749c4c29ce27d44587966bc7e1a96dcbf765c5061e1f32ccc3ea98b4fb97051",
     "0100000001bdbd4a1801c59788ec808efdfba03e3393967fd0358579b251d09541c5ec3e1f01000000fdfe0000483045022100d1a6a9dd4ff7230eccb61398e4c72d94655023424b6a1cc7856370dceedde22d02201bd4769336e84f1f32c8fa8572a05082697f394dc8cc96575ca1e359513a662841483045022100d2ac1feae2e674469c95a50487452ee2e62985be8ce7fa98c29fbe70db8a3621022034781c77607d1924b3b926440e30d524cd3d08062ca3ffd036757420eee61eef414c69522103e158e9d6adfcb379155a13fdba1051f270ba8167193fffa1f321e46bf18b2b872102364a768c4e314ff6750cc33f4a5789cb4fe55467a5d06da9be9800cbf3b76a9e210295d1788a891cb70ec8b91b908174cc16db2dc3fbbeb2279b84e19f19d28400ff53aeffffffff01c2fa2403000000001976a914e3c3c04e6feb9fd383aa8eb88211c4cf6012ffcc88ac00000000"},
    {"5f702896351963a2b5b648ad48f5e997451fa1c68d77676dd7133a8a83b511f9",
     "01000000027b43a6d501804e056d54c3271ad57bc17cb75c832d5aa6b56e02640ddbbfb371000000008a47304402205732c334901ccdf2565bc3d5638c9a6901cb9cf8f809542e5f9cae473c5af331022009473d33e87541b1f9b675af65ec34a69144fe86e68bbc552dbed884eb4b6ef24141044524bcce9ee0eb3c1c532568a47a7ebfe8b31dc109c4dccc3f4bf5b07ad7f5eb4561b9e283f7ef6a3b6911db30da7ca827e2c94ffdf79cca3fa40e2c7114af5affffffffea3653e136e3e5f48df7bccd6c1f887ee31864c61596e57a4616708e51dc2f1a010000008b4830450221009b08e552ec654d9244f807c09f9396df26eb5a4a4479e121082f5f6a64fc4af102202acd4d8a94e6f16a7b0b49d16f1ae31b1b0a3f7d56b4b3ce0a469e3c5eb8bf594141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8ffffffff038bbb2200000000001976a91488d9f6ca2109801f2108e4c9a0c455800e0c371a88ac0556da00000000001976a9148b80536aa3c460258cda834b86a46787c9a2b0bf88ac0000000000000000326a0402446365512071b3bfdb0d64026eb5a65a2d835cb77cc17bd51a27c3546d054e8001d5a6437b040000000004008e51ab00000000"},
    {"71b3bfdb0d64026eb5a65a2d835cb77cc17bd51a27c3546d054e8001d5a6437b",
     "0200000001c5611fffe99e12117719b1b5ed52bf6c9a0bb2c7afd6133a574c579a946a1388010000006b483045022100c21ac2ff1af0b7df2ec354bc0351575df234c4db84a38fba535a1ffad3621dda022010b3e16a3359f9329838184bc1d7385a6d51845938cbef01cb0248d01d016eb1412102b0bf7e88a23ac485d3758f8686ca38f025eeb15d94781da4fe3f853f64614a9efdffffff025f1d1a00000000001976a9148b805038c9869989fdd3c02f196c61dd7a0c093b88ac3c71aa12000000001976a9147a91891f694536600db5134e58414f21ae2e823788ac00000000"},
    {"7c138e42f7d35f3c83858c44e335d90ab7ea859f2917cde575ab48cedbff820b",
     "01000000023f611689599081673570c8b3fb1a275d5fbc22db4caf9362bd9f62ef98a41f1c000000006a473044022016c14605d04867d76380ab51b46d898756cbeef18dfd79362dd9bb60dad4693d0220237a878901ff67e0d3d6e157be6d8d0528b831a5b7e3abee6b073a709a843a2941210250f12d91944ec67c5c91093e6e8660d072775814f7cdf7703c5fca351d66456effffffff33fd0b50c24b61096e29c5d7ca4b25c78d8b33642e96778fcdc0c24e300315e5010000006a47304402200ffff141726076efd8f79e0ffa3a6ab854eaa1b8f369849b9423580e6dcf6b92022047e10aa373bbbfac2d478e505445d0626cd1d1b7803bb01ffa4c82e9e429e4a241210250f12d91944ec67c5c91093e6e8660d072775814f7cdf7703c5fca351d66456effffffff023073f91c000000001976a914510e05cd25890c0d2ce28b6f2825f854d9ac5af188ac6c48265a030000001976a9145ea3cfff9c69374d94e95b0838aea78549fb541a88ac00000000"},
    {"8c1923eadb9ff1370f3634642d367f35a57d1ec7e652702e503e74e93275a491",
     "0200000002f911b5838a3a13d76d67778dc6a11f4597e9f548ad48b6b5a26319359628705f000000006b483045022100ad3d464e6d0a6c9921e146c4ea87dca00055cc8b7a1f81c97ed3b36bc4087530022017ff1ba49c8ac7307abce3affabb2eef38b7de00dc02ea76dd467881e269ea27412102b0bf7e88a23ac485d3758f8686ca38f025eeb15d94781da4fe3f853f64614a9efdffffff7b43a6d501804e056d54c3271ad57bc17cb75c832d5aa6b56e02640ddbbfb371010000006b483045022100cd5ce6d3f88ff6c3d467a4eead80764f5883219e51b69882e75781e11b301316022061d3b1699c606b45a2abc2e6145cb87116d3fcbdbb4fdab4854b838739267e3e412103d49c781b204610ab422c54d339572c8f70e2af6f189d97cd582a2c64b278bd86fdffffff021f329002000000001976a9148b805038c9869989fdd3c02f196c61dd7a0c093b88ac30f93c10000000001976a914083e44cb8b7d168f7a89236d7702d243d36528de88ac00000000"},
    {"a3966ab8d56ff0fd2f83e8e0bf8fdb85a995c23da851965762a29b165842d77d",
     "0100000001cc0fd60deb444ee813d29c075005a6900a686702c1951995d639acd87f9ab3c4000000006a47304402205936d10b81ab0d75f9a2d0dcf7fab086df40951e2c1cfec17e59493dbe8e4860022075490692f75bd9182090bb9ccbe1d374680276e6d7adafddbf697e5a8473f2aa4121029d1eb4bb16546f1c0cbff0c2f4eeae059430ce139a9e477f0f2572908f87f36cffffffff0116ea0601000000001976a91451e7c7d3e5db09fd77c4f9606a9129b03390809188ac00000000"},
    {"a727ad2d873a81e44f38f858ef54f36944e21c3a5bbe6666ddb5180f5042b275",
     "010000000391a47532e9743e502e7052e6c71e7da5357f362d6434360f37f19fdbea23198c000000008a473044022054828f2810b804048df325d66b7630b2a506acd94ae1cac36be855c09226ed7702204709850439bb8c598ebc811bc0f4ae8929da7145af07e04d68243f970ea9effb4141044524bcce9ee0eb3c1c532568a47a7ebfe8b31dc109c4dccc3f4bf5b07ad7f5eb4561b9e283f7ef6a3b6911db30da7ca827e2c94ffdf79cca3fa40e2c7114af5affffffff0d09f8f5482a30b6243c4d7aabf630dd21e92fa47ba21de8418a7e10ccb2b11e010000008a47304402202b7c39ac6a007ae94e696207579723bfe017493255b69cdca7153238c4b6757b02204c2cdb5c3273f0fff7853063240f734f20d1483bbeef501a348704d4e4dd16f14141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8ffffffff08f170bdcbcab8018c33adec3e22dbb4d463ed0b9635dd29c8afdbbd01c531ed010000008a47304402202c170f3d50a94f83dc854b3dd5d47aca4b3399a114e446a0c9d62a379965697f022025977dd4ca1d994d3b4ef02feef258a26f16cc87962819cd3d0b1631879d31814141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c34fdd793cfc8ffffffff038abd6803000000001976a91488d9f6ca2109801f2108e4c9a0c455800e0c371a88ac731cbd00000000001976a9148b80536aa3c460258cda834b86a46787c9a2b0bf88ac0000000000000000326a040244636551208c1923eadb9ff1370f3634642d367f35a57d1ec7e652702e503e74e93275a491040000000004008e51af00000000"},
    {"bdaa9802b60a2c2acef3191c17f8d3094d5761f7df6f057b3c7a88db3c09a693",
     "0200000002223dfc38ab1dad937c8c6259bc23f7635b5e2416729b7336d5b515d9873626a9010000006b483045022100dfce3a86d9a051f8bb808b9f9b67d80dd6b4a45584ba247b2dcf6501fad88ee0022050b08754d4a70dcf0eb5ca7ec94f15812f00a549a17a8080cb021ec194ec66db412103963e22ebd71b82dfea87edd27062bb7cc2b60da23632ae34d344262f4c63b89bffffffffb799580251f297d56383c0013a0b427c98240993ca32a8641687a604cdc82a6e000000006b4830450221008c7e2799f82b3481cd78502bc5e22be14af9a7e45f0aca923b1ceb2e3180df0902205de433f33de4ca76586df7a884ad54b8471fb5566ecb38c7c951100c3a14b18a412103963e22ebd71b82dfea87edd27062bb7cc2b60da23632ae34d344262f4c63b89bffffffff02006e2e12010000001976a91429bc68205a7d9d43f3c6a2252a813b05b618a9e688ac91709002000000001976a9147e3224747d37ddfd2b49fb6f1ca1e875f755740288ac00000000"},
    {"bf5f6fba2d01fee46d40c95b26a81cbde76443f7aca357b3cd22030e377ed66a",
     "0100000001b492399078f1139ea758ea1438082bf95804f003731b891605cf4f4086f782d8000000006b48304502210097552b2f6a44968f590cc43be34c046fb1f33de6f7f85a81b9311b49357b9b580220569494b1eb0e363c1b121e5c007fb8f83bdee19d5638aac7fd31f028825cd830412102bb936363cdc6436ebaba9fa49b8557c117b87d66ec53412fd9eacdecb426dd8affffffff0118925600000000001976a914dada6e90f29c285791f4786527019bd5773dfcf388ac00000000"},
    {"c410fc527ce08a0eb430db547b5fa2667980ba8374159a7917343d0516ca7cf8",
     "0200000001526e02a68346be4d914c387481bf08e8b8fd7180e621a61bb8e1127b74509888010000006a473044022024695861c8b335de6b0e43174e18f84e2805139f374355f06c736192b00d945e02207d55ca8510a77d5aac663968a8177c38ccce5861ea0248aba03cc0b89c33a6c3412102e9c1323c9372d823578168b4bad20dfb2b042002b90104bc4ea2bb2d3fe3d0f8ffffffff02cf277e00000000001976a91456b223067327fe139c6f7fc7bdb089195eea690a88acc4ec126a000000001976a914132a8068d912e1b2030094a60ec9e4570006c19788ac00000000"},
    {"e6b757659de98cf05a727fe4d4dfc580e89f1614b34695e40d769ce7df5c26a2",
     "0100000001091c04ea8cbaee72a9363592a184418ee80e0973a7b02c7f1cf0427023681244010000006a4730440220440bf57b2f26c5209013e42b9b8abad42c0cb391b2222cf425b6f39cdabc4f58022030b18dc2369841d659c69cb25c86dc52bda5e23474b8edcf2ab91202f959dbad412103d8e0a12bcfc60eafbdcf7f34134573efcf6b5d2414560feda487e1d035eec00effffffff015ea3b407000000001976a914790785deaf222ea72074168c41f0b2efef82df4788ac00000000"},
    {"f7825051a7384595c74d275a04b960c06f837e63b5c3ede429512366ac2a4abf",
     "020000000170e7df5d0ad297f9c8dbe5a11fa59ee9a0a4ab479b55b0c0601645c9dc8bc508010000006a47304402203ce98ee32db09f89ec9842ef7aa65798c1dc0b8e6d60b53fb7d14fa8e1dd6eab0220601c0e5308a342b6742eb35b4bf46a0c0e7315e92f879dc0c5a924662c487826412102a1ece326db0889fbee98e9202a20ec85215d7cdad55186778b6f21a946dbeaeaffffffff024718831b000000001976a9146c3fb5232abd42ca065eca40617b772fd401f27188acb7707526000000001976a914bc5b45979de1b9bb479add17c541233938c345ad88ac00000000"},
    {"fc023fa7023bafa6603880f2cc2473aab58b0e5ab5d873986625fe2404e4e11b",
     "0100000001bfdb704f0775e7391359d2ff213ef4ebd28a78de15eecb48b6bc965376e4a058010000006b483045022100df9213762938e858e46d6c22127ea00450c128f36770dba4c212c8888c4f39180220169388d12f7fab512a6a57d65b7432963b159f96551c4b4064762ca67e258c89412103937eca759358b6216502b8bacd4f8a90b0f55cabcc739a967ef323e17db5bc93ffffffff02b81e0000000000001976a914c8bcd166db906e94467526b7950159f9df96f1ed88ac0873c702000000001976a914f0bbbee39e34b9c549cbb6c61781524872ab3bb788ac00000000"},
};
constexpr size_t kN = sizeof(kBody) / sizeof(kBody[0]);

uint256 from_display(const char* h) { uint256 u; u.SetHex(h); return u; }

uint256 header_root(const std::vector<unsigned char>& hdr)
{
    uint256 r;
    if (hdr.size() == 80) std::memcpy(r.data(), hdr.data() + 36, 32);
    return r;
}

} // namespace

int run_ctor_real_block_checks()
{
    g_fails = 0;
    const auto hdr = ParseHex(kHeader);
    const uint256 root = header_root(hdr);
    const uint256 cb = from_display(kCoinbaseTxid);
    std::vector<uint256> block_order;
    for (const auto& t : kBody) block_order.push_back(from_display(t.txid));

    // 0. Fixture self-consistency.
    CTOR_CHECK(kN == 14);
    CTOR_CHECK(hdr.size() == 80);
    CTOR_CHECK(Hash(std::span<const unsigned char>(hdr.data(), hdr.size())) == from_display(kBlockHash));
    for (size_t i = 0; i < kN; ++i) {
        auto raw = ParseHex(kBody[i].raw);
        CTOR_CHECK(Hash(std::span<const unsigned char>(raw.data(), raw.size())) == block_order[i]);
    }
    std::vector<uint256> leaves{cb};
    leaves.insert(leaves.end(), block_order.begin(), block_order.end());
    CTOR_CHECK(bch::coin::compute_merkle_root(leaves) == root);

    // 1. Comparator.
    CTOR_CHECK(std::is_sorted(block_order.begin(), block_order.end()));
    std::vector<uint256> shuffled(block_order.rbegin(), block_order.rend());
    std::rotate(shuffled.begin(), shuffled.begin() + 5, shuffled.end());
    std::sort(shuffled.begin(), shuffled.end());
    CTOR_CHECK(shuffled == block_order);
    std::vector<uint256> memcmp_order = block_order;
    std::sort(memcmp_order.begin(), memcmp_order.end(), [](const uint256& a, const uint256& b) {
        return std::memcmp(a.data(), b.data(), 32) < 0;
    });
    CTOR_CHECK(memcmp_order != block_order);

    // 2. TemplateBuilder over the txs added in reverse block order.
    auto params = bch::coin::BCHChainParams::mainnet();
    uint256 cp;
    cp.SetHex("00000000000000000002c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee00");
    params.fast_start_checkpoint = bch::coin::BCHChainParams::Checkpoint{100000, cp};
    bch::coin::HeaderChain chain{params};
    CTOR_CHECK(chain.init());
    bch::coin::Mempool pool;
    for (size_t k = kN; k-- > 0;) {
        PackStream ps(ParseHex(kBody[k].raw));
        bch::coin::MutableTransaction tx;
        ps >> tx;
        CTOR_CHECK(bch::coin::compute_txid(tx) == block_order[k]);
        CTOR_CHECK(pool.add_tx_with_known_fee(tx, 1000 + k));
    }
    auto wd = bch::coin::TemplateBuilder::build_template(chain, pool, false);
    CTOR_CHECK(wd.has_value());
    if (wd) {
        CTOR_CHECK(wd->m_hashes == block_order);
        const auto& tj = wd->m_data["transactions"];
        CTOR_CHECK(tj.size() == kN);
        for (size_t i = 0; i < tj.size() && i < kN; ++i) {
            CTOR_CHECK(tj[i]["txid"].get<std::string>() == kBody[i].txid);
            CTOR_CHECK(tj[i]["data"].get<std::string>() == kBody[i].raw);
        }

        // 3. Stratum fold of the real coinbase txid == the real header root.
        uint256 acc = cb;
        for (const auto& b : bch::coin::stratum_merkle_siblings(wd->m_hashes))
            acc = bch::coin::merkle_hash_pair(acc, b);
        CTOR_CHECK(acc == root);
    }

    if (g_fails == 0)
        std::cout << "ctor_real_block_kat_test: all checks passed\n";
    else
        std::cerr << "ctor_real_block_kat_test: " << g_fails << " check(s) failed\n";
    return g_fails;
}
