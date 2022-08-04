#include <gtest/gtest.h>

#include <libcoind/data.h>
#include <libcoind/transaction.h>
#include <btclibs/util/strencodings.h>
#include <libdevcore/stream.h>

const char* _data = "0100000000010232a417a23fcd43a983a44b35da54becf63e847231b8ec85108e25c1f0cd31a000100000017160014fac097f9703d4fc98c2900db3601f21f9a1aad1ffeffffff24b2de51a95460800c0ef0342e01fe4e02defc293a330fdb6c90f806cc282ac40100000000feffffff1f207c595f000000001976a9148187062887881cd021efc5937d6104182954d14388ac9cb90a00000000001976a9141fcf7716f095f5cacbfe86d5b27d0a6e4cc1414e88acabb90a00000000001976a9143805c07928a5d40c1748c0458e3dc21aff48412188acb00e99150000000017a9145c17463506dfb14d040c3889df3f08ca17c3f5278778b90a00000000001976a914c878108c50739e6d89d97ce07330478b3501abde88ac3d590b00000000001976a9147f75e68fc64b9dd116026fda9c0af036d98e404d88ac11ba0a00000000001976a914a37d265a788fc886c82f9e5390f5b639e073916a88ac83b90a00000000001976a914febd3de8b26edc4c33d049e7fba8fb21e8ec3f5b88ac85b90a00000000001976a914a1449f74947a8021354f2a83910dabf2dde88e3088ac88b90a00000000001976a9149099c11205425377c0f46a0c5c17b964d457b60d88ac3aba0a00000000001976a914d41dcc028571e6cc97b325a206aeced6b0d6c32988acc9b90a00000000001976a914bf3bbd4fd06c27a4d95be9febd6be66b8e7b9c4c88ac2f4a130000000000160014cf3d6918d4a6974721b20e10358e0451134c36d9e9b90a00000000001976a9141c7dafe71156be1f0b8e58a9065e307d2efebe8888ac90b90a00000000001976a914d0a6e3a19ae68f163c83555e4b020456859e600088ac82b90a00000000001976a9140393790f3c257c9f592d402d9c8e3f2f6a6aee0888acc0b90a00000000001976a914603897bfa99da5924997da87e87805560923dd2988ac98ba0a00000000001976a914fe7fa5e8907ce8bcee742611429207bad6efb70888aca83fd600000000001976a9148726de96b5f0f5efa5e8b552f3e3c270f9e72af188ac75b90a00000000001976a9143f35d78584044b1b0e5a277ddceb3f4bf7fd9da588acd0b90a00000000001976a914712db89e425150862cdf23777f025ce028189f3488ac83b90a00000000001976a91407d45d72c1b06fc13a0926a576a9089cda43218288ac80b90a00000000001976a9145143892483447a164a92a33a7ef834acc6ff3ff688ac60ae0a00000000001976a9144c60cd4026e2490f2676c95a9a556dba5284360688acf5b90a00000000001976a91437f59eea3d9a6c1577d079c44caf2b76af1a638e88ac80b90a00000000001976a9147735217bc605a23719bc21851b273bac5de9d88588ac81b90a00000000001976a914af7c4ac35d9f92abe7f4544a20826689b9b0448a88ac74b90a00000000001976a9149750df36e9d9541d96b5c3d60ae625447358c12e88ac75b90a00000000001976a914bbefd901a803246f2cb156c53c2ff850c58d525b88ac25ba0a00000000001976a914fa92ff5d88eb0098db00c8fa2c8ecd058d04812a88aca4b90a00000000001976a91496d82c9e9ebffb5e87249a659278776764f3c11f88ac0247304402207c8a9cfacdf5892b89009d382c3d1c1a7864303ebb7da69637b69b4fdf3bb328022021688e24543b1c6702b37d61751d284bf00f69960480b7b3030de1a75f7a6196012102d7f8c4e6cffeef6b04554c53abf4ec0fb63ab53ef59cef39b73f8055ea79da020247304402202522e5eb81f990828b9e52add7676174ac8ae370e4df02ec8149d4f218c8e8da02200b9b7af95215a678de48ccb80df61f6d4fa20d5b943e0dd15202c44e9f21f9180121035ff2c4781bc19092f5ca51df813fc72bc626688bf1720715740f913f1bae58ce6315d500";

TEST(TX_TEST, data_load)
{
	std::cout << "TX_TEST" << std::endl;
	auto packed = PackStream(ParseHex(_data));

	coind::data::stream::TransactionType_stream _unpacked;
	packed >> _unpacked;
	coind::data::tx_type unpacked;
	unpacked = _unpacked.tx;
}

// TODO:
/*
TEST(CoindTxs, tx_hash)
{
    vector<coind::data::TxInType> _tx_ins;
    coind::data::TxInType tx_in1;

    StrType unpacked_in_script;
    unpacked_in_script.fromHex("70736a0468860e1a0452389500522cfabe6d6d2b2f33cf8f6291b184f1b291d24d82229463fcec239afea0ee34b4bfc622f62401000000000000004d696e656420627920425443204775696c6420ac1eeeed88");

    std::cout << unpacked_in_script.get().size() << std::endl;
    tx_in1.script = unpacked_in_script.value;
//    std::cout << "tx_in1.Script: ";
//	for (auto v : tx_in1.script){
//		std::cout << (unsigned int) v << " ";
//	}
//	std::cout << std::endl;

    _tx_ins.push_back(tx_in1);


    vector<coind::data::TxOutType> _tx_outs;

    PackStream packed_out_script(ParseHex("ca975b00a8c203b8692f5a18d92dc5c2d2ebc57b"));
    IntType(160) script_num;
    packed_out_script >> script_num;
    auto _script = coind::data::pubkey_hash_to_script2(script_num.get());
    StrType unpacked_out_script;
    unpacked_out_script.fromHex(_script);

    coind::data::TxOutType tx_out1(5003880250, unpacked_out_script.value);
    _tx_outs.push_back(tx_out1);

    coind::data::tx_type tx = std::make_shared<coind::data::TransactionType>(1, _tx_ins, _tx_outs, 0);
//    std::cout << "tx.tx_ins.script:";
//    for (auto v : tx->tx_ins[0].script){
//        std::cout << (unsigned int) v << " ";
//    }
//    std::cout << std::endl;
//    //===

    PackStream result;
    coind::data::stream::TransactionType_stream packed_tx(tx);
    result << packed_tx;

//    for (auto v : result.data)
//    {
//        std::cout << (unsigned int) v << " ";
//    }
//    std::cout << std::endl;

    auto hash_tx = coind::data::hash256(result);
    std::cout << "HexStr: " << HexStr(hash_tx.begin(), hash_tx.end()) << std::endl;

    ASSERT_EQ(HexStr(hash_tx.begin(), hash_tx.end()), "b53802b2333e828d6532059f46ecf6b313a42d79f97925e457fbbfda45367e5c");

    auto arith_hash_tx2 = UintToArith256(hash_tx);
    arith_hash_tx2 += 1;
    auto hash_tx2 = ArithToUint256(arith_hash_tx2);
    std::cout << HexStr(hash_tx2.begin(), hash_tx2.end()) << std::endl;
}
*/

TEST(JSONRPC_DATA, data_unpack)
{
    std::string x = "01000000013ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff01c40965f0020000001976a9141462c3dd3f936d595c9af55978003b27c250441f88ac80feea62";
    PackStream packed = PackStream(ParseHex(x));
    uint256 txid = coind::data::hash256(packed, true);

//    std::cout << "TXID: " << txid.GetHex() << std::endl;
    ASSERT_EQ(txid.GetHex(), "3cd5e16cd8caff78cec651bb72b681bd4bb6d36a0069211242f6709ca9cff7bb");

    auto hex_data = ParseHex(x);
    for (auto _x : hex_data)
    {
        std::cout << (unsigned int)_x << " ";
    }
    std::cout << std::endl;

    coind::data::stream::TransactionType_stream _unpacked;
    packed >> _unpacked;

}