#ifndef SHARE_H
#define SHARE_H

#include <string>
#include <shareTypes.h>
#include <memory>
#include <tuple>

namespace c2pool::config
{
    class Network;
}

using std::shared_ptr, std::string;
using namespace c2pool::shares;

namespace c2pool::shares
{
    class Share
    {
    public:
        int shareType;        //pack.VarIntType()
        string shareContents; //pack.VarStrType()

        void load_share(/*in parameters block*/ Share share, string net, std::tuple<std::string, std::string> peerAddr, /*out parameters block*/ share_versions[share['type']](net, peer_addr, share_versions[share['type']].get_dynamic_types(net)['share_type'].unpack(share['contents']))){

        };
    };

    class BaseShare
    {
    public:
        BaseShare(shared_ptr<c2pool::config::Network> _net, std::tuple<std::string, std::string> _peer_addr, ShareType _contents);
    public:
        int VERSION = 0;
        int VOTING_VERSION = 0;
        // auto SUCCESSOR = nullptr; // None //TODO

        auto gentxBeforeRefhash; //TODO: gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

        int gentxSize = 50000; // conservative estimate, will be overwritten during execution
        int gentxWeight = 200000;

    public:
        shared_ptr<c2pool::config::Network> net;
        std::tuple<std::string, std::string> peer_addr;
        ShareType contents;

        std::shared_ptr<SmallBlockHeaderType> min_header;
        std::shared_ptr<ShareInfoType> share_info;
        std::shared_ptr<HashLinkType> hash_link;
        std::shared_ptr<MerkleLink> merkle_link;
        std::shared_ptr<ShareData> share_data;
        uint256 max_target; //TODO: arith_256?
        uint256 target; //TODO: arith_256?
        unsigned int timestamp;
        uint256 previous_hash;
        //template for new_script: p2pool->test->bitcoin->test_data->test_tx_hash()[34;38 lines]
        auto /*TODO: char[N], where N = len('\x76\xa9' + ('\x14' + pack.IntType(160).pack(pubkey_hash)) + '\x88\xac') */ new_script;
        unsigned long long desired_version;
        unsigned long absheight;
        uint128 abswork;
        uint256 gentx_hash; //check_hash_link
        c2pool::shares::Header header;
        uint256 pow_hash; //litecoin_scrypt->sctyptmodule.c->scrypt_getpowhash
        uint256 hash;
        uint256 header_hash;
        std::vector<uint256> new_transaction_hashes; //TODO: ShareInfoType && shared_ptr<vector<uint256>>?
        unsigned int time_seen;
    public:
        
        /*TODO: return type*/ auto generateTransaction(
                                auto /*tracker type*/ tracker
                                 /*cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None*/
                                 /*out parameters block*/
                                 /*share_info, gentx, other_transaction_hashes, get_share*/){};

        // @classmethod
        void getRefHash(shared_ptr<c2pool::config::Network> _net, auto shareInfo, auto refMerkleLink)
        {
            return 0; //pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(identifier=net.IDENTIFIER, share_info=share_info,))), ref_merkle_link))
        };

        // class initialization constructor __init__(self...)
    public:
        /*type?*/ check(/*type?*/ tracker, /*type?*/ otherTXs = nullptr){

        };

        //TODO: [wanna this?] /*type?*/ void as_share;
        //TODO: [wanna this?] /*type?*/ asBlock(/*type?*/ tracker, /*type?*/ knownTXs)
    };

    class NewShare : BaseShare
    {
        /*type?*/ VERSION = 33;
        /*type?*/ VOTING_VERSION = 33;
        /*type?*/ SUCCESSOR = nullptr;
    };

    class PreSegwitShare : BaseShare
    {
        /*type?*/ VERSION = 32;
        /*type?*/ VOTING_VERSION = 32;
        /*type?*/ SUCCESSOR = NewShare;
    };

    class Share : BaseShare
    {
        /*type?*/ VERSION = 17;
        /*type?*/ VOTING_VERSION = 17;
        /*type?*/ SUCCESSOR = NewShare;
    };
} // namespace c2pool::shares

#endif //SHARE_H