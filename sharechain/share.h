#pragma once
#include "dbObject.h"

#include <string>
#include <shareTypes.h>
#include <memory>
#include <tuple>
#include <vector>
#include <map>
#include "uint256.h"

namespace c2pool::config
{
    class Network;
}

namespace c2pool::shares
{
    class OkayTracker;
}

namespace coind::data
{
    class TransactionType;
}

using dbshell::DBObject;
using std::shared_ptr, std::string;
using namespace c2pool::shares;
using std::vector, std::tuple, std::map;

namespace c2pool::shares
{

    template <typename ShareClass>
    ShareClass load_share(RawShare _share, shared_ptr<c2pool::config::Network> _net, std::tuple<std::string, std::string> _peer_addr)
    {
        ShareVersion type = (ShareVersion)_share.type;
        switch (type)
        {
        case Share:
        case PreSegwitShare:
        case NewShare:
            return ShareClass(_net, _peer_addr, _share.contents);
        default:
            if (_share.type < Share)
            {
                //TODO: raise p2p.PeerMisbehavingError('sent an obsolete share')
            }
            else
            {
                //TODO: raise ValueError('unknown share type: %r' % (share['type'],))
            }
            break;
        }
    }

    struct GeneratedTransaction
    {
        std::shared_ptr<ShareInfoType> share_info;
        //TODO: gentx
        std::vector<uint256> other_transaction_hashes;
        //TODO boost::functional: get_share()
    };

    class BaseShare : public DBObject
    {
    public:
        BaseShare(){};

        BaseShare(shared_ptr<c2pool::config::Network> _net, std::tuple<std::string, std::string> _peer_addr, ShareType _contents, ShareVersion _TYPE = NoneVersion);

    public:
        int VERSION = 0;
        int VOTING_VERSION = 0;
        ShareVersion TYPE = NoneVersion;
        // auto SUCCESSOR = nullptr; // None //TODO

        //auto gentxBeforeRefhash; //TODO: gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

        static int gentxSize; // conservative estimate, will be overwritten during execution
        static int gentxWeight;

    public:
        shared_ptr<c2pool::config::Network> net;
        std::tuple<std::string, std::string> peer_addr;
        ShareType contents;

        std::shared_ptr<SmallBlockHeaderType> min_header;
        std::shared_ptr<ShareInfoType> share_info;
        std::shared_ptr<HashLinkType> hash_link;
        std::shared_ptr<MerkleLink> merkle_link;
        std::shared_ptr<ShareData> share_data;
        uint256 max_target;
        uint256 target;
        unsigned int timestamp;
        uint256 previous_hash;

        //TODO:
        //template for new_script: p2pool->test->bitcoin->test_data->test_tx_hash()[34;38 lines]
        //auto /*TODO: char[N], where N = len('\x76\xa9' + ('\x14' + pack.IntType(160).pack(pubkey_hash)) + '\x88\xac') */ new_script;

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
        virtual std::string SerializeJSON() override;   //TODO
        virtual void DeserializeJSON(std::string json); //TODO

    public:
        //TODO: return type
        template <int Version>
        static GeneratedTransaction generate_transaction(c2pool::shares::OkayTracker _tracker, shared_ptr<ShareData> _share_data,
                                                         uint256 _block_target, unsigned int _desired_timestamp,
                                                         uint256 _desired_target, MerkleLink _ref_merkle_link,
                                                         vector<tuple<uint256, int>> desired_other_transaction_hashes_and_fees,
                                                         shared_ptr<c2pool::config::Network> _net, map<uint256, coind::data::TransactionType> known_txs, /*TODO:  <type> last_txout_nonce=0,*/
                                                         long long base_subsidy, shared_ptr<SegwitData> _segwit_data);

        // // @classmethod
        // void getRefHash(shared_ptr<c2pool::config::Network> _net, auto shareInfo, auto refMerkleLink)
        // {
        //     //pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(identifier=net.IDENTIFIER, share_info=share_info,))), ref_merkle_link))
        // };

        // // class initialization constructor __init__(self...)
    public:
        // /*type?*/ check(/*type?*/ tracker, /*type?*/ otherTXs = nullptr){

        // };

        //TODO: [wanna this?] /*type?*/ void as_share;
        //TODO: [wanna this?] /*type?*/ asBlock(/*type?*/ tracker, /*type?*/ knownTXs)
    };
} // namespace c2pool::shares