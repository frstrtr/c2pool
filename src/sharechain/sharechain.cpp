#include <string>
using namespace std;

class Share
{
public:
    int shareType;        //pack.VarIntType()
    string shareContents; //pack.VarStrType()

    void load_share(/*in parameters block*/ Share share, string net, /*addr*/ peerAddr, /*out parameters block*/ share_versions[share['type']](net, peer_addr, share_versions[share['type']].get_dynamic_types(net)['share_type'].unpack(share['contents']))){

    };

    bool is_segwit_activated(int version, string net)
    {
        //assert not(version is None or net is None)
        // segwit_activation_version = getattr(net, 'SEGWIT_ACTIVATION_VERSION', 0)
        return 0; //version >= segwit_activation_version and segwit_activation_version > 0
    };
};

class SmallBlockHeaderType
{
public:
    int version;       // ('version', pack.VarIntType()),
    int previousBlock; // ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
    int timeStamp;     // ('timestamp', pack.IntType(32)),
    float bits;        // ('bits', bitcoin_data.FloatingIntegerType()),
    long int nonce;    // ('nonce', pack.IntType(32)),
};

class BaseShare
{
public:
    int VERSION = 0;
    int VOTING_VERSION = 0;
    int *SUCCESSOR = nullptr; // None
    SmallBlockHeaderType smallBlockHeader;

    Share *shareInfoType = nullptr; // None
    Share *shareType = nullptr;     // None
    Share *refType = nullptr;       // None

    auto gentxBeforeRefhash; //gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

    int gentxSize = 50000; // conservative estimate, will be overwritten during execution
    int gentxWeight = 200000;
    int *cachedTypes = nullptr; // None

    // @classmethod
    void getDynamicTypes(/*in parameters block*/ /*this?*/ cls, auto net, /*out paarmeters block*/ auto cachedTypes, /*dict*/ t)
    {
    }

    // @classmethod
    void generateTransaction(/*in parameters block*/
                             /*cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None*/
                             /*out parameters block*/
                             /*share_info, gentx, other_transaction_hashes, get_share*/)
    {
    }

    // @classmethod
    void getRefHash(/*this?*/ cls, auto net, auto shareInfo, auto refMerkleLink)
    {
        return 0; //pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(identifier=net.IDENTIFIER, share_info=share_info,))), ref_merkle_link))
    }

    // class initialization
};

class Sharechain
{
};