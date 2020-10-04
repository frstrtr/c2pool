#include <string>
#include <vector>
#include <uint256.h>

//TODO: MerkleLink.index -> IntType(0)?????
//TODO: HashLinkType.extra_data ->  FixedStrType(0) ?????



//VarIntType = unsigned long long
//IntType(256) = uint256
//IntType(160) = uint160
//IntType(64) = unsigned long long
//IntType(32) = unsigned int
//IntType(16) = unsigned short
//PossiblyNoneType(0, IntType(256)) — Переменная, у которой 0 и None/nullptr — одно и то же.

namespace c2pool::shares
{
    enum StaleInfo
    {
        None = 0,
        orphan = 253,
        doa = 254
    };

    class HashLinkType
    {
        std::string state;      //TODO: pack.FixedStrType(32)
        std::string extra_data; //TODO: pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
        unsigned long long length;             //pack.VarIntType()
    };

    class MerkleLink
    {
        std::vector<long long> branch; //TODO: pack.ListType(pack.IntType(256))
        int index;                   //TODO: pack.IntType(0) # it will always be 0
    };

    class SmallBlockHeaderType
    {
    public:
        unsigned long long version; // + ('version', pack.VarIntType()),
        uint256 previousBlock; // TODO: none — ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
        unsigned int timeStamp;           // ('timestamp', pack.IntType(32)),
        unsigned int bits;  // ('bits', bitcoin_data.FloatingIntegerType()),
        unsigned int nonce; // ('nonce', pack.IntType(32)),
    };

    class ShareData
    {
    public:
        uint256 previous_share_hash; //TODO: none — pack.PossiblyNoneType(0, pack.IntType(256))
        std::string coinbase;
        unsigned int nonce;       //pack.IntType(32)
        uint160 pubkey_hash; //pack.IntType(160)
        unsigned long long subsidy;     //pack.IntType(64)
        unsigned short donation;    //pack.IntType(16)
        StaleInfo stale_info;
        unsigned long long desired_version; //pack.VarIntType()
    };

    class SegwitData
    {
        //SEGWIT DATA, 94 data.py
    public:
        MerkleLink *txid_merkle_link;
        uint256 wtxid_merkle_root; //pack.IntType(256)

        //InitPossiblyNoneType
        SegwitData()
        {
            //TODO: txid_merkle_link=dict(branch=[], index=0)
            //TODO: wtxid_merkle_root=2**256-1
        }
    };

    class ShareInfoType
    {
        ShareData *share_data;
        SegwitData *segwit_data;

        std::vector<uint256> new_transaction_hashes; //pack.ListType(pack.IntType(256))
        //TODO: std::vector<???> transaction_hash_refs; //TODO: pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        uint256 far_share_hash; //TODO: none — pack.PossiblyNoneType(0, pack.IntType(256))
        unsigned int max_bits; //bitcoin_data.FloatingIntegerType() max_bits;
        unsigned int bits;     //bitcoin_data.FloatingIntegerType() bits;
        unsigned int timestamp; //pack.IntType(32)
        unsigned int absheigth; //pack.IntType(32)
        uint256 abswork;   //pack.IntType(128)
    };

    class ShareType
    {
    public:
        SmallBlockHeaderType *min_header;
        ShareInfoType *share_info;
        MerkleLink *ref_merkle_link;
        unsigned long long last_txout_nonce; //IntType64
        HashLinkType *hash_link;
        MerkleLink *merkle_link;
    };

    class RefType
    {
    public:
        std::string identifier; //TODO: pack.FixedStrType(64//8)
        ShareInfoType *share_info;
    };
} // namespace c2pool::shares