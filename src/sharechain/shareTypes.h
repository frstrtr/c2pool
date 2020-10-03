#include <string>
#include <vector>

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
        int length;             //TODO: pack.VarIntType()
    };

    class MerkleLink
    {
        std::vector<long long> branch; //TODO: pack.ListType(pack.IntType(256))
        int index;                   //TODO: pack.IntType(0) # it will always be 0
    };

    class SmallBlockHeaderType
    {
    public:
        int version; // + ('version', pack.VarIntType()),
        //TODO: type ???
        long long previousBlock; // ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
        int timeStamp;           // + ('timestamp', pack.IntType(32)),
        //TODO: type ???
        long long bits;  // ('bits', bitcoin_data.FloatingIntegerType()),
        long long nonce; // ('nonce', pack.IntType(32)),
    };

    class ShareData
    {
    public:
        long long previous_share_hash; //TODO: pack.PossiblyNoneType(0, pack.IntType(256))
        std::string coinbase;
        long long nonce;       //TODO: pack.IntType(32)
        long long pubkey_hash; //TODO: pack.IntType(160)
        long long subsidy;     //TODO: pack.IntType(64)
        long long donation;    //TODO: pack.IntType(16)
        StaleInfo stale_info;
        int desired_version; //TODO: pack.VarIntType()
    };

    class SegwitData
    {
        //SEGWIT DATA, 94 data.py
    public:
        MerkleLink *txid_merkle_link;
        long long wtxid_merkle_root; //TODO: pack.IntType(256)

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

        std::vector<long long> new_transaction_hashes; //TODO: pack.ListType(pack.IntType(256))
        //TODO: std::vector<???> transaction_hash_refs; //TODO: pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        long long far_share_hash; //TODO: pack.PossiblyNoneType(0, pack.IntType(256))
        //TODO: bitcoin_data.FloatingIntegerType() max_bits;
        //TODO: bitcoin_data.FloatingIntegerType() bits;
        long long timestamp; //TODO: pack.IntType(32)
        long long absheigth; //TODO: pack.IntType(32)
        long long abswork;   //TODO: pack.IntType(128)
    };

    class ShareType
    {
    public:
        SmallBlockHeaderType *min_header;
        ShareInfoType *share_info;
        MerkleLink *ref_merkle_link;
        long long last_txout_nonce; //TODO: IntType64
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