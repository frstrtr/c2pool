#include <string>

namespace c2pool::shares
{

    class HashLinkType
    {
    };

    class MerkleLink
    {
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

    class ShareInfoType
    {
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