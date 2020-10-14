#include <string>
#include <vector>
#include <uint256.h>
#include <memory>

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
    public:
        std::string state;         //TODO: pack.FixedStrType(32)
        std::string extra_data;    //TODO: pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
        unsigned long long length; //pack.VarIntType()

        HashLinkType(){};
        HashLinkType(std::string state, std::string extra_data);

        friend std::istream &operator>>(std::istream &is, HashLinkType &value);
        friend std::ostream &operator<<(std::ostream &os, const HashLinkType &value);
        friend bool operator==(const HashLinkType &first, const HashLinkType &second);

        friend bool operator!=(const HashLinkType &first, const HashLinkType &second);
    };

    class MerkleLink
    {
    public:
        std::vector<uint256> branch; //pack.ListType(pack.IntType(256))
        int index;                   //TODO: pack.IntType(0) # it will always be 0

        MerkleLink(){};
        MerkleLink(std::vector<uint256> branch, int index);

        friend std::istream &operator>>(std::istream &is, MerkleLink &value);
        friend std::ostream &operator<<(std::ostream &os, const MerkleLink &value);
    };

    class SmallBlockHeaderType
    {
    public:
        unsigned long long version; // + ('version', pack.VarIntType()),
        uint256 previousBlock;      // none — ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
        unsigned int timeStamp;     // ('timestamp', pack.IntType(32)),
        unsigned int bits;          // ('bits', bitcoin_data.FloatingIntegerType()),
        unsigned int nonce;         // ('nonce', pack.IntType(32)),

        SmallBlockHeaderType(){};
        SmallBlockHeaderType(unsigned long long version, uint256 previousBlock, unsigned int timeStamp, unsigned int bits, unsigned int nonce);

        friend std::istream &operator>>(std::istream &is, SmallBlockHeaderType &value);
        friend std::ostream &operator<<(std::ostream &os, const SmallBlockHeaderType &value);
    };

    class ShareData
    {
    public:
        uint256 previous_share_hash; //none — pack.PossiblyNoneType(0, pack.IntType(256))
        std::string coinbase;
        unsigned int nonce;         //pack.IntType(32)
        uint160 pubkey_hash;        //pack.IntType(160)
        unsigned long long subsidy; //pack.IntType(64)
        unsigned short donation;    //pack.IntType(16)
        StaleInfo stale_info;
        unsigned long long desired_version; //pack.VarIntType()

        ShareData(){};
        ShareData(uint256 previous_share_hash, std::string coinbase, unsigned int nonce, uint160 pubkey_hash, unsigned long long subsidy, unsigned short donation, StaleInfo stale_info, unsigned long long desired_version);

        friend std::istream &operator>>(std::istream &is, ShareData &value);
        friend std::ostream &operator<<(std::ostream &os, const ShareData &value);
    };

    class SegwitData
    {
        //SEGWIT DATA, 94 data.py
    public:
        std::shared_ptr<MerkleLink> txid_merkle_link; //---------------
        uint256 wtxid_merkle_root;                    //pack.IntType(256)

        //InitPossiblyNoneType
        SegwitData(){
            //TODO: txid_merkle_link=dict(branch=[], index=0)
            //TODO: wtxid_merkle_root=2**256-1
        };
        SegwitData(std::shared_ptr<MerkleLink> txid_merkle_link, uint256 wtxid_merkle_root);

        friend std::istream &operator>>(std::istream &is, SegwitData &value);
        friend std::ostream &operator<<(std::ostream &os, const SegwitData &value);
    };

    class TransactionHashRef
    {
    public:
        unsigned long long share_count; //VarIntType
        unsigned long long tx_count;    //VarIntType

        TransactionHashRef(){};
        TransactionHashRef(unsigned long long share_count, unsigned long long tx_count);

        friend std::istream &operator>>(std::istream &is, TransactionHashRef &value);
        friend std::ostream &operator<<(std::ostream &os, const TransactionHashRef &value);
    };

    class ShareInfoType
    {
    public:
        std::shared_ptr<ShareData> share_data;
        std::shared_ptr<SegwitData> segwit_data;

        std::vector<uint256> new_transaction_hashes;           //pack.ListType(pack.IntType(256))
        std::vector<TransactionHashRef> transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        uint256 far_share_hash;                                //none — pack.PossiblyNoneType(0, pack.IntType(256))
        unsigned int max_bits;                                 //bitcoin_data.FloatingIntegerType() max_bits;
        unsigned int bits;                                     //bitcoin_data.FloatingIntegerType() bits;
        unsigned int timestamp;                                //pack.IntType(32)
        unsigned long absheigth;                               //pack.IntType(32)

        uint128 abswork; //pack.IntType(128)

        ShareInfoType(){};
        ShareInfoType(std::shared_ptr<ShareData> share_data, std::shared_ptr<SegwitData> segwit_data, std::vector<uint256> new_transaction_hashes, std::vector<TransactionHashRef> transaction_hash_refs, uint256 far_share_hash, unsigned int max_bits, unsigned int bits, unsigned int timestamp, unsigned long absheigth, uint128 abswork);

        friend std::istream &operator>>(std::istream &is, ShareInfoType &value);
        friend std::ostream &operator<<(std::ostream &os, const ShareInfoType &value);
    };

    class ShareType
    {
    public:
        std::shared_ptr<SmallBlockHeaderType> min_header;
        std::shared_ptr<ShareInfoType> share_info;
        std::shared_ptr<MerkleLink> ref_merkle_link;
        unsigned long long last_txout_nonce; //IntType64
        std::shared_ptr<HashLinkType> hash_link;
        std::shared_ptr<MerkleLink> merkle_link;

        ShareType(){};
        ShareType(std::shared_ptr<SmallBlockHeaderType> min_header, std::shared_ptr<ShareInfoType> share_info, std::shared_ptr<MerkleLink> ref_merkle_link, unsigned long long last_txout_nonce, std::shared_ptr<HashLinkType> hash_link, std::shared_ptr<MerkleLink> merkle_link);

        friend std::istream &operator>>(std::istream &is, ShareType &value);
        friend std::ostream &operator<<(std::ostream &os, const ShareType &value);
    };

    class RefType
    {
    public:
        std::string identifier; //TODO: pack.FixedStrType(64//8)
        std::shared_ptr<ShareInfoType> share_info;

        RefType(){};
        RefType(std::string identifier, std::shared_ptr<ShareInfoType> share_info);

        friend std::istream &operator>>(std::istream &is, RefType &value);
        friend std::ostream &operator<<(std::ostream &os, const RefType &value);
    };
} // namespace c2pool::shares