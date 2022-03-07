#pragma once

#include <btclibs/uint256.h>
#include <univalue.h>
#include <boost/optional.hpp>
#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>

#include <set>
#include <tuple>
#include <vector>

enum StaleInfo
{
    unk = 0,
    orphan = 253,
    doa = 254
};

#define PackShareType(type, data, out_data) \
    {                                       \
        type##_stream __pack_data(data);    \
        out_data << __pack_data;            \
    }

struct PackedShareData
{
	VarIntType type;
	StrType contents;

	PackStream &write(PackStream &stream)
	{
		stream << type << contents;
		return stream;
	}

	PackStream &read(PackStream &stream)
	{
		stream >> type >> contents;
		return stream;
	}
};

struct SmallBlockHeaderType_stream
{
    VarIntType version;
    PossibleNoneType<IntType(256)> previous_block;
    IntType(32) timestamp;
    FloatingIntegerType bits;
    IntType(32) nonce;

    PackStream &write(PackStream &stream)
    {
        stream << version << previous_block << timestamp << bits << nonce;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> version >> previous_block >> timestamp >> bits >> nonce;
        return stream;
    }
};

class SmallBlockHeaderType
{
public:
    unsigned long long version;
    uint256 previous_block;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

    SmallBlockHeaderType()
    {};

    SmallBlockHeaderType(unsigned long long version, uint256 previous_block, unsigned int timeStamp, unsigned int bits,
                         unsigned int nonce);

    bool operator==(const SmallBlockHeaderType &value)
    {
        return version == value.version && previous_block.Compare(value.previous_block) == 0 &&
               timestamp == value.timestamp && bits == value.bits && nonce == value.nonce;
    }

    bool operator!=(const SmallBlockHeaderType &value)
    {
        return !(*this == value);
    }

    SmallBlockHeaderType &operator=(UniValue value);

    operator UniValue()
    {
        UniValue result(UniValue::VOBJ);

        result.pushKV("version", (uint64_t) version);
        result.pushKV("previous_block", previous_block.GetHex());
        result.pushKV("timestamp", (uint64_t) timestamp);
        result.pushKV("bits", (uint64_t) bits);
        result.pushKV("nonce", (uint64_t) nonce);

        return result;
    }
};

struct MerkleLink_stream
{
    ListType<IntType(256) > branch;
    //В p2pool используется костыль при пустой упаковке, но в этой реализации он не нужен.
    //index

    PackStream &write(PackStream &stream)
    {
        stream << branch;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> branch;
        return stream;
    }
};

class MerkleLink
{
public:
    std::vector<uint256> branch;
    int32_t index;

    MerkleLink()
    {
        index = 0;
    };

    MerkleLink(std::vector<uint256> branch, int index);

    bool operator==(const MerkleLink &value)
    {
        return branch == value.branch && index == value.index;
    }

    bool operator!=(const MerkleLink &value)
    {
        return !(*this == value);
    }

    MerkleLink &operator=(UniValue value)
    {
        for (auto hex_str: value["branch"].get_array().getValues())
        {
            uint256 temp_uint256;
            temp_uint256.SetHex(hex_str.get_str());
            branch.push_back(temp_uint256);
        }
        index = value["index"].get_int();

        return *this;
    }

    operator UniValue()
    {
        UniValue result(UniValue::VOBJ);

        UniValue branch_list(UniValue::VARR);
        for (auto num: branch)
        {
            branch_list.push_back(num.GetHex());
        }

        result.pushKV("branch", branch_list);
        result.pushKV("index", index);

        return result;
    }
};

class BlockHeaderType : public SmallBlockHeaderType
{
public:
    uint256 merkle_root;

public:
    BlockHeaderType() : SmallBlockHeaderType()
    {};

    BlockHeaderType(SmallBlockHeaderType _min_header, uint256 _merkle_root) : SmallBlockHeaderType(_min_header)
    {
        merkle_root = _merkle_root;
    }

    bool operator==(const BlockHeaderType &value) const
    {
        return version == value.version && previous_block.Compare(value.previous_block) == 0 &&
               timestamp == value.timestamp && bits == value.bits && nonce == value.nonce &&
               merkle_root.Compare(value.merkle_root) == 0;
    }

    bool operator!=(const BlockHeaderType &value) const
    {
        return !(*this == value);
    }
};

struct BlockHeaderType_stream
{
    VarIntType version;
    PossibleNoneType<IntType(256) > previous_block;
    IntType(256) merkle_root;
    IntType(32) timestamp;
    FloatingIntegerType bits;
    IntType(32) nonce;

    BlockHeaderType_stream()
    {}

    BlockHeaderType_stream(const BlockHeaderType &value)
    {
        version = value.version;
        previous_block = value.previous_block;
        merkle_root = value.merkle_root;
        timestamp = value.timestamp;
        bits = value.bits;
        nonce = value.nonce;
    }

    operator BlockHeaderType()
    {
        BlockHeaderType result;
        result.version = version.value;
        result.previous_block = previous_block.get().value;
        result.merkle_root = merkle_root.value;
        result.timestamp = timestamp.value;
        result.bits = bits.get();
        result.nonce = nonce.value;
    }

    PackStream &write(PackStream &stream)
    {
        stream << version << previous_block << merkle_root << timestamp << bits << nonce;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> version >> previous_block >> merkle_root >> timestamp >> bits >> nonce;
        return stream;
    }
};

struct HashLinkType_stream
{
    FixedStrType<32> state;
    //Костыль в p2pool, который не нужен.
    //FixedStrType<0> extra_data
    VarIntType length;

    PackStream &write(PackStream &stream)
    {
        stream << state << length;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> state >> length;
        return stream;
    }
};

class HashLinkType
{
public:
    std::string state;         //pack.FixedStrType(32)
    std::string extra_data;    //pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    unsigned long long length; //pack.VarIntType()

    HashLinkType()
    {}

    HashLinkType(std::string state, std::string extra_data, unsigned long long length);

    bool operator==(const HashLinkType &value)
    {
        return state == value.state && extra_data == value.extra_data && length == value.length;
    }

    bool operator!=(const HashLinkType &value)
    {
        return !(*this == value);
    }

    HashLinkType &operator=(UniValue value)
    {
        state = value["state"].get_str();
        extra_data = value["extra_data"].get_str();
        length = value["length"].get_int64();
        return *this;
    }

    operator UniValue()
    {
        UniValue result(UniValue::VOBJ);

        result.pushKV("state", state);
        result.pushKV("extra_data", extra_data);
        result.pushKV("length", (uint64_t) length);

        return result;
    }
};

struct SegwitData_stream
{
    MerkleLink_stream txid_merkle_link;
    IntType(256) wtxid_merkle_root;

    PackStream &write(PackStream &stream)
    {
        stream << txid_merkle_link << wtxid_merkle_root;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> txid_merkle_link >> wtxid_merkle_root;
        return stream;
    }
};

class SegwitData
{
    //SEGWIT DATA, 94 data.py
public:
    MerkleLink txid_merkle_link; //---------------
    uint256 wtxid_merkle_root;   //pack.IntType(256)

    //Init PossiblyNoneType
    SegwitData()
    {
        txid_merkle_link = MerkleLink();
        wtxid_merkle_root.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    };

    SegwitData(MerkleLink txid_merkle_link, uint256 wtxid_merkle_root);

    bool operator==(const SegwitData &value)
    {
        return txid_merkle_link == value.txid_merkle_link && wtxid_merkle_root == value.wtxid_merkle_root;
    }

    bool operator!=(const SegwitData &value)
    {
        return !(*this == value);
    }

    SegwitData &operator=(UniValue value)
    {
        txid_merkle_link = value["txid_merkle_link"].get_obj();

        wtxid_merkle_root.SetHex(value["wtxid_merkle_root"].get_str());

        return *this;
    }

    operator UniValue()
    {
        UniValue result(UniValue::VOBJ);

        result.pushKV("txid_merkle_link", txid_merkle_link);
        result.pushKV("wtxid_merkle_root", wtxid_merkle_root.GetHex());

        return result;
    }
};

struct ShareData_stream
{
    PossibleNoneType<IntType(256) > previous_share_hash;
    StrType coinbase;
    IntType(32) nonce;
    IntType(160) pubkey_hash;
    IntType(64) subsidy;
    IntType(16) donation;
    EnumType<StaleInfo, IntType(8) > stale_info;
    VarIntType desired_version;

    PackStream &write(PackStream &stream)
    {
        stream << previous_share_hash << coinbase << nonce << pubkey_hash << subsidy << donation << stale_info
               << desired_version;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> previous_share_hash >> coinbase >> nonce >> pubkey_hash >> subsidy >> donation >> stale_info
               >> desired_version;
        return stream;
    }
};

struct ShareData
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

    bool operator==(const ShareData &value)
    {
        return previous_share_hash == value.previous_share_hash && coinbase == value.coinbase && nonce == value.nonce &&
               pubkey_hash == value.pubkey_hash && subsidy == value.subsidy && donation == value.donation &&
               stale_info == value.stale_info && desired_version == value.desired_version;
    }

    bool operator!=(const ShareData &value)
    {
        return !(*this == value);
    }

    ShareData &operator=(UniValue value)
    {
        previous_share_hash.SetHex(value["previous_share_hash"].get_str());
        coinbase = value["coinbase"].get_str();
        nonce = value["nonce"].get_int64();
        pubkey_hash.SetHex(value["pubkey_hash"].get_str());
        subsidy = value["subsidy"].get_int64();
        donation = value["donation"].get_int();
        stale_info = (StaleInfo) value["stale_info"].get_int();
        desired_version = value["desired_version"].get_int64();

        return *this;
    }

    operator UniValue()
    {
        UniValue result(UniValue::VOBJ);

        result.pushKV("previous_share_hash", previous_share_hash.GetHex());
        result.pushKV("coinbase", coinbase);
        result.pushKV("nonce", (uint64_t) nonce);
        result.pushKV("pubkey_hash", pubkey_hash.GetHex());
        result.pushKV("subsidy", (uint64_t) subsidy);
        result.pushKV("donation", donation);
        result.pushKV("stale_info", (int) stale_info);
        result.pushKV("desired_version", (uint64_t) desired_version);

        return result;
    }
};

struct transaction_hash_refs_stream
{
    VarIntType share_count;
    VarIntType tx_count;

    PackStream &write(PackStream &stream)
    {
        stream << share_count << tx_count;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> share_count >> tx_count;
        return stream;
    }
};

struct ShareInfo_stream
{
    ListType<IntType(256) > new_transaction_hashes;
    ListType<transaction_hash_refs_stream> transaction_hash_refs;
    PossibleNoneType<IntType(256) > far_share_hash;
    FloatingIntegerType max_bits;
    FloatingIntegerType bits;
    IntType(32) timestamp;
    IntType(32) absheight;
    IntType(128) abswork;

    virtual PackStream &write(PackStream &stream) {
        stream << new_transaction_hashes << transaction_hash_refs << far_share_hash << max_bits << bits << timestamp
               << absheight << abswork;
        return stream;
    }

    virtual PackStream &read(PackStream &stream){
        stream >> new_transaction_hashes >> transaction_hash_refs >> far_share_hash >> max_bits >> bits >> timestamp
               >> absheight >> abswork;
        return stream;
    }
};

struct ShareInfo
{
public:
    ShareData share_data;
    uint256 far_share_hash;                                  //none — pack.PossiblyNoneType(0, pack.IntType(256))
    unsigned int max_bits;                                   //bitcoin_data.FloatingIntegerType() max_bits;
    unsigned int bits;                                       //bitcoin_data.FloatingIntegerType() bits;
    unsigned int timestamp;                                  //pack.IntType(32)
    std::vector<uint256> new_transaction_hashes;             //pack.ListType(pack.IntType(256))
    std::vector<std::tuple<int, int>> transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
    unsigned long absheigth;                                 //pack.IntType(32)
    uint128 abswork;                                         //pack.IntType(128)

    boost::optional<SegwitData> segwit_data;

public:
    ShareInfo()
    {};

    ShareInfo(ShareData share_data, std::vector<uint256> new_transaction_hashes,
              std::vector<std::tuple<int, int>> transaction_hash_refs, uint256 far_share_hash, unsigned int max_bits,
              unsigned int bits, unsigned int timestamp, unsigned long absheigth, uint128 abswork,
              SegwitData segwit_data);

    bool operator==(const ShareInfo &value)
    {
        return share_data == value.share_data && far_share_hash == value.far_share_hash && max_bits == value.max_bits &&
               bits == value.bits && timestamp == value.timestamp &&
               new_transaction_hashes == value.new_transaction_hashes &&
               transaction_hash_refs == value.transaction_hash_refs && absheigth == value.absheigth &&
               abswork == value.abswork;
    }

    bool operator!=(const ShareInfo &value)
    {
        return !(*this == value);
    }

    //TODO: remove or create just obj -> json;
    // ShareInfo &operator=(UniValue value)
    // {
    //     share_data = std::make_shared<ShareData>();
    //     *share_data = value["share_data"].get_obj();

    //     segwit_data = std::make_shared<SegwitData>();
    //     *segwit_data = value["segwit_data"].get_obj();

    //     for (auto hex_str : value["new_transaction_hashes"].get_array().getValues())
    //     {
    //         uint256 temp_uint256;
    //         temp_uint256.SetHex(hex_str.get_str());
    //         new_transaction_hashes.push_back(temp_uint256);
    //     }

    //     for (auto tx_hash_ref : value["transaction_hash_refs"].get_array().getValues())
    //     {
    //         TransactionHashRef temp_tx_hash_ref;
    //         temp_tx_hash_ref = tx_hash_ref.get_obj();
    //         transaction_hash_refs.push_back(temp_tx_hash_ref);
    //     }

    //     far_share_hash.SetHex(value["far_share_hash"].get_str());
    //     max_bits = value["max_bits"].get_int64();
    //     bits = value["bits"].get_int64();
    //     timestamp = value["timestamp"].get_int64();
    //     absheigth = value["absheigth"].get_int64();

    //     abswork.SetHex(value["abswork"].get_str());
    //     return *this;
    // }

    // operator UniValue()
    // {
    //     UniValue result(UniValue::VOBJ);

    //     result.pushKV("share_data", *share_data);
    //     result.pushKV("segwit_data", *segwit_data);

    //     UniValue new_transaction_hashes_array(UniValue::VARR);
    //     for (auto hash : new_transaction_hashes)
    //     {
    //         new_transaction_hashes_array.push_back(hash.GetHex());
    //     }
    //     result.pushKV("new_transaction_hashes", new_transaction_hashes_array);

    //     UniValue transaction_hash_refs_array(UniValue::VA[SRR);
    //     for (auto tx_hash_ref : transaction_hash_refs)
    //     {
    //         transaction_hash_refs_array.push_back(tx_hash_ref);
    //     }
    //     result.pushKV("transaction_hash_refs", transaction_hash_refs_array);

    //     result.pushKV("far_share_hash", far_share_hash.GetHex());
    //     result.pushKV("max_bits", (uint64_t)max_bits);
    //     result.pushKV("bits", (uint64_t)bits);
    //     result.pushKV("timestamp", (uint64_t)timestamp);
    //     result.pushKV("absheigth", (uint64_t)absheigth);
    //     result.pushKV("abswork", abswork.GetHex());

    //     return result;
    // }
};

struct RefType
{
    FixedStrType<8> identifier;
    shared_ptr<ShareInfo_stream> share_info;

    RefType(const unsigned char *_ident, ShareInfo _share_info)
    {
        string str_ident((const char *) _ident, 8);
        identifier = FixedStrType<8>(str_ident);

        //TODO: *share_info = _share_info;
    }

    PackStream &write(PackStream &stream)
    {
        stream << identifier << share_info;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> identifier >> share_info;
        return stream;
    }
};

struct ShareType_stream {
	SmallBlockHeaderType_stream min_header;
	ShareInfo_stream share_info;
	MerkleLink_stream ref_merkle_link;
	IntType(64) last_txout_nonce;
	HashLinkType_stream hash_link;
	MerkleLink_stream merkle_link;

	PackStream &write(PackStream &stream)
	{
		stream << min_header << share_info << ref_merkle_link << last_txout_nonce << hash_link << merkle_link;
		return stream;
	}

	PackStream &read(PackStream &stream)
	{
		stream >> min_header >> share_info >> ref_merkle_link >> last_txout_nonce >> hash_link >> merkle_link;
		return stream;
	}
};