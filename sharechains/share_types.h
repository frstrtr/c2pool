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

namespace shares
{
    class SmallBlockHeaderType
    {
    public:
        uint64_t version;
        uint256 previous_block;
        uint32_t timestamp;
        int32_t bits;
        uint32_t nonce;

        SmallBlockHeaderType()
        {};

        SmallBlockHeaderType(uint64_t _version, uint256 _previous_block, uint32_t _timestamp, int32_t _bits,
                             uint32_t _nonce)
        {
            version = _version;
            previous_block = _previous_block;
            timestamp = _timestamp;
            bits = _bits;
            nonce = _nonce;
        }

        bool operator==(const SmallBlockHeaderType &value)
        {
            return version == value.version && previous_block.Compare(value.previous_block) == 0 &&
                   timestamp == value.timestamp && bits == value.bits && nonce == value.nonce;
        }

        bool operator!=(const SmallBlockHeaderType &value)
        {
            return !(*this == value);
        }

//        SmallBlockHeaderType &operator=(UniValue value);

//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            result.pushKV("version", (uint64_t) version);
//            result.pushKV("previous_block", previous_block.GetHex());
//            result.pushKV("timestamp", (uint64_t) timestamp);
//            result.pushKV("bits", (uint64_t) bits);
//            result.pushKV("nonce", (uint64_t) nonce);
//
//            return result;
//        }
    };

    class MerkleLink
    {
    public:
        std::vector<uint256> branch;
//        int32_t index;

        MerkleLink()
        {
//            index = 0;
        };

        MerkleLink(std::vector<uint256> _branch)//, int index)
        {
            branch = _branch;
        }

        bool operator==(const MerkleLink &value)
        {
            return branch == value.branch;
            //return branch == value.branch && index == value.index;
        }

        bool operator!=(const MerkleLink &value)
        {
            return !(*this == value);
        }

//        MerkleLink &operator=(UniValue value)
//        {
//            for (auto hex_str: value["branch"].get_array().getValues())
//            {
//                uint256 temp_uint256;
//                temp_uint256.SetHex(hex_str.get_str());
//                branch.push_back(temp_uint256);
//            }
//            index = value["index"].get_int();
//
//            return *this;
//        }

//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            UniValue branch_list(UniValue::VARR);
//            for (auto num: branch)
//            {
//                branch_list.push_back(num.GetHex());
//            }
//
//            result.pushKV("branch", branch_list);
//            result.pushKV("index", index);
//
//            return result;
//        }
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

		BlockHeaderType(uint64_t _version, uint256 _previous_block, uint32_t _timestamp, int32_t _bits,
				uint32_t _nonce, uint256 _merkle_root)
		{
			version = _version;
			previous_block = _previous_block;
			timestamp = _timestamp;
			bits = _bits;
			nonce = _nonce;
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

    class HashLinkType
    {
    public:
        std::string state;         //pack.FixedStrType(32)
        std::string extra_data;    //pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
        unsigned long long length; //pack.VarIntType()

        HashLinkType()
        {}

        HashLinkType(std::string _state, std::string _extra_data, unsigned long long _length)
		{
			state = _state;
			extra_data = _extra_data;
			length = _length;
		}

        bool operator==(const HashLinkType &value)
        {
            return state == value.state && length == value.length;
        }

        bool operator!=(const HashLinkType &value)
        {
            return !(*this == value);
        }

//        HashLinkType &operator=(UniValue value)
//        {
//            state = value["state"].get_str();
//            extra_data = value["extra_data"].get_str();
//            length = value["length"].get_int64();
//            return *this;
//        }

//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            result.pushKV("state", state);
//            result.pushKV("extra_data", extra_data);
//            result.pushKV("length", (uint64_t) length);
//
//            return result;
//        }
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

        SegwitData(MerkleLink _txid_merkle_link, uint256 _wtxid_merkle_root)
		{
			txid_merkle_link = _txid_merkle_link;
			wtxid_merkle_root = _wtxid_merkle_root;
		}

        bool operator==(const SegwitData &value)
        {
            return txid_merkle_link == value.txid_merkle_link && wtxid_merkle_root == value.wtxid_merkle_root;
        }

        bool operator!=(const SegwitData &value)
        {
            return !(*this == value);
        }

//        SegwitData &operator=(UniValue value)
//        {
//            txid_merkle_link = value["txid_merkle_link"].get_obj();
//
//            wtxid_merkle_root.SetHex(value["wtxid_merkle_root"].get_str());
//
//            return *this;
//        }
//
//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            result.pushKV("txid_merkle_link", txid_merkle_link);
//            result.pushKV("wtxid_merkle_root", wtxid_merkle_root.GetHex());
//
//            return result;
//        }
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

		ShareData()
		{
			previous_share_hash.SetHex("0");
		}

		ShareData(uint256 _prev_share_hash, std::string _coinbase, uint32_t _nonce, uint160 _pubkey_hash,
					unsigned long long _subsidy, unsigned short _donation, StaleInfo _stale_info, unsigned long long _desired_version)
		{
			previous_share_hash = _prev_share_hash;
			coinbase = _coinbase;
			nonce = _nonce;
			pubkey_hash = _pubkey_hash;
			subsidy = _subsidy;
			donation = _donation;
			stale_info = _stale_info;
			desired_version = _desired_version;
		}

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

//        ShareData &operator=(UniValue value)
//        {
//            previous_share_hash.SetHex(value["previous_share_hash"].get_str());
//            coinbase = value["coinbase"].get_str();
//            nonce = value["nonce"].get_int64();
//            pubkey_hash.SetHex(value["pubkey_hash"].get_str());
//            subsidy = value["subsidy"].get_int64();
//            donation = value["donation"].get_int();
//            stale_info = (StaleInfo) value["stale_info"].get_int();
//            desired_version = value["desired_version"].get_int64();
//
//            return *this;
//        }
//
//        operator UniValue()
//        {
//            UniValue result(UniValue::VOBJ);
//
//            result.pushKV("previous_share_hash", previous_share_hash.GetHex());
//            result.pushKV("coinbase", coinbase);
//            result.pushKV("nonce", (uint64_t) nonce);
//            result.pushKV("pubkey_hash", pubkey_hash.GetHex());
//            result.pushKV("subsidy", (uint64_t) subsidy);
//            result.pushKV("donation", donation);
//            result.pushKV("stale_info", (int) stale_info);
//            result.pushKV("desired_version", (uint64_t) desired_version);
//
//            return result;
//        }
    };

    struct ShareInfo
    {
    public:
        uint256 far_share_hash;                                  //none — pack.PossiblyNoneType(0, pack.IntType(256))
        unsigned int max_bits;                                   //bitcoin_data.FloatingIntegerType() max_bits;
        unsigned int bits;                                       //bitcoin_data.FloatingIntegerType() bits;
        unsigned int timestamp;                                  //pack.IntType(32)
        std::vector<uint256> new_transaction_hashes;             //pack.ListType(pack.IntType(256))
        std::vector<std::tuple<int, int>> transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        unsigned long absheigth;                                 //pack.IntType(32)
        uint128 abswork;                                         //pack.IntType(128)

    public:
        ShareInfo()
        {
			far_share_hash.SetHex("0");
		}

        ShareInfo(uint256 _far_share_hash, unsigned int _max_bits, unsigned int _bits,
				  unsigned int _timestamp, std::vector<uint256> _new_transaction_hashes,
                  std::vector<std::tuple<int, int>> _transaction_hash_refs, unsigned long _absheigth,
				  uint128 _abswork)
		{
			far_share_hash = _far_share_hash;
			max_bits = _max_bits;
			bits = _bits;
			timestamp = _timestamp;
			new_transaction_hashes = _new_transaction_hashes;
			transaction_hash_refs = _transaction_hash_refs;
			absheigth = _absheigth;
			abswork = _abswork;
		}

        bool operator==(const ShareInfo &value)
        {
            return far_share_hash == value.far_share_hash && max_bits == value.max_bits &&
                   bits == value.bits && timestamp == value.timestamp &&
                   new_transaction_hashes == value.new_transaction_hashes &&
                   transaction_hash_refs == value.transaction_hash_refs && absheigth == value.absheigth &&
                   abswork == value.abswork;
        }

        bool operator!=(const ShareInfo &value)
        {
            return !(*this == value);
        }
    };

	//t['share_type']
	struct ShareTypeData
	{
		SmallBlockHeaderType min_header;
		ShareInfo share_info;
		MerkleLink ref_merkle_link;
		uint64_t last_txout_nonce;
		HashLinkType hash_link;
		MerkleLink merkle_link;

		ShareTypeData() = default;

		ShareTypeData(SmallBlockHeaderType _min_header, ShareInfo _share_info,
					  MerkleLink _ref_merkle_link, uint64_t _last_txout_nonce,
					  HashLinkType _hash_link, MerkleLink _merkle_link)
		{
			min_header = _min_header;
			share_info = _share_info;
			ref_merkle_link = _ref_merkle_link;
			last_txout_nonce = _last_txout_nonce;
			hash_link = _hash_link;
			merkle_link = _merkle_link;
		}
	};
}