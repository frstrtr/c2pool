#pragma once

#include <btclibs/uint256.h>
#include <univalue.h>
#include <boost/optional.hpp>
#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>
#include <libcoind/data.h>
#include <libcoind/types.h>

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

	PackedShareData() = default;

	PackedShareData(uint64_t _type, PackStream& _contents)
	{
		type = _type;
		contents = StrType(_contents.data);
	}

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

namespace shares::types
{

    class HashLinkType
    {
    public:
        std::vector<unsigned char> state;         //pack.FixedStrType(32)
        std::vector<unsigned char> extra_data;    //pack.FixedStrType(0) # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
        uint64_t length; //pack.VarIntType()

        HashLinkType() = default;

        HashLinkType(std::vector<unsigned char> _state, std::vector<unsigned char> _extra_data, uint64_t _length)
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

        friend std::ostream &operator<<(std::ostream& stream, const HashLinkType& v)
        {
            stream << "(HashLinkType: ";
            stream << " state = " << v.state;
            stream << ", extra_data = " << v.extra_data;
            stream << ", length = " << v.length;
            stream << ")";

            return stream;
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
        coind::data::MerkleLink txid_merkle_link; //---------------
        uint256 wtxid_merkle_root;   //pack.IntType(256)

        //Init PossiblyNoneType
        SegwitData()
        {
            txid_merkle_link = coind::data::MerkleLink();
            wtxid_merkle_root.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        };

        SegwitData(coind::data::MerkleLink _txid_merkle_link, uint256 _wtxid_merkle_root)
		{
			txid_merkle_link = std::move(_txid_merkle_link);
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

        friend std::ostream &operator<<(std::ostream& stream, const SegwitData& v)
        {
            stream << "(SegwitData: ";
            stream << "txid_merkle_link = " << v.txid_merkle_link;
            stream << ", wtxid_merkle_root = " << v.wtxid_merkle_root.GetHex();
            stream << ")";

            return stream;
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

    struct ShareAddrType
    {
        std::vector<unsigned char>* address;
        uint160* pubkey_hash;

        ShareAddrType() = default;

        ~ShareAddrType()
        {
            delete address;
            delete pubkey_hash;
        }

        bool operator==(const ShareAddrType &value) const
        {
            return ((address && value.address) && (*address == *value.address)) || ((pubkey_hash && value.pubkey_hash) && (*pubkey_hash == *value.pubkey_hash));
        }

        friend std::ostream &operator<<(std::ostream& stream, const ShareAddrType& v)
        {
            stream << "(ShareAddrType: ";
            stream << "address: ";
            if (v.address)
                stream << *v.address;
            else
                stream << "null";

            stream << ", pubkey_hash: ";
            if (v.pubkey_hash)
                stream << v.pubkey_hash->GetHex();
            else
                stream << "null";
            stream << ")";
            return stream;
        }


    };

    struct ShareAddress : ShareAddrType
    {

    };

    struct SharePubkeyHash : ShareAddrType
    {

    };

    struct ShareData
    {
    public:
        uint256 previous_share_hash; //none — pack.PossiblyNoneType(0, pack.IntType(256))
		std::vector<unsigned char> coinbase;
        uint32_t nonce;         //pack.IntType(32)
        ShareAddrType* addr;
//        uint160 pubkey_hash;        //pack.IntType(160)
        uint64_t subsidy; //pack.IntType(64)
        uint16_t donation;    //pack.IntType(16)
        StaleInfo stale_info;
        uint64_t desired_version; //pack.VarIntType()

		ShareData()
		{
			previous_share_hash.SetHex("0");
		}

        template<typename ADDRESS_TYPE>
		ShareData(uint256 _prev_share_hash, std::vector<unsigned char> _coinbase, uint32_t _nonce, ADDRESS_TYPE _addr,
					unsigned long long _subsidy, unsigned short _donation, StaleInfo _stale_info, unsigned long long _desired_version)
		{
			previous_share_hash = _prev_share_hash;
			coinbase = std::move(_coinbase);
			nonce = _nonce;
			addr = new ADDRESS_TYPE(_addr);
			subsidy = _subsidy;
			donation = _donation;
			stale_info = _stale_info;
			desired_version = _desired_version;
		}

        bool operator==(const ShareData &value) const
        {
            assert(addr);
            return previous_share_hash == value.previous_share_hash && coinbase == value.coinbase && nonce == value.nonce &&
            *addr == *value.addr && subsidy == value.subsidy && donation == value.donation &&
                   stale_info == value.stale_info && desired_version == value.desired_version;
        }

        bool operator!=(const ShareData &value)
        {
            return !(*this == value);
        }

        friend std::ostream &operator<<(std::ostream& stream, const ShareData& v)
        {
            stream << "(ShareData: ";
            stream << "previous_share_hash = " << v.previous_share_hash;
            stream << ", coinbase = " << v.coinbase;
            stream << ", nonce = " << v.nonce;
            stream << ", pubkey_hash = " << *v.addr;
            stream << ", subsidy = " << v.subsidy;
            stream << ", donation = " << v.donation;
            stream << ", stale_info = " << v.stale_info;
            stream << ", desired_version = " << v.desired_version;
            stream << ")";

            return stream;
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
        uint32_t max_bits;                                   //bitcoin_data.FloatingIntegerType() max_bits;
        uint32_t bits;                                       //bitcoin_data.FloatingIntegerType() bits;
        uint32_t timestamp;                                  //pack.IntType(32)
        std::vector<uint256> new_transaction_hashes;             //pack.ListType(pack.IntType(256))
        std::vector<std::tuple<uint64_t, uint64_t>> transaction_hash_refs; //pack.ListType(pack.VarIntType(), 2)), # pairs of share_count, tx_count
        uint32_t absheight;                                 //pack.IntType(32)
        uint128 abswork;                                         //pack.IntType(128)
        std::optional<SegwitData> segwit_data;
    public:
        ShareInfo()
        {
			far_share_hash.SetHex("0");
		}

        ShareInfo(uint256 _far_share_hash, unsigned int _max_bits, unsigned int _bits,
				  unsigned int _timestamp, std::vector<uint256> _new_transaction_hashes,
				  vector<tuple<uint64_t, uint64_t>> _transaction_hash_refs, unsigned long _absheight,
				  uint128 _abswork)
		{
			far_share_hash = _far_share_hash;
			max_bits = _max_bits;
			bits = _bits;
			timestamp = _timestamp;
			new_transaction_hashes = _new_transaction_hashes;
			transaction_hash_refs = _transaction_hash_refs;
            absheight = _absheight;
			abswork = _abswork;
		}

        bool operator==(const ShareInfo &value)
        {
            return far_share_hash == value.far_share_hash && max_bits == value.max_bits &&
                   bits == value.bits && timestamp == value.timestamp &&
                   new_transaction_hashes == value.new_transaction_hashes &&
                   transaction_hash_refs == value.transaction_hash_refs && absheight == value.absheight &&
                   abswork == value.abswork;
        }

        bool operator!=(const ShareInfo &value)
        {
            return !(*this == value);
        }

        friend std::ostream &operator<<(std::ostream& stream, const ShareInfo& v)
        {
            stream << "(ShareInfo: ";
            stream << " far_share_hash = " << v.far_share_hash;
            stream << ", max_bits = " << v.max_bits;
            stream << ", bits = " << v.bits;
            stream << ", timestamp = " << v.timestamp;
            stream << ", new_transaction_hashes = " << v.new_transaction_hashes;
            stream << ", transaction_hash_refs = [";
            for (auto &[x1,x2] : v.transaction_hash_refs)
            {
                stream << "(" << x1 << "; " << x2 << "), ";
            }
            stream << "], absheight = " << v.absheight;
            stream << ", abswork = " << v.abswork;
            stream << ", segwit_data = " << v.segwit_data;
            stream << ")";
            return stream;
        }
    };

	//t['share_type']
//	struct ShareTypeData
//	{
//		coind::data::types::SmallBlockHeaderType min_header;
//		ShareInfo share_info;
//		coind::data::MerkleLink ref_merkle_link;
//		uint64_t last_txout_nonce;
//		HashLinkType hash_link;
//		coind::data::MerkleLink merkle_link;
//
//		ShareTypeData() = default;
//
//		ShareTypeData(coind::data::types::SmallBlockHeaderType _min_header, ShareInfo _share_info,
//					  coind::data::MerkleLink _ref_merkle_link, uint64_t _last_txout_nonce,
//					  HashLinkType _hash_link, coind::data::MerkleLink _merkle_link)
//		{
//			min_header = _min_header;
//			share_info = _share_info;
//			ref_merkle_link = _ref_merkle_link;
//			last_txout_nonce = _last_txout_nonce;
//			hash_link = _hash_link;
//			merkle_link = _merkle_link;
//		}
//	};
}