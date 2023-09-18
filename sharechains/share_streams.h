#pragma once

#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>
#include <libcoind/types.h>

#include <utility>

#include "share_types.h"

namespace shares::stream
{
    struct MerkleLink_stream
    {
        ListType<IntType(256)> branch;
        //В p2pool используется костыль при пустой упаковке, но в этой реализации он не нужен.
        //index

        MerkleLink_stream() = default;

		MerkleLink_stream(const coind::data::MerkleLink &value)
		{
			branch = ListType<IntType(256)>::make_type(value.branch);
		}

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

    struct HashLinkType_stream
    {
        FixedStrType<32> state;
        //Костыль в p2pool, который не нужен.
//        FixedStrType<0> extra_data;
        VarIntType length;

        HashLinkType_stream() = default;

		HashLinkType_stream(const types::HashLinkType &val)
		{
			state = val.state;
			length = val.length;
		}

        PackStream &write(PackStream &stream)
        {
            stream << state
//            << extra_data
            << length;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream
                >> state
//                >> extra_data
                >> length;
            return stream;
        }
    };

    struct SegwitData_stream
    {
        MerkleLink_stream txid_merkle_link;
        IntType(256) wtxid_merkle_root;

        SegwitData_stream() : txid_merkle_link(), wtxid_merkle_root()
        {
            wtxid_merkle_root.set(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        }

		SegwitData_stream(const types::SegwitData &val)
		{
			txid_merkle_link = MerkleLink_stream(val.txid_merkle_link);
			wtxid_merkle_root = val.wtxid_merkle_root;
		}

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

    struct ShareAddrType_stream
    {
        StrType* address;
        IntType(160)* pubkey_hash;

        auto &operator=(const shares::types::ShareAddrType &_addr)
        {
            if (_addr.address)
                address = new StrType(*_addr.address);
            if (_addr.pubkey_hash)
                pubkey_hash = new IntType(160)(*_addr.pubkey_hash);
            return *this;
        }

        virtual PackStream &write(PackStream &stream) = 0;
        virtual PackStream &read(PackStream &stream) = 0;
    };

    struct ShareAddress_stream : ShareAddrType_stream
    {
        ShareAddress_stream()
        {
            address = new StrType();
        }

        explicit ShareAddress_stream(const shares::types::ShareAddrType &_addr)
        {
            if (_addr.address)
                address = new StrType(*_addr.address);
            if (_addr.pubkey_hash)
                pubkey_hash = new IntType(160)(*_addr.pubkey_hash);
        }

        explicit ShareAddress_stream(std::vector<unsigned char> addr)
        {
            address = new StrType(std::move(addr));
        }

        PackStream &write(PackStream &stream) override
        {
            stream << *address;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> *address;
            return stream;
        }
    };

    struct SharePubkeyHash_stream : ShareAddrType_stream
    {
        SharePubkeyHash_stream()
        {
            pubkey_hash = new IntType(160)();
        }

        explicit SharePubkeyHash_stream(const shares::types::ShareAddrType &_addr)
        {
            if (_addr.address)
                address = new StrType(*_addr.address);
            if (_addr.pubkey_hash)
                pubkey_hash = new IntType(160)(*_addr.pubkey_hash);
        }

        explicit SharePubkeyHash_stream(uint160 pubkey)
        {
            pubkey_hash = new IntType(160)(pubkey);
        }

        PackStream &write(PackStream &stream) override
        {
            stream << *pubkey_hash;
            return stream;
        }

        PackStream &read(PackStream &stream) override
        {
            stream >> *pubkey_hash;
            return stream;
        }
    };

    struct ShareData_stream
    {
        PossibleNoneType<IntType(256)> previous_share_hash;
        StrType coinbase;
        IntType(32) nonce;
        ShareAddrType_stream addr;
        IntType(64) subsidy;
        IntType(16) donation;
        EnumType<StaleInfo, IntType(8)> stale_info;
        VarIntType desired_version;

        ShareData_stream() : previous_share_hash(uint256())
        {

        }

		explicit ShareData_stream(const types::ShareData &val) : ShareData_stream()
		{
			previous_share_hash = val.previous_share_hash;
			coinbase = val.coinbase;
			nonce = val.nonce;
			addr = val.addr;
			subsidy = val.subsidy;
			donation = val.donation;
			stale_info = val.stale_info;
			desired_version = val.desired_version;
		}

        PackStream &write(PackStream &stream)
        {
            stream << previous_share_hash << coinbase << nonce << addr << subsidy << donation << stale_info
                   << desired_version;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> previous_share_hash >> coinbase >> nonce >> addr >> subsidy >> donation >> stale_info
                   >> desired_version;
            return stream;
        }
    };

    struct transaction_hash_refs_stream : public CustomGetter<std::tuple<uint64_t, uint64_t>>
    {
        VarIntType share_count;
        VarIntType tx_count;

        transaction_hash_refs_stream() = default;

		transaction_hash_refs_stream(const std::tuple<uint64_t, uint64_t> &val)
		{
			share_count = std::get<0>(val);
			tx_count = std::get<1>(val);
		}

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

		std::tuple<uint64_t, uint64_t> get() const override
		{
			return std::make_tuple(share_count.get(), tx_count.get());
		}
    };

    struct ShareInfo_stream
    {
        ListType<IntType(256)> new_transaction_hashes;
        ListType<transaction_hash_refs_stream> transaction_hash_refs;
        PossibleNoneType<IntType(256)> far_share_hash;
        FloatingIntegerType max_bits;
        FloatingIntegerType bits;
        IntType(32) timestamp;
        IntType(32) absheight;
        IntType(128) abswork;

        ShareInfo_stream() : far_share_hash(uint256{})
        {

        }

        ShareInfo_stream(const types::ShareInfo &val) : ShareInfo_stream()
		{
			new_transaction_hashes = new_transaction_hashes.make_type(val.new_transaction_hashes);
			for (auto tx_hash_ref : val.transaction_hash_refs)
			{
				transaction_hash_refs.value.push_back(transaction_hash_refs_stream(tx_hash_ref));
			}
			far_share_hash = val.far_share_hash;
			max_bits = val.max_bits;
			bits = val.bits;
			timestamp = val.timestamp;
			absheight = val.absheight;
			abswork = val.abswork;
		}

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

//    struct ShareType_stream {
//        coind::data::stream::SmallBlockHeaderType_stream min_header;
//        ShareInfo_stream share_info;
//        MerkleLink_stream ref_merkle_link;
//        IntType(64) last_txout_nonce;
//        HashLinkType_stream hash_link;
//        MerkleLink_stream merkle_link;
//
//        ShareType_stream() = default;
//
//		ShareType_stream(const types::ShareTypeData &val)
//		{
//			min_header = val.min_header;
//			share_info = val.share_info;
//			ref_merkle_link = val.ref_merkle_link;
//			last_txout_nonce = val.last_txout_nonce;
//			hash_link = val.hash_link;
//			merkle_link = val.merkle_link;
//		}
//
//        PackStream &write(PackStream &stream)
//        {
//            stream << min_header << share_info << ref_merkle_link << last_txout_nonce << hash_link << merkle_link;
//            return stream;
//        }
//
//        PackStream &read(PackStream &stream)
//        {
//            stream >> min_header >> share_info >> ref_merkle_link >> last_txout_nonce >> hash_link >> merkle_link;
//            return stream;
//        }
//    };

    struct RefType
    {
        bool segwit_activated;

        FixedStrType<8> identifier;
        ShareData_stream share_data;
        ShareInfo_stream share_info;
        PossibleNoneType<SegwitData_stream> segwit_data;

		RefType(bool _segwit_activated = true) : segwit_data({})
        {
            segwit_activated = _segwit_activated;
        }

		RefType(bool _segwit_activated, std::vector<unsigned char> _ident, shares::types::ShareData &_share_data, shares::types::ShareInfo &_share_info, std::optional<shares::types::SegwitData> _segwit_data) : segwit_activated(_segwit_activated), segwit_data({})
		{
			identifier = FixedStrType<8>(_ident);
            share_data = ShareData_stream(_share_data);
			share_info = ShareInfo_stream(_share_info);

            if (_segwit_data.has_value())
                segwit_data = _segwit_data.value();
		}

        PackStream &write(PackStream &stream)
        {
            stream << identifier << share_data;
            if (segwit_activated)
                stream << segwit_data;
            stream << share_info;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> identifier >> share_info;
            if (segwit_activated)
                stream >> segwit_data;
            stream >> share_info;
            return stream;
        }
    };

}
