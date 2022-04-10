#pragma once

#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>

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
			branch = branch.make_type(value.branch);
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

	struct SmallBlockHeaderType_stream
	{
		VarIntType version;
		PossibleNoneType<IntType(256)> previous_block;
		IntType(32) timestamp;
		FloatingIntegerType bits;
		IntType(32) nonce;

		SmallBlockHeaderType_stream() : previous_block(IntType(256)(uint256()))
		{
		}

		SmallBlockHeaderType_stream(const shares::types::SmallBlockHeaderType &val) : SmallBlockHeaderType_stream()
		{
			version = val.version;
			previous_block = previous_block.make_type(val.previous_block);
			timestamp = val.timestamp;
			bits = val.bits;
			nonce = val.nonce;
		}

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

    struct BlockHeaderType_stream
    {
        VarIntType version;
        PossibleNoneType<IntType(256) > previous_block;
        IntType(256) merkle_root;
        IntType(32) timestamp;
        FloatingIntegerType bits;
        IntType(32) nonce;

        BlockHeaderType_stream() : previous_block(IntType(256)(uint256()))
        {
        }

		BlockHeaderType_stream(const types::BlockHeaderType &val) : BlockHeaderType_stream()
		{
			version = val.version;
			previous_block = previous_block.make_type(val.previous_block);
			merkle_root = val.merkle_root;
			timestamp = val.timestamp;
			bits = val.bits;
			nonce = val.nonce;
		}

//        BlockHeaderType_stream(const BlockHeaderType &value) : BlockHeaderType_stream()
//        {
//            version = value.version;
//            previous_block = value.previous_block;
//            merkle_root = value.merkle_root;
//            timestamp = value.timestamp;
//            bits = value.bits;
//            nonce = value.nonce;
//        }

//        operator BlockHeaderType()
//        {
//            BlockHeaderType result;
//            result.version = version.value;
//            result.previous_block = previous_block.get().value;
//            result.merkle_root = merkle_root.value;
//            result.timestamp = timestamp.value;
//            result.bits = bits.get();
//            result.nonce = nonce.value;
//        }

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
        FixedStrType<0> extra_data;
        VarIntType length;

        HashLinkType_stream() = default;

		HashLinkType_stream(const types::HashLinkType &val)
		{
			state = val.state;
			length = val.length;
		}

        PackStream &write(PackStream &stream)
        {
            stream << state << extra_data << length;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> state >> extra_data >> length;
            return stream;
        }
    };

    struct SegwitData_stream
    {
        MerkleLink_stream txid_merkle_link;
        IntType(256) wtxid_merkle_root;

        SegwitData_stream() = default;

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

    struct ShareData_stream
    {
        PossibleNoneType<IntType(256)> previous_share_hash;
        StrType coinbase;
        IntType(32) nonce;
        IntType(160) pubkey_hash;
        IntType(64) subsidy;
        IntType(16) donation;
        EnumType<StaleInfo, IntType(8)> stale_info;
        VarIntType desired_version;

        ShareData_stream() : previous_share_hash(uint256())
        {

        }

		ShareData_stream(const types::ShareData &val) : ShareData_stream()
		{
			previous_share_hash = val.previous_share_hash;
			coinbase = val.coinbase;
			nonce = val.nonce;
			pubkey_hash = val.pubkey_hash;
			subsidy = val.subsidy;
			donation = val.donation;
			stale_info = val.stale_info;
			desired_version = val.desired_version;
		}

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
        ShareData_stream share_data;
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
            share_data = ShareData_stream(val.share_data);
			new_transaction_hashes = new_transaction_hashes.make_type(val.new_transaction_hashes);
			for (auto tx_hash_ref : val.transaction_hash_refs)
			{
				transaction_hash_refs.value.push_back(transaction_hash_refs_stream(tx_hash_ref));
			}
			far_share_hash = val.far_share_hash;
			max_bits = val.max_bits;
			bits = val.bits;
			timestamp = val.timestamp;
			absheight = val.absheigth;
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

    struct ShareType_stream {
        SmallBlockHeaderType_stream min_header;
        ShareInfo_stream share_info;
        MerkleLink_stream ref_merkle_link;
        IntType(64) last_txout_nonce;
        HashLinkType_stream hash_link;
        MerkleLink_stream merkle_link;

        ShareType_stream() = default;

		ShareType_stream(const types::ShareTypeData &val)
		{
			min_header = val.min_header;
			share_info = val.share_info;
			ref_merkle_link = val.ref_merkle_link;
			last_txout_nonce = val.last_txout_nonce;
			hash_link = val.hash_link;
			merkle_link = val.merkle_link;
		}

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

    struct RefType
    {
        FixedStrType<8> identifier;
        shared_ptr<ShareInfo_stream> share_info;

		RefType() = default;

		RefType(std::string _ident, shared_ptr<ShareInfo_stream> _share_info)
		{
			identifier.value = _ident;
			share_info = _share_info;
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
}
