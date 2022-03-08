#pragma once

#include <libdevcore/stream_types.h>
#include <libdevcore/stream.h>


namespace shares::stream
{
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

        SmallBlockHeaderType_stream(SmallBlockHeaderType) : SmallBlockHeaderType_stream(){

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

        BlockHeaderType_stream(const BlockHeaderType &value) : BlockHeaderType_stream()
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
}
