#pragma once

#include <cstdint>

#include "transaction.h"

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

// TYPES
namespace coind::data::types
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

        virtual void print(std::ostream &stream) const
        {
            stream << "(SmallBlockHeaderType: ";
            stream << "version = " << version;
            stream << ", previous_block = " << previous_block;
            stream << ", timestamp = " << timestamp;
            stream << ", bits = " << bits;
            stream << ", nonce = " << nonce;
            stream << ")";
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
            // FOR TESTS! comment in prod
            if (version != value.version)
                assert(false);
            if (previous_block.Compare(value.previous_block) != 0)
                assert(false);
            if (timestamp != value.timestamp)
                assert(false);
            if (bits != value.bits)
                assert(false);
            if (nonce != value.nonce)
                assert(false);
            if (merkle_root.Compare(value.merkle_root) != 0)
                assert(false);

            return version == value.version && previous_block.Compare(value.previous_block) == 0 &&
                   timestamp == value.timestamp && bits == value.bits && nonce == value.nonce &&
                   merkle_root.Compare(value.merkle_root) == 0;
        }

        bool operator!=(const BlockHeaderType &value) const
        {
            return !(*this == value);
        }

        void print(std::ostream &stream) const override
        {
            stream << "(BlockHeaderType: ";
            stream << "version = " << version;
            stream << ", previous_block = " << previous_block;
            stream << ", timestamp = " << timestamp;
            stream << ", bits = " << bits;
            stream << ", nonce = " << nonce;
            stream << ", merkle_root = " << merkle_root;
            stream << ")";
        }
    };

    inline std::ostream &operator<<(std::ostream &stream, const SmallBlockHeaderType &value)
    {
        value.print(stream);
        return stream;
    }

    inline std::ostream &operator<<(std::ostream &stream, const BlockHeaderType &value)
    {
        value.print(stream);
        return stream;
    }

    struct BlockType
    {
        BlockHeaderType header;
        std::vector<coind::data::tx_type> txs;

        BlockType() = default;

        BlockType(BlockHeaderType _header, std::vector<coind::data::tx_type> _txs)
        {
            header = _header;
            txs = _txs;
        }
    };

    //TODO: maybe remove?
    struct StrippedBlockType
    {
        BlockHeaderType header;
        std::vector<coind::data::TxIDType> txs;

        StrippedBlockType() = default;

        StrippedBlockType(BlockHeaderType _header, std::vector<coind::data::TxIDType> _txs)
        {
            header = _header;
            txs = _txs;
        }
    };
}

// STREAM
namespace coind::data::stream
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

        SmallBlockHeaderType_stream(const types::SmallBlockHeaderType &val) : SmallBlockHeaderType_stream()
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
		IntType(32) version;
        PossibleNoneType<IntType(256)> previous_block;
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
//            stream >> version >> previous_block >> merkle_root >> timestamp >> bits >> nonce;
			stream >> version;
			stream >> previous_block;
			stream >> merkle_root;
			stream >> timestamp;
			stream >> bits;
			stream >> nonce;
			return stream;
        }
    };

    struct BlockType_stream
    {
        BlockHeaderType_stream header;
        ListType<coind::data::stream::TransactionType_stream> txs;

        BlockType_stream() = default;

        BlockType_stream(types::BlockHeaderType _header, std::vector<coind::data::tx_type> _txs)
        {
            header = _header;

            std::vector<coind::data::stream::TransactionType_stream> _temp_txs;

            for (auto _tx : _txs)
            {
                coind::data::stream::TransactionType_stream tx_stream(_tx);
                txs.value.push_back(std::move(tx_stream));
            }
//            std::transform(_txs.begin(), _txs.end(), _temp_txs.begin(), [&](coind::data::tx_type _tx)
//            {
//                return coind::data::stream::TransactionType_stream(_tx);
//            });
//            txs = _temp_txs;
        }

        BlockType_stream (types::BlockType _block)
        {
            header = _block.header;
            std::vector<coind::data::stream::TransactionType_stream> _temp_txs;
            for (auto _tx : _block.txs)
            {
                coind::data::stream::TransactionType_stream tx_stream(_tx);
                txs.value.push_back(std::move(tx_stream));
            }
//            std::transform(_block.txs.begin(), _block.txs.end(), _temp_txs.begin(), [&](coind::data::tx_type _tx)
//            {
//                return coind::data::stream::TransactionType_stream(_tx);
//            });
//            txs = _temp_txs;
        }

        PackStream &write(PackStream &stream)
        {
            stream << header << txs;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> header >> txs;
            return stream;
        }
    };

    //TODO: maybe remove?
    struct StrippedBlockType_stream
    {
        BlockHeaderType_stream header;
        ListType<coind::data::stream::TxIDType_stream> txs;

        StrippedBlockType_stream() = default;

        StrippedBlockType_stream(types::BlockHeaderType _header, std::vector<coind::data::TxIDType> _txs)
        {
            header = _header;

            std::vector<coind::data::stream::TxIDType_stream> _temp_txs;
            std::transform(_txs.begin(), _txs.end(), _temp_txs.begin(), [&](const coind::data::TxIDType &_tx)
            {
                return coind::data::stream::TxIDType_stream(_tx);
            });
            txs = _temp_txs;
        }

        StrippedBlockType_stream (types::StrippedBlockType _block)
        {
            header = _block.header;
            std::vector<coind::data::stream::TxIDType_stream> _temp_txs;
            std::transform(_block.txs.begin(), _block.txs.end(), _temp_txs.begin(), [&](const coind::data::TxIDType &_tx)
            {
                return coind::data::stream::TxIDType_stream(_tx);
            });
            txs = _temp_txs;
        }

        PackStream &write(PackStream &stream)
        {
            stream << header << txs;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream >> header >> txs;
            return stream;
        }
    };
}

namespace coind::data
{
    struct SmallBlockHeaderType :
            StreamTypeAdapter<types::SmallBlockHeaderType, stream::SmallBlockHeaderType_stream>
    {
        void _to_stream() override
        {
            make_stream(*_value);
        }

        void _to_value() override
        {
            make_value(_stream->version.value, _stream->previous_block.get(), _stream->timestamp.get(), _stream->bits.get(), _stream->nonce.get());
        }
    };

    struct BlockHeaderType :
            StreamTypeAdapter<types::BlockHeaderType, stream::BlockHeaderType_stream>
    {
        void _to_stream() override
        {
            make_stream(*_value);
        }

        void _to_value() override
        {
            make_value(_stream->version.value, _stream->previous_block.get(), _stream->timestamp.get(), _stream->bits.get(), _stream->nonce.get(), _stream->merkle_root.get());
        }
    };

    struct BlockTypeA :
            StreamTypeAdapter<types::BlockType, stream::BlockType_stream>
    {
        void _to_stream() override
        {
            make_stream(*_value);
        }

        void _to_value() override
        {
            BlockHeaderType _block_header;
            _block_header.set_stream(stream()->header);

            make_value(*_block_header.get(), stream()->txs.get());
        }
    };
}