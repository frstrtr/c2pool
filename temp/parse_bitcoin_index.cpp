#include <iostream>
// #include <core/pack.hpp>
// #include <core/pack_types.hpp>

#include <btclibs/uint256.h>
#include <btclibs/serialize.h>
#include <btclibs/streams.h>
#include <btclibs/util/strencodings.h>

enum BlockStatus : uint32_t {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Reserved (was BLOCK_VALID_HEADER).
    BLOCK_VALID_RESERVED     =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS.
     *
     * If a block's validity is at least VALID_TRANSACTIONS, CBlockIndex::nTx will be set. If a block and all previous
     * blocks back to the genesis block or an assumeutxo snapshot block are at least VALID_TRANSACTIONS,
     * CBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all previous blocks back to the genesis block or an assumeutxo snapshot block are at least VALID_CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all previous blocks back to the genesis block or an assumeutxo snapshot block
    //! are at least VALID_SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_RESERVED | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //!< full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //!< descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,

    BLOCK_OPT_WITNESS        =   128, //!< block data in blk*.dat was received with a witness-enforcing client

    BLOCK_STATUS_RESERVED    =   256, //!< Unused flag that was previously set on assumeutxo snapshot blocks and their
                                      //!< ancestors before they were validated, and unset when they were validated.
};


struct Index
{
    //! pointer to the hash of the block, if any. Memory is owned by this CBlockIndex
    // const uint256* phashBlock{nullptr};

    // //! pointer to the index of the predecessor of this block
    // CBlockIndex* pprev{nullptr};

    // //! pointer to the index of some further predecessor of this block
    // CBlockIndex* pskip{nullptr};

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight{0};

    //! Which # file this block is stored in (blk?????.dat)
    int nFile /*GUARDED_BY(::cs_main)*/{0};

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos /*GUARDED_BY(::cs_main)*/{0};

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos /*GUARDED_BY(::cs_main)*/{0};

    // //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    // arith_uint256 nChainWork{};

    //! Number of transactions in this block. This will be nonzero if the block
    //! reached the VALID_TRANSACTIONS level, and zero otherwise.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx{0};

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero if this block and all previous blocks back
    //! to the genesis block or an assumeutxo snapshot block have reached the
    //! VALID_TRANSACTIONS level.
    //! Change to 64-bit type before 2024 (assuming worst case of 60 byte transactions).
    unsigned int nChainTx{0};

    // //! Verification status of this block. See enum BlockStatus
    // //!
    // //! Note: this value is modified to show BLOCK_OPT_WITNESS during UTXO snapshot
    // //! load to avoid the block index being spuriously rewound.
    // //! @sa NeedsRedownload
    // //! @sa ActivateSnapshot
    uint32_t nStatus /*GUARDED_BY(::cs_main)*/{0};

    //! block header
    int32_t nVersion{0};
    legacy::uint256 hashMerkleRoot{};
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    int32_t nSequenceId{0};

    //! (memory only) Maximum nTime in the chain up to and including this block.
    unsigned int nTimeMax{0};
};

struct DiskIndex : public Index
{
    static constexpr int DUMMY_VERSION = 259900;
    legacy::uint256 hashPrev;

    SERIALIZE_METHODS(DiskIndex, obj)
    {
        int _nVersion = DUMMY_VERSION;
        READWRITE(legacy::VARINT_MODE(_nVersion, legacy::VarIntMode::NONNEGATIVE_SIGNED));

        READWRITE(legacy::VARINT_MODE(obj.nHeight, legacy::VarIntMode::NONNEGATIVE_SIGNED));
        READWRITE(legacy::VARINT(obj.nStatus));
        READWRITE(legacy::VARINT(obj.nTx));
        if (obj.nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)) READWRITE(legacy::VARINT_MODE(obj.nFile, legacy::VarIntMode::NONNEGATIVE_SIGNED));
        if (obj.nStatus & BLOCK_HAVE_DATA) READWRITE(legacy::VARINT(obj.nDataPos));
        if (obj.nStatus & BLOCK_HAVE_UNDO) READWRITE(legacy::VARINT(obj.nUndoPos));

        // // block header
        READWRITE(obj.nVersion);
        READWRITE(obj.hashPrev);
        READWRITE(obj.hashMerkleRoot);
        READWRITE(obj.nTime);
        READWRITE(obj.nBits);
        READWRITE(obj.nNonce);
    }
};

#define PRINT_I(value) std::cout << #value << ":" << index. value << std::endl;
#define PRINTT_I(value) std::cout << "\t" << #value << ":" << index. value << std::endl;

int main()
{
    auto data = ParseHex("572fe3011b5bede64c91a5338fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b260071900000000001937917bd2caba204bb1aa530ec1de9d0f6736e5d85d96da9c8bba0000000129ffd98136b19a8e00021d00f0833ced8e");
    std::reverse(data.begin(), data.end());

    DataStream stream(data);
    DiskIndex index;
    stream >> index;

    PRINT_I(nHeight);
    PRINT_I(nStatus);
    PRINT_I(nTx);
    PRINT_I(nFile);
    PRINT_I(nDataPos);
    PRINT_I(nUndoPos);

    //header
    std::cout << "header:" << std::endl;
    PRINTT_I(nVersion);
    // PRINT_I(hashPrev);
    std::cout << "\thashPrev" << ":" << index.hashPrev.GetHex() << std::endl;
    // PRINT_I(hashMerkleRoot);
    std::cout << "\thashMerkleRoot" << ":" << index.hashMerkleRoot.GetHex() << std::endl;
    PRINTT_I(nTime);
    PRINTT_I(nBits);
    PRINTT_I(nNonce);
}