#ifndef C2POOL_SHARE_BUILDER_H
#define C2POOL_SHARE_BUILDER_H

#include "share.h"

#include <memory>
#include <utility>
#include <networks/network.h>

// When update Builder -> update pack_share

class BaseShareBuilder
{
protected:
	ShareType share;
	c2pool::Network* net;
public:
	BaseShareBuilder(c2pool::Network* _net) : net(_net)
	{
		Reset();
	}

	void create(uint64_t version, const NetAddress& addr)
	{
		share = std::make_shared<Share>(version, net, addr);
	}

	void Reset()
	{
		share = nullptr;
	}

	ShareType GetShare()
	{
        share->init();
		auto result = share;
		Reset();
		return result;
	}

protected:
    void _min_header(std::shared_ptr<coind::data::SmallBlockHeaderType> value)
    {
        share->min_header = value;
    }

    void _share_data(std::shared_ptr<ShareData> value)
    {
        share->share_data = value;

        share->previous_hash = std::unique_ptr<uint256>(&(*value)->previous_share_hash);
        share->coinbase = std::unique_ptr<std::vector<unsigned char>>(&(*value)->coinbase);
        share->nonce = std::unique_ptr<uint32_t>(&(*value)->nonce);
        share->addr = std::unique_ptr<shares::types::ShareAddrType>(&(*value)->addr);
        share->subsidy = std::unique_ptr<uint64_t>(&(*value)->subsidy);
        share->donation = std::unique_ptr<uint16_t>(&(*value)->donation);
        share->stale_info = std::unique_ptr<StaleInfo>(&(*value)->stale_info);
        share->desired_version = std::unique_ptr<uint64_t>(&(*value)->desired_version);
    }

    void _segwit_data(std::shared_ptr<SegwitData> value)
    {
        share->segwit_data = std::move(value);
    }

    void _share_tx_info(const std::shared_ptr<ShareTxInfo>& value)
    {
        share->share_tx_info = value;
        share->new_transaction_hashes = std::unique_ptr<vector<uint256>>(&(*value)->new_transaction_hashes);
    }

    void _share_info(const std::shared_ptr<ShareInfo>& value)
    {
        share->share_info = value;

        share->max_target = FloatingInteger((*value)->max_bits).target();
        share->target = FloatingInteger((*value)->bits).target();
        share->timestamp = std::unique_ptr<uint32_t>(&(*value)->timestamp);
        share->absheight = std::unique_ptr<uint32_t>(&(*value)->absheight);
        share->abswork = std::unique_ptr<uint128>(&(*value)->abswork);

    }

    void _ref_merkle_link(std::shared_ptr<MerkleLink> value)
    {
        share->ref_merkle_link = value;
    }

    void _last_txout_nonce(uint64_t value)
    {
        share->last_txout_nonce = value;
    }

    void _hash_link(std::shared_ptr<HashLinkType> value)
    {
        share->hash_link = value;
    }

    void _merkle_link(std::shared_ptr<MerkleLink> value)
    {
        share->merkle_link = value;
    }
};

// Build Share from shares::types
class ShareObjectBuilder : public BaseShareBuilder, public enable_shared_from_this<ShareObjectBuilder>
{
public:
	ShareObjectBuilder(c2pool::Network* _net) : BaseShareBuilder(_net) { }
public:
    auto min_header(const coind::data::types::SmallBlockHeaderType &data)
    {
        auto value = std::make_shared<coind::data::SmallBlockHeaderType>();
        value->set_value(data);
        _min_header(value);
        return shared_from_this();
    }

    auto share_data(const shares::types::ShareData &data)
    {
        auto value = std::make_shared<ShareData>();
        value->set_value(data);
        _share_data(value);
        return shared_from_this();
    }

    auto segwit_data(const shares::types::SegwitData &data)
    {
        auto value = std::make_shared<SegwitData>();
        value->set_value(data);
        _segwit_data(value);
        return shared_from_this();
    }

    auto share_tx_info(const shares::types::ShareTxInfo &data)
    {
        auto value = std::make_shared<ShareTxInfo>();
        value->set_value(data);
        _share_tx_info(value);
        return shared_from_this();
    }

    auto share_info(const shares::types::ShareInfo &data)
    {
        auto value = std::make_shared<ShareInfo>();
        value->set_value(data);
        _share_info(value);
        return shared_from_this();
    }

    auto ref_merkle_link(const coind::data::MerkleLink &data)
    {
        auto value = std::make_shared<MerkleLink>();
        value->set_value(data);
        _ref_merkle_link(value);
        return shared_from_this();
    }

    auto last_txout_nonce(const uint64_t &data)
    {
        _last_txout_nonce(data);
        return shared_from_this();
    }

    auto hash_link(const shares::types::HashLinkType &data)
    {
        auto value = std::make_shared<HashLinkType>();
        value->set_value(data);
        _hash_link(value);
        return shared_from_this();
    }

    auto merkle_link(const coind::data::MerkleLink &data)
    {
        auto value = std::make_shared<MerkleLink>();
        value->set_value(data);
        _merkle_link(value);
        return shared_from_this();
    }
};

// Build share from PackStream
class ShareStreamBuilder : public BaseShareBuilder, public enable_shared_from_this<ShareStreamBuilder>
{
public:
	ShareStreamBuilder(c2pool::Network* _net) : BaseShareBuilder(_net) { }
public:
	auto min_header(PackStream &stream)
	{
		auto value = std::make_shared<coind::data::SmallBlockHeaderType>();
		stream >> *value;
        _min_header(value);
		return shared_from_this();
	}

    // is_pubkey_hash: true -- pubkey_hash; false -- address.
	auto share_data(PackStream &stream, shares::types::ShareAddrType::Type addr_type)
    {
        auto value = std::make_shared<ShareData>(addr_type);
        stream >> *value;
        _share_data(value);
		return shared_from_this();
	}

	auto segwit_data(PackStream &stream)
    {
        auto value = std::make_shared<SegwitData>();
        stream >> *value;
        _segwit_data(value);
		return shared_from_this();
	}

    auto share_tx_info(PackStream &stream)
    {
        auto value = std::make_shared<ShareTxInfo>();
        stream >> *value;
        _share_tx_info(value);
        return shared_from_this();
    }

	auto share_info(PackStream &stream)
	{
        auto value = std::make_shared<ShareInfo>();
        stream >> *value;
        _share_info(value);
		return shared_from_this();
	}

	auto ref_merkle_link(PackStream &stream)
	{
        auto value = std::make_shared<MerkleLink>();
        stream >> *value;
        _ref_merkle_link(value);
		return shared_from_this();
	}

	auto last_txout_nonce(PackStream &stream)
	{
		IntType(64) value;
        stream >> value;
        _last_txout_nonce(value.get());
		return shared_from_this();
	}

	auto hash_link(PackStream &stream)
	{
        auto value = std::make_shared<HashLinkType>();
        stream >> *value;
        _hash_link(value);
		return shared_from_this();
	}

	auto merkle_link(PackStream &stream)
	{
        auto value = std::make_shared<MerkleLink>();
        stream >> *value;
        _merkle_link(value);
		return shared_from_this();
	}
};

class ShareDirector
{
private:
	std::shared_ptr<ShareStreamBuilder> builder;
public:
	ShareDirector(c2pool::Network* _net)
	{
		builder = std::make_shared<ShareStreamBuilder>(_net);
	}

	ShareType make_share(uint64_t version, const NetAddress &addr, PackStream& stream)
	{
		builder->create(version, addr);
		builder->min_header(stream)
				->share_data(stream, shares::types::ShareAddrType::Type::pubkey_hash_type)
                ->share_tx_info(stream)
				->share_info(stream)
				->ref_merkle_link(stream)
				->last_txout_nonce(stream)
				->hash_link(stream)
				->merkle_link(stream);
        return builder->GetShare();
	}

	ShareType make_preSegwitShare(uint64_t version, const NetAddress &addr, PackStream& stream)
	{
		builder->create(version, addr);
		builder->min_header(stream)
				->share_data(stream, shares::types::ShareAddrType::Type::pubkey_hash_type)
				->segwit_data(stream)
                ->share_tx_info(stream)
				->share_info(stream)
				->ref_merkle_link(stream)
				->last_txout_nonce(stream)
				->hash_link(stream)
				->merkle_link(stream);
        return builder->GetShare();
	}

    ShareType make_segwitMiningShare(uint64_t version, const NetAddress &addr, PackStream& stream)
    {
        builder->create(version, addr);
        builder->min_header(stream)
                ->share_data(stream, shares::types::ShareAddrType::Type::address_type)
                ->segwit_data(stream)
                ->share_info(stream)
                ->ref_merkle_link(stream)
                ->last_txout_nonce(stream)
                ->hash_link(stream)
                ->merkle_link(stream);
        return builder->GetShare();
    }
};

#endif //C2POOL_SHARE_BUILDER_H
