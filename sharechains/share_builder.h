#ifndef C2POOL_SHARE_BUILDER_H
#define C2POOL_SHARE_BUILDER_H

#include "share.h"

#include <memory>
#include <networks/network.h>

class BaseShareBuilder
{
protected:
	ShareType share;
	std::shared_ptr<c2pool::Network> net;
public:
	BaseShareBuilder(std::shared_ptr<c2pool::Network> _net) : net(_net)
	{
		Reset();
	}

	void create(int64_t version, c2pool::libnet::addr addr)
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
    void _min_header(std::shared_ptr<SmallBlockHeaderType> value)
    {
        share->min_header = value;
    }

    void _share_data(std::shared_ptr<ShareData> value)
    {
        share->share_data = value;

        share->previous_hash = std::unique_ptr<uint256>(&(*value)->previous_share_hash);
        share->coinbase = std::unique_ptr<std::string>(&(*value)->coinbase);
        share->nonce = std::unique_ptr<uint32_t>(&(*value)->nonce);
        share->pubkey_hash = std::unique_ptr<uint160>(&(*value)->pubkey_hash);
        share->subsidy = std::unique_ptr<uint64_t>(&(*value)->subsidy);
        share->donation = std::unique_ptr<uint16_t>(&(*value)->donation);
        share->stale_info = std::unique_ptr<StaleInfo>(&(*value)->stale_info);
        share->desired_version = std::unique_ptr<uint64_t>(&(*value)->desired_version);
    }

    void _segwit_data(std::shared_ptr<SegwitData> value)
    {
        share->segwit_data = value;
    }

    void _share_info(std::shared_ptr<ShareInfo> value)
    {
        share->share_info = value;

        share->max_target = FloatingInteger((*value)->max_bits).target();
        share->target = FloatingInteger((*value)->bits).target();
        share->timestamp = std::unique_ptr<uint32_t>(&(*value)->timestamp);
        share->absheight = std::unique_ptr<uint32_t>(&(*value)->absheigth);
        share->abswork = std::unique_ptr<uint128>(&(*value)->abswork);
        share->new_transaction_hashes = std::unique_ptr<vector<uint256>>(&(*value)->new_transaction_hashes);
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

class ShareObjectBuilder : public BaseShareBuilder, enable_shared_from_this<ShareObjectBuilder>
{
public:
	ShareObjectBuilder(std::shared_ptr<c2pool::Network> _net) : BaseShareBuilder(_net) { }
public:
    auto min_header(const shares::types::SmallBlockHeaderType &data)
    {
        auto value = std::make_shared<SmallBlockHeaderType>();
        value->set_value(data);
        _min_header(value);
        return shared_from_this();
    }

    auto share_data(const shares::types::ShareData &data){
        auto value = std::make_shared<ShareData>();
        value->set_value(data);
        _share_data(value);
        return shared_from_this();
    }

    auto segwit_data(const shares::types::SegwitData &data){
        auto value = std::make_shared<SegwitData>();
        value->set_value(data);
        _segwit_data(value);
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

class ShareStreamBuilder : public BaseShareBuilder, enable_shared_from_this<ShareStreamBuilder>
{
public:
	ShareStreamBuilder(std::shared_ptr<c2pool::Network> _net) : BaseShareBuilder(_net) { }
public:
	auto min_header(PackStream &stream)
	{
		auto value = std::make_shared<SmallBlockHeaderType>();
		stream >> *value;
        _min_header(value);
		return shared_from_this();
	}

	auto share_data(PackStream &stream){
        auto value = std::make_shared<ShareData>();
        stream >> *value;
        _share_data(value);
		return shared_from_this();
	}

	auto segwit_data(PackStream &stream){
        auto value = std::make_shared<SegwitData>();
        stream >> *value;
        _segwit_data(value);
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
	ShareDirector(std::shared_ptr<c2pool::Network> _net)
	{
		builder = std::make_shared<ShareStreamBuilder>(_net);
	}

	ShareType make_share(uint64_t version, const c2pool::libnet::addr &addr, PackStream& stream)
	{
		builder->create(version, addr);
		builder->min_header(stream)
				->share_data(stream)
				->share_info(stream)
				->ref_merkle_link(stream)
				->last_txout_nonce(stream)
				->hash_link(stream)
				->merkle_link(stream);
        return builder->GetShare();
	}

	ShareType make_preSegwitShare(uint64_t version, const c2pool::libnet::addr &addr, PackStream& stream)
	{
		builder->create(version, addr);
		builder->min_header(stream)
				->share_data(stream)
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