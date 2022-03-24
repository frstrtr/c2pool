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
		auto result = share;
		Reset();
		return result;
	}
};

class ShareObjectBuilder : public BaseShareBuilder, enable_shared_from_this<ShareObjectBuilder>
{
public:
	ShareObjectBuilder(std::shared_ptr<c2pool::Network> _net) : BaseShareBuilder(_net) { }
public:

};

class ShareStreamBuilder : public BaseShareBuilder, enable_shared_from_this<ShareStreamBuilder>
{
public:
	ShareStreamBuilder(std::shared_ptr<c2pool::Network> _net) : BaseShareBuilder(_net) { }
public:
	auto min_header(PackStream &stream)
	{
		share->min_header = std::make_shared<SmallBlockHeaderType>();
		stream >> *share->min_header;
		return shared_from_this();
	}

	auto share_data(PackStream &stream){
		share->share_data = std::make_shared<ShareData>();
		stream >> *share->share_data;
		return shared_from_this();
	}

	auto segwit_data(PackStream &stream){
		share->segwit_data = std::make_shared<SegwitData>();
		stream >> *share->segwit_data;
		return shared_from_this();
	}

	auto share_info(PackStream &stream)
	{
		share->share_info = std::make_shared<ShareInfo>();
		stream >> *share->share_info;
		//TODO: share->target = (*share->share_info)->bits;
		return shared_from_this();
	}

	auto ref_merkle_link(PackStream &stream)
	{
		share->ref_merkle_link = std::make_shared<MerkleLink>();
		stream >> *share->ref_merkle_link;
		return shared_from_this();
	}

	auto last_txout_nonce(PackStream &stream)
	{
		IntType(64) _last_txout_nonce;
		stream >> _last_txout_nonce;
		share->last_txout_nonce = _last_txout_nonce.get();
		return shared_from_this();
	}

	auto hash_link(PackStream &stream)
	{
		share->hash_link = std::make_shared<HashLinkType>();
		stream >> *share->hash_link;
		return shared_from_this();
	}

	auto merkle_link(PackStream &stream)
	{
		share->merkle_link = std::make_shared<MerkleLink>();
		stream >> *share->merkle_link;
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
	}
};

#endif //C2POOL_SHARE_BUILDER_H
