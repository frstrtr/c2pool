#pragma once

#include <boost/format.hpp>
#include <libcoind/data.h>
#include <btclibs/uint256.h>
#include <networks/network.h>
#include <libdevcore/addrStore.h>
#include <libdevcore/types.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string, std::make_shared;
using std::vector, std::tuple, std::map;

#include "share_types.h"
#include "data.h"

class ShareTracker;

class Share
{
public:
	const uint64_t SHARE_VERSION; //init in constructor
	static const int32_t gentx_size = 50000;
public:
	std::shared_ptr<SmallBlockHeaderType> min_header;
    std::shared_ptr<ShareData> share_data;
    std::shared_ptr<SegwitData> segwit_data;
    std::shared_ptr<ShareInfo> share_info;
	std::shared_ptr<MerkleLink> ref_merkle_link;
	unsigned long long last_txout_nonce;
	std::shared_ptr<HashLinkType> hash_link;
	std::shared_ptr<MerkleLink> merkle_link;
public:
//	//============share_data=============
//	uint256 previous_hash;
//	string coinbase;
//	unsigned int nonce;
//	uint160 pubkey_hash;
//	unsigned long long subsidy;
//	unsigned short donation;
//	StaleInfo stale_info;
//	unsigned long long desired_version;
//	//===================================
//
//	vector<uint256> new_transaction_hashes;
//	vector<tuple<int, int>> transaction_hash_refs; //TODO: check+test; # pairs of share_count, tx_count
//	uint256 far_share_hash;
//	uint256 max_target; //from max_bits;
//	uint256 target;     //from bits;
//	int32_t timestamp;
//	int32_t absheight;
//	uint128 abswork;
//	std::vector<unsigned char> new_script; //TODO: self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash']) //FROM pubkey_hash;
//	//TODO: gentx_hash
//	BlockHeaderType header;
//	uint256 pow_hash;
//	uint256 hash; //=header_hash
//	int32_t time_seen;

	shared_ptr<c2pool::Network> net;
	c2pool::libnet::addr peer_addr;

public:
	Share(uint64_t version, std::shared_ptr<c2pool::Network> _net, c2pool::libnet::addr _addr) : SHARE_VERSION(version)
	{
        net = _net;
        peer_addr = _addr;
	}
};

typedef std::shared_ptr<Share> ShareType;

class ShareBuilder : enable_shared_from_this<ShareBuilder>
{
private:
	ShareType share;

	std::shared_ptr<c2pool::Network> net;
public:
	ShareBuilder(std::shared_ptr<c2pool::Network> _net) : net(_net)
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

public:
	auto min_header(PackStream &stream)
	{
		SmallBlockHeaderType_stream _min_header;
		stream >> _min_header;
		return shared_from_this();
	}

    auto share_data(PackStream &stream){
        ShareData_stream share_data;
        stream >> share_data;
        return shared_from_this();
    }

    auto segwit_data(PackStream &stream){
        PossibleNoneType<SegwitData_stream> segwit_data;
        stream >> segwit_data;
        return shared_from_this();
    }

	auto share_info(PackStream &stream)
	{
		ShareInfo_stream _share_info;
		stream >> _share_info;
		return shared_from_this();
	}

	auto ref_merkle_link(PackStream &stream)
	{
		MerkleLink_stream _ref_merkle_link;
		stream >> _ref_merkle_link;
		return shared_from_this();
	}

	auto last_txout_nonce(PackStream &stream)
	{
		IntType(64) _last_txout_nonce;
		stream >> _last_txout_nonce;
		return shared_from_this();
	}

	auto hash_link(PackStream &stream)
	{
		HashLinkType_stream _hash_link;
		stream >> _hash_link;
		return shared_from_this();
	}

	auto merkle_link(PackStream &stream)
	{
		MerkleLink_stream _merkle_link;
		stream >> _merkle_link;
		return shared_from_this();
	}
};

class ShareDirector
{
private:
	std::shared_ptr<ShareBuilder> builder;
public:
	ShareDirector(std::shared_ptr<c2pool::Network> _net)
	{
		builder = std::make_shared<ShareBuilder>(_net);
	}

	ShareType make_Share(uint64_t version, const c2pool::libnet::addr &addr, PackStream& stream)
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

	ShareType make_PreSegwitShare(uint64_t version, const c2pool::libnet::addr &addr, PackStream& stream)
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

ShareType load_share(PackStream &stream, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr);