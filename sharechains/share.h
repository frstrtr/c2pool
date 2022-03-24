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

#include "share_adapters.h"
//#include "data.h"
using namespace shares::stream;

class ShareTracker;

class Share
{
public:
	const uint64_t SHARE_VERSION; //init in constructor
	static const int32_t gentx_size = 50000;

    shared_ptr<c2pool::Network> net;
    c2pool::libnet::addr peer_addr;
public:
    ///objs
	std::shared_ptr<SmallBlockHeaderType> min_header;
    std::shared_ptr<ShareData> share_data;
    std::shared_ptr<SegwitData> segwit_data;
    std::shared_ptr<ShareInfo> share_info;
    std::shared_ptr<MerkleLink> ref_merkle_link;
	uint64_t last_txout_nonce;
    std::shared_ptr<HashLinkType> hash_link;
    std::shared_ptr<MerkleLink> merkle_link;
public:
    ///Reference to objs
	//============share_data=============
//TODO: Init:
	std::unique_ptr<uint256> previous_hash;
    std::unique_ptr<string> coinbase;
    std::unique_ptr<unsigned int> nonce;
    std::unique_ptr<uint160> pubkey_hash;
    std::unique_ptr<unsigned long long> subsidy;
    std::unique_ptr<unsigned short> donation;
    std::unique_ptr<StaleInfo> stale_info;
    std::unique_ptr<unsigned long long> desired_version;
	//===================================

    ///Other reference
    std::unique_ptr<vector<uint256>> new_transaction_hashes;
    std::unique_ptr<uint256> max_target; //from max_bits; //TODO: init
    std::unique_ptr<uint256> target;     //from bits; //TODO: init
    std::unique_ptr<int32_t> timestamp;
    std::unique_ptr<int32_t> absheight;
    std::unique_ptr<uint128> abswork;

public:
    ///other
    //TODO: init
    PackStream new_script; //FROM pubkey_hash;

//TODO: gentx_hash

	BlockHeaderType header; //TODO: init
	uint256 pow_hash; //TODO: init
	uint256 hash; //=header_hash //TODO: init
	int32_t time_seen;

public:
	Share(uint64_t version, std::shared_ptr<c2pool::Network> _net, c2pool::libnet::addr _addr) : SHARE_VERSION(version)
	{
        net = _net;
        peer_addr = _addr;
	}

    ///check for verify share
    void check(std::shared_ptr<ShareTracker> _tracker);

    ~Share()
    {
        //share_data reference
        previous_hash.release();
        coinbase.release();
        nonce.release();
        pubkey_hash.release();
        subsidy.release();
        donation.release();
        stale_info.release();
        desired_version.release();

        //other reference
        new_transaction_hashes.release();
        max_target.release();
        target.release();
        timestamp.release();
        absheight.release();
        abswork.release();
    }
};

typedef std::shared_ptr<Share> ShareType;

ShareType load_share(PackStream &stream, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr);