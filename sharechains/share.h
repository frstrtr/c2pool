#pragma once

#include <boost/format.hpp>
#include <libcoind/data.h>
#include <libcoind/transaction.h>
#include <libcoind/types.h>
#include <btclibs/uint256.h>
#include <networks/network.h>
#include <libdevcore/addr_store.h>
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

#define SHARE_VERSION 17
#define PreSegwitShare_VERSION 32

class Share
{
public:
	const uint64_t VERSION; // Share version, init in constructor
	static const int32_t gentx_size = 50000;

    c2pool::Network* net;
    NetAddress peer_addr;
public:
    ///objs
	std::shared_ptr<coind::data::SmallBlockHeaderType> min_header;
    std::shared_ptr<ShareData> share_data;
    std::shared_ptr<SegwitData> segwit_data;
    std::shared_ptr<ShareTxInfo> share_tx_info;
    std::shared_ptr<ShareInfo> share_info;
    std::shared_ptr<MerkleLink> ref_merkle_link;
	uint64_t last_txout_nonce;
    std::shared_ptr<HashLinkType> hash_link;
    std::shared_ptr<MerkleLink> merkle_link;
public:
    ///Reference to objs
	//============share_data=============
	std::unique_ptr<uint256> previous_hash;
    std::unique_ptr<std::vector<unsigned char>> coinbase;
    std::unique_ptr<uint32_t> nonce;
    std::unique_ptr<shares::types::ShareAddrType> addr;
    std::unique_ptr<uint64_t> subsidy;
    std::unique_ptr<uint16_t> donation;
    std::unique_ptr<StaleInfo> stale_info;
    std::unique_ptr<uint64_t> desired_version;
	//===================================

    ///Other reference
    std::unique_ptr<vector<uint256>> new_transaction_hashes;
    uint256 max_target; //from max_bits;
    uint256 target;     //from bits;
    std::unique_ptr<uint32_t> timestamp;
    std::unique_ptr<uint32_t> absheight;
    std::unique_ptr<uint128> abswork;

public:
    ///other
    PackStream new_script; //FROM pubkey_hash;
    std::string address;

    uint256 gentx_hash;
    coind::data::BlockHeaderType header;
	uint256 pow_hash;
	uint256 hash; //=header_hash
	int32_t time_seen;

    int32_t gentx_weight;
public:
	Share(uint64_t version, c2pool::Network* _net, const NetAddress& _addr) : VERSION(version)
	{
        net = _net;
        peer_addr = _addr;
	}

	~Share()
	{
		//share_data reference
		previous_hash.release();
		coinbase.release();
		nonce.release();
		addr.release();
		subsidy.release();
		donation.release();
		stale_info.release();
		desired_version.release();

		//other reference
		new_transaction_hashes.release();
		timestamp.release();
		absheight.release();
		abswork.release();
	}

    /// called, when Builder finished building obj.
    void init();

    /// check for verify share.
    void check(ShareTracker* _tracker, std::optional<std::map<uint256, coind::data::tx_type>> other_txs = nullopt);
/* TODO:
	/// share -> block
	coind::data::stream::BlockType_stream as_block(const std::shared_ptr<ShareTracker>& _tracker, std::map<uint256, coind::data::tx_type> known_txs);

	std::vector<uint256> get_other_tx_hashes(const std::shared_ptr<ShareTracker>& _tracker);
	std::vector<coind::data::tx_type> _get_other_txs(const std::shared_ptr<ShareTracker>& _tracker, std::map<uint256, coind::data::tx_type> known_txs);
*/

    nlohmann::json json();
};

typedef std::shared_ptr<Share> ShareType;

PackedShareData pack_share(const ShareType& share);