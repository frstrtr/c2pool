#pragma once

#include <boost/format.hpp>
#include <libcoind/data.h>
#include <btclibs/uint256.h>
#include <libdevcore/dbObject.h>
#include <networks/network.h>
#include <libdevcore/addrStore.h>
#include <libdevcore/types.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

using dbshell::DBObject;

#include <string>
#include <memory>
#include <tuple>
#include <vector>
#include <map>

using std::shared_ptr, std::string, std::make_shared;
using std::vector, std::tuple, std::map;

#include "shareTypes.h"
#include "data.h"

class ShareTracker;



class BaseShare //: public DBObject
{
public:
    const int SHARE_VERSION; //init in constructor
    static const int32_t gentx_size = 50000;
protected:
	StrType contents;
	ShareType_stream share_type_data;

public:


//public:
//    SmallBlockHeaderType min_header;
//    ShareInfo share_info;
//    MerkleLink ref_merkle_link; //FOR?
//    unsigned long long last_txout_nonce;
//    HashLinkType hash_link;
//    MerkleLink merkle_link;
//
//public:
//    //============share_data=============
//    uint256 previous_hash;
//    string coinbase;
//    unsigned int nonce;
//    uint160 pubkey_hash;
//    unsigned long long subsidy;
//    unsigned short donation;
//    StaleInfo stale_info;
//    unsigned long long desired_version;
//    //===================================
//
//    vector<uint256> new_transaction_hashes;
//    vector<tuple<int, int>> transaction_hash_refs; //TODO: check+test; # pairs of share_count, tx_count
//    uint256 far_share_hash;
//    uint256 max_target; //from max_bits;
//    uint256 target;     //from bits;
//    int32_t timestamp;
//    int32_t absheight;
//    uint128 abswork;
//    char *new_script; //TODO: self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash']) //FROM pubkey_hash;
//    //TODO: gentx_hash
//    BlockHeaderType header;
//    uint256 pow_hash;
//    uint256 hash; //=header_hash
//    int32_t time_seen;
//
//    shared_ptr<c2pool::Network> net;
//    c2pool::libnet::addr peer_addr;
//    UniValue contents;
//    //TODO: segwit ???

public:
    BaseShare(int VERSION, shared_ptr<c2pool::Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents);

//    virtual string SerializeJSON() override;
//
//    virtual void DeserializeJSON(std::string json) override;

    bool is_segwit_activated() const
    {
        return c2pool::shares::is_segwit_activated(SHARE_VERSION, net);
    }

//    virtual void contents_load(UniValue contents);
//
//    virtual UniValue to_contents();

    virtual bool check(shared_ptr<ShareTracker> tracker /*, TODO: other_txs = None???*/);

    static PackStream get_ref_hash(shared_ptr<c2pool::Network> _net, ShareInfo _share_info, MerkleLink _ref_merkle_link)
    {
        PackStream res;

        RefType ref_type_value(_net->IDENTIFIER, _share_info);
        PackStream ref_type_stream;
        ref_type_stream << ref_type_value;
        auto ref_type_hash = coind::data::hash256(ref_type_stream);

        auto unpacked_res = coind::data::check_merkle_link(ref_type_hash, std::make_tuple(_ref_merkle_link.branch,
                                                                                          _ref_merkle_link.index));

        IntType(256) packed_res(unpacked_res);
        res << packed_res;

        return res;
    }

    PackStream &write(PackStream &stream)
    {
		//TODO:
		stream << share_type_data;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
		stream >> share_type_data;
        return stream;
    }
};

//17
class Share : public BaseShare
{
public:
    Share(shared_ptr<c2pool::Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents) : BaseShare(17, _net,
                                                                                                     _peer_addr,
                                                                                                     _contents)
    {}

//    virtual void contents_load(UniValue contents) override;

PackStream &write(PackStream &stream)
	{
		//TODO:
		stream << share_type_data;
		return stream;
	}

	PackStream &read(PackStream &stream)
	{
		stream >> share_type_data;
		return stream;
	}
};

//32
class PreSegwitShare : public BaseShare
{
public:
    SegwitData segwit_data;

public:
    PreSegwitShare(shared_ptr<c2pool::Network> _net, c2pool::libnet::addr _peer_addr, UniValue _contents) : BaseShare(32, _net,
                                                                                                              _peer_addr,
                                                                                                              _contents)
    {
        if (merkle_link.branch.size() > 16 ||
            (is_segwit_activated() && segwit_data.txid_merkle_link.branch.size() > 16))
        {
            throw std::runtime_error("merkle branch too long!");
        }
    }

//    virtual void contents_load(UniValue contents) override;
	PackStream &write(PackStream &stream)
	{
		//TODO:
		stream << share_type_data;
		return stream;
	}

	PackStream &read(PackStream &stream)
	{
		stream >> share_type_data;
		return stream;
	}
};

class Share
{
public:
	const uint64_t SHARE_VERSION; //init in constructor
	static const int32_t gentx_size = 50000;
public:
	std::shared_ptr<SmallBlockHeaderType> min_header;
	std::shared_ptr<ShareInfo> share_info;
	std::shared_ptr<MerkleLink> ref_merkle_link;
	unsigned long long last_txout_nonce;
	std::shared_ptr<HashLinkType> hash_link;
	std::shared_ptr<MerkleLink> merkle_link;
	std::shared_ptr<SegwitData> segwit_data;
public:
	//============share_data=============
	uint256 previous_hash;
	string coinbase;
	unsigned int nonce;
	uint160 pubkey_hash;
	unsigned long long subsidy;
	unsigned short donation;
	StaleInfo stale_info;
	unsigned long long desired_version;
	//===================================

	vector<uint256> new_transaction_hashes;
	vector<tuple<int, int>> transaction_hash_refs; //TODO: check+test; # pairs of share_count, tx_count
	uint256 far_share_hash;
	uint256 max_target; //from max_bits;
	uint256 target;     //from bits;
	int32_t timestamp;
	int32_t absheight;
	uint128 abswork;
	std::vector<unsigned char> new_script; //TODO: self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash']) //FROM pubkey_hash;
	//TODO: gentx_hash
	BlockHeaderType header;
	uint256 pow_hash;
	uint256 hash; //=header_hash
	int32_t time_seen;

	shared_ptr<c2pool::Network> net;
	c2pool::libnet::addr peer_addr;

public:
	Share(uint64_t version) : SHARE_VERSION(version)
	{

	}
};

class ShareBuilder : enable_shared_from_this<ShareBuilder>
{
private:
	std::shared_ptr<Share> share;

	std::shared_ptr<c2pool::Network> net;
public:
	ShareBuilder(std::shared_ptr<c2pool::Network> _net) : net(_net)
	{
		Reset();
	}

	void create(int64_t version)
	{
		share = std::make_shared<Share>(version);
	}

	void Reset()
	{
		share = nullptr;
	}

	std::shared_ptr<Share> GetShare()
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

	std::shared_ptr<Share> make_Share(uint64_t version, PackStream& stream)
	{
		builder->create(version);
		builder->min_header(stream)
			->share_info(stream)
			->ref_merkle_link(stream)
			->last_txout_nonce(stream)
			->hash_link(stream)
			->merkle_link(stream);
	}

	std::shared_ptr<Share> make_PreSegwitShare(uint64_t version, PackStream& stream)
	{
		builder->create(version);
		builder->min_header(stream)
			->share_info(stream)
			->ref_merkle_link(stream)
			->segwit_data(stream)
			->last_txout_nonce(stream)
			->hash_link(stream)
			->merkle_link(stream);
	}
};

shared_ptr<BaseShare> load_share(UniValue share, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr);