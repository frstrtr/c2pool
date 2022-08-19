#include "share.h"

#include <stdexcept>
#include <tuple>
#include <set>
#include <string>

#include <univalue.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/addr_store.h>
#include "tracker.h"
#include "data.h"
#include "share_builder.h"


using namespace std;

#include <boost/format.hpp>

#define CheckShareRequirement(field_name)               \
    if (!field_name)                                     \
        throw std::runtime_error(#field_name " == NULL");

void Share::init()
{
    CheckShareRequirement(min_header);
    CheckShareRequirement(share_data);
    CheckShareRequirement(share_info);
    CheckShareRequirement(ref_merkle_link);
    CheckShareRequirement(hash_link);
    CheckShareRequirement(merkle_link);

    bool segwit_activated = shares::is_segwit_activated(VERSION, net);
    if (segwit_activated && !segwit_data)
        throw std::runtime_error("Segwit activated, but segwit_data == nullptr!");


    if (!(coinbase->size() >= 2 && coinbase->size() <= 100))
    {
        throw std::runtime_error((boost::format("bad coinbase size! %1% bytes.") % coinbase->size()).str());
    }

    if ((*merkle_link)->branch.size() > 16)
    {
        throw std::runtime_error("Merkle branch too long#1!");
    }

    if (segwit_activated)
        if ((*segwit_data)->txid_merkle_link.branch.size() > 16)
            throw std::runtime_error("Merkle branch too long#1!");

    assert(hash_link->get()->extra_data.empty());

    new_script = coind::data::pubkey_hash_to_script2((*share_data)->pubkey_hash);

    if (net->net_name == "bitcoin" && *absheight > 3927800 && *desired_version == 16)
    {
        throw std::runtime_error("This is not a hardfork-supporting share!");
    }

//TODO: check txs
//    std::set<int32_t> n;
//    for share_count, tx_count in self.iter_transaction_hash_refs():
//      assert share_count < 110
//      if share_count == 0:
//          n.add(tx_count)
//    assert n == set(range(len(self.share_info['new_transaction_hashes'])))

    std::vector<unsigned char> hash_link_data;
    {
        auto ref_hash = shares::get_ref_hash(net, *share_info->get(), *ref_merkle_link->get());
        hash_link_data = ref_hash.data;

        IntType(64) _last_txout_nonce(last_txout_nonce);
        PackStream packed_last_txout_nonce;
        packed_last_txout_nonce << _last_txout_nonce;
        hash_link_data.insert(hash_link_data.begin(), packed_last_txout_nonce.data.begin(), packed_last_txout_nonce.data.end());

        IntType(32) _z(0);
        PackStream packed_z;
        packed_z << _z;
        hash_link_data.insert(hash_link_data.begin(), packed_z.data.begin(), packed_z.data.end());
    }

    // TODO: for test
//    (*hash_link)->state.insert((*hash_link)->state.begin(), (unsigned char)31);

    std::cout << "HASH_LINK.length: " << (*hash_link)->length << std::endl;
    std::cout << "HASH_LINK.state: ";
    for (auto v : (*hash_link)->state)
        std::cout << (unsigned int)v << " ";
    std::cout << std::endl;
    std::cout << "HASH_LINK.extra_data == nullptr: " << ((*hash_link)->extra_data.data() == nullptr) << std::endl;
    std::cout << "=============" << std::endl;
    std::cout << "HASH_LINK_DATA: ";
    for (auto v : hash_link_data)
        std::cout << (unsigned int)v << " ";
    std::cout << std::endl;

    std::cout << "GENTX_BEFORE_REFHASH: ";
    for (auto v : net->gentx_before_refhash)
        std::cout << (unsigned int)v << " ";
    std::cout << std::endl;

    gentx_hash = shares::check_hash_link(hash_link, hash_link_data, net->gentx_before_refhash);
    std::cout << "GENTX: " << gentx_hash.GetHex() << std::endl;

    auto merkle_root = coind::data::check_merkle_link(gentx_hash, segwit_activated ? (*segwit_data)->txid_merkle_link : *merkle_link->get());
    std::cout << "FIRST MERKLE_ROOT: " << merkle_root.GetHex() << std::endl;
    header.set_value(coind::data::types::BlockHeaderType(*min_header->get(), merkle_root));

    coind::data::stream::BlockHeaderType_stream header_stream(*header.get());

    std::cout << "Version: " << header_stream.version.get() << std::endl;
    std::cout << "PreviousBlock: " << header_stream.previous_block.get().GetHex() << std::endl;
    std::cout << "MerkleRoot: " << header_stream.merkle_root.get().GetHex() << std::endl;
    std::cout << "Timestamp: " << header_stream.timestamp.get() << std::endl;
    std::cout << "Bits: " << header_stream.bits.get() << std::endl;
    std::cout << "Nonce: " << header_stream.nonce.get() << std::endl;
    PackStream packed_block_header;
    packed_block_header << header_stream;


    std::cout << "BlockHeader: " << HexStr(packed_block_header.data) << "[END]" << std::endl;
    pow_hash = net->parent->POW_FUNC(packed_block_header);


    PackStream packed_block_header2;
    packed_block_header2 << header_stream;
    hash = coind::data::hash256(packed_block_header2);

    if (target > net->MAX_TARGET)
    {
        throw std::runtime_error("Share target invalid!"); //TODO: remake for c2pool::p2p::exception_from_peer
    }

    std::cout << "POW_HASH:\t" << pow_hash.GetHex() << std::endl;
    std::cout << "Target:\t\t" << target.GetHex() << std::endl;
    if (UintToArith256(pow_hash) > UintToArith256(target))
    {
        throw std::runtime_error("Share PoW indalid!"); //TODO: remake for c2pool::p2p::exception_from_peer
    }
}
#undef CheckShareRequirement

void Share::check(std::shared_ptr<ShareTracker> _tracker, std::map<uint256, coind::data::tx_type> other_txs)
{
    if (*timestamp > (c2pool::dev::timestamp() + 600))
    {
        throw std::invalid_argument(
                (boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} %
                 (*timestamp - c2pool::dev::timestamp())).str());
    }

    std::map<uint64_t, uint256> counts;

    if (!previous_hash->IsNull())
    {
        auto previous_share = _tracker->get(*previous_hash);
        if (_tracker->get_height(*previous_hash) >= net->CHAIN_LENGTH)
        {
            //tracker.get_nth_parent_hash(previous_share.hash, self.net.CHAIN_LENGTH*9//10), self.net.CHAIN_LENGTH//10
            counts = _tracker->get_desired_version_counts(
                    _tracker->get_nth_parent_hash(previous_share->hash, net->CHAIN_LENGTH * 9 / 10),
                    net->CHAIN_LENGTH / 10);

            //TODO: python check for version
//            if type(self) is type(previous_share):
//                pass
//              elif type(self) is type(previous_share).SUCCESSOR:
//                  # switch only valid if 60% of hashes in [self.net.CHAIN_LENGTH*9//10, self.net.CHAIN_LENGTH] for new version
//                  if counts.get(self.VERSION, 0) < sum(counts.itervalues())*60//100:
//                      raise p2p.PeerMisbehavingError('switch without enough hash power upgraded')
//              else:
//                  raise p2p.PeerMisbehavingError('''%s can't follow %s''' % (type(self).__name__, type(previous_share).__name__))
        }
        //elif type(self) is type(previous_share).SUCCESSOR:
        //      raise p2p.PeerMisbehavingError('switch without enough history')
    }

    std::vector<uint256> other_tx_hashes;
    for (auto v: (*share_info)->transaction_hash_refs)
    {
        auto share_count = std::get<0>(v);
        auto tx_count = std::get<1>(v);

        other_tx_hashes.push_back(_tracker->get(_tracker->get_nth_parent_hash(hash,
                                                                              share_count))->share_info->get()->new_transaction_hashes[tx_count]);
    }

    // TODO: Check type in python???
    //if other_txs is not None and not isinstance(other_txs, dict): other_txs = dict((bitcoin_data.hash256(bitcoin_data.tx_type.pack(tx)), tx) for tx in other_txs)

    auto gentx_F = GenerateShareTransaction(_tracker);
    gentx_F.set_share_data(*share_data->get());
    gentx_F.set_block_target(FloatingInteger(header->bits).target()); //TODO: check
    gentx_F.set_desired_timestamp(*timestamp);
    gentx_F.set_desired_target(FloatingInteger((*share_info)->bits).target()); //TODO: check
    gentx_F.set_ref_merkle_link(*ref_merkle_link->get());
    {
        std::vector<std::tuple<uint256, std::optional<int32_t>>> _desired_other_transaction_hashes_and_fees;
        for (auto v: other_tx_hashes)
        {
            std::optional<int32_t> temp_value{};
            _desired_other_transaction_hashes_and_fees.emplace_back(v, temp_value);
        }
        gentx_F.set_desired_other_transaction_hashes_and_fees(_desired_other_transaction_hashes_and_fees);
    }
    gentx_F.set_known_txs(other_txs);
    gentx_F.set_last_txout_nonce(last_txout_nonce);
    if (segwit_data)
    {
        gentx_F.set_segwit_data(*segwit_data->get());
    }

    auto gentx = gentx_F(VERSION);

    //TODO: just check
//    assert other_tx_hashes2 == other_tx_hashes
//    if share_info != self.share_info:
//        raise ValueError('share_info invalid')
//    if bitcoin_data.get_txid(gentx) != self.gentx_hash:
//        raise ValueError('''gentx doesn't match hash_link''')
//    if bitcoin_data.calculate_merkle_link([None] + other_tx_hashes, 0) != self.merkle_link: # the other hash commitments are checked in the share_info assertion
//        raise ValueError('merkle_link and other_tx_hashes do not match')

    //TODO: wanna for upd protocol version???
    // update_min_protocol_version(counts, self)

    //TODO: Нужно ли это делать в c2pool???
//    self.gentx_size = len(bitcoin_data.tx_id_type.pack(gentx))

    //    self.gentx_weight = len(bitcoin_data.tx_type.pack(gentx)) + 3*self.gentx_size
    {
        PackStream weight_stream;
        coind::data::stream::TransactionType_stream tx_type_data = gentx->gentx;
        weight_stream << tx_type_data;

        gentx_weight = weight_stream.size();
    }


//
//    type(self).gentx_size   = self.gentx_size # saving this share's gentx size as a class variable is an ugly hack, and you're welcome to hate me for doing it. But it works.
//            type(self).gentx_weight = self.gentx_weight

//TODO: При получении блока, нужно ли это?
// return gentx # only used by as_block
}

std::shared_ptr<Share> load_share(PackStream &stream, std::shared_ptr<c2pool::Network> net, addr_type peer_addr)
{
	PackedShareData packed_share;
	stream >> packed_share;

	PackStream _stream(packed_share.contents.value);

    //TODO: remove
    for (auto v : _stream.data)
    {
        std::cout << (unsigned int) v << " ";
    }
    std::cout << std::endl;

	ShareDirector director(net);
	switch (packed_share.type.value)
	{
		case 17:
//			return director.make_share(packed_share.type.value, peer_addr, _stream);
//		case 32:
			return director.make_preSegwitShare(packed_share.type.value, peer_addr, _stream);
		default:
			if (packed_share.type.value < 17)
				throw std::runtime_error("sent an obsolete share");
			else
				throw std::runtime_error((boost::format("unkown share type: %1") % packed_share.type.value).str());
			break;
	}
}

PackedShareData pack_share(ShareType share)
{
	// Pack share to t['share_type'] from p2pool
	PackStream contents;
	contents << *share->min_header->stream();
	contents << *share->share_info->stream();
	contents << *share->ref_merkle_link->stream();
	IntType(64) last_txout_nonce(share->last_txout_nonce);
	contents << last_txout_nonce;
	contents << *share->hash_link->stream();
	contents << *share->merkle_link->stream();

	// Pack share to PackedShareData
	PackedShareData result(share->VERSION, contents);

	return result;
}