#include "share.h"

#include <stdexcept>
#include <tuple>
#include <set>
#include <string>

#include <univalue.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/addr_store.h>
#include "share_tracker.h"
#include "data.h"
#include "share_builder.h"
#include "generate_tx.h"


using namespace std;

#include <boost/format.hpp>
#include <utility>

#define CheckShareRequirement(field_name)                  \
    if (!(field_name))                                     \
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
        throw std::invalid_argument("Segwit activated, but segwit_data == nullptr!");

    if (!(coinbase->size() >= 2 && coinbase->size() <= 100))
    {
        throw std::invalid_argument((boost::format("bad coinbase size! %1% bytes.") % coinbase->size()).str());
    }

    if ((*merkle_link)->branch.size() > 16)
    {
        throw std::invalid_argument("Merkle branch too long#1!");
    }

    if (segwit_activated)
        if ((*segwit_data)->txid_merkle_link.branch.size() > 16)
            throw std::invalid_argument("Merkle branch too long#2!");

    assert(hash_link->get()->extra_data.empty());

    if (VERSION >= 34)
    {
        assert((*share_data)->addr.address);
        new_script = coind::data::address_to_script2(std::string{(*share_data)->addr.address->begin(), (*share_data)->addr.address->end()}, net);
        address = *(*share_data)->addr.address;
    }
    else
    {
        assert((*share_data)->addr.pubkey_hash);
        new_script = coind::data::pubkey_hash_to_script2(*(*share_data)->addr.pubkey_hash, net->parent->ADDRESS_VERSION, -1, net);
        auto _address = coind::data::pubkey_hash_to_address(*(*share_data)->addr.pubkey_hash, net->parent->ADDRESS_VERSION, -1, net);
        address.insert(address.begin(), _address.begin(), _address.end());
    }

    if (net->net_name == "bitcoin" && *absheight > 3927800 && *desired_version == 16)
    {
        throw std::invalid_argument("This is not a hardfork-supporting share!");
    }

    // check txs
    std::set<uint64_t> n;
    for (uint64_t i = 0; i < new_transaction_hashes->size(); i++)
        n.insert(i);
    for (auto [share_count, tx_count] : share_info->get()->transaction_hash_refs)
    {
        assert(share_count < 110);
        if (share_count == 0)
            n.erase(tx_count);
    }
    assert(n.empty());

    std::vector<unsigned char> hash_link_data;
    {
        auto ref_hash = shares::get_ref_hash(VERSION, net, *share_data->get(), *share_info->get(), *ref_merkle_link->get(), segwit_data ? std::make_optional(*segwit_data->get()) : nullopt);
//        LOG_TRACE.stream() << "INIT hash_link_data(ref_hash): " << ref_hash;
        hash_link_data = ref_hash.data;

        IntType(64) _last_txout_nonce(last_txout_nonce);
        PackStream packed_last_txout_nonce;
        packed_last_txout_nonce << _last_txout_nonce;
//        LOG_TRACE.stream() << "INIT hash_link_data(packed_last_txout_nonce): " << packed_last_txout_nonce;
        hash_link_data.insert(hash_link_data.end(), packed_last_txout_nonce.data.begin(), packed_last_txout_nonce.data.end());

        IntType(32) _z(0);
        PackStream packed_z;
        packed_z << _z;
//        LOG_TRACE.stream() << "INIT hash_link_data(packed_z): " << packed_z;
        hash_link_data.insert(hash_link_data.end(), packed_z.data.begin(), packed_z.data.end());
    }

    gentx_hash = shares::check_hash_link(hash_link, hash_link_data, net->gentx_before_refhash);

    auto merkle_root = coind::data::check_merkle_link(gentx_hash, segwit_activated ? (*segwit_data)->txid_merkle_link : *merkle_link->get());
    header.set_value(coind::data::types::BlockHeaderType(*min_header->get(), merkle_root));

    coind::data::stream::BlockHeaderType_stream header_stream(*header.get());

    PackStream packed_block_header;
    packed_block_header << header_stream;


    pow_hash = net->parent->POW_FUNC(packed_block_header);


    PackStream packed_block_header2;
    packed_block_header2 << header_stream;
    hash = coind::data::hash256(packed_block_header2, true);

    if (target > net->MAX_TARGET)
    {
        throw std::invalid_argument("Share target invalid!");
    }

    if (UintToArith256(pow_hash) > UintToArith256(target))
    {
        throw std::invalid_argument((boost::format("Share PoW indalid! pow_hash = %1%; target = %2%") % pow_hash.GetHex() % target.GetHex()).str());
    }
}
#undef CheckShareRequirement

void Share::check(const std::shared_ptr<ShareTracker>& _tracker, std::optional<std::map<uint256, coind::data::tx_type>> other_txs)
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
                    _tracker->get_nth_parent_key(previous_share->hash, net->CHAIN_LENGTH * 9 / 10),
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
    for (auto [share_count, tx_count]: (*share_info)->transaction_hash_refs)
    {
        other_tx_hashes.push_back(
                _tracker->get(_tracker->get_nth_parent_key(hash, share_count))->share_info->get()->new_transaction_hashes[tx_count]);
    }


    auto gentx_F = std::make_shared<shares::GenerateShareTransaction>(_tracker);
    gentx_F->
            set_share_data(*share_data->get()).
            set_block_target(FloatingInteger(header->bits).target()).
            set_desired_timestamp(*timestamp).
            set_desired_target(FloatingInteger((*share_info)->bits).target()).
            set_ref_merkle_link(*ref_merkle_link->get()).
            set_last_txout_nonce(last_txout_nonce);

    // set known txs
    if (other_txs.has_value())
        gentx_F->set_known_txs(other_txs.value());

    // set_segwit_data
    if (segwit_data)
        gentx_F->set_segwit_data(*segwit_data->get());

    // set_desired_other_transaction_hashes_and_fees
    {
        std::vector<std::tuple<uint256, std::optional<int32_t>>> desired_other_transaction_hashes_and_fees;
        for (auto h : other_tx_hashes)
        {
            desired_other_transaction_hashes_and_fees.emplace_back(h, std::nullopt);
        }

        gentx_F->set_desired_other_transaction_hashes_and_fees(
                desired_other_transaction_hashes_and_fees);
    }

    auto gentx = (*gentx_F)(VERSION);

    assert(other_tx_hashes == gentx->other_transaction_hashes);
    if (*share_info->get() != *gentx->share_info)
        throw std::invalid_argument("share_info invalid");
    if (coind::data::get_txid(gentx->gentx) != gentx_hash)
        throw std::invalid_argument((boost::format("gentx doesn't match hash_link: txid = %1%, gentx_hash = %2%") % coind::data::get_txid(gentx->gentx).GetHex() % gentx_hash).str());

    // Check merkle link
    {
        std::vector<uint256> _copy_for_link{uint256::ZERO};
        _copy_for_link.insert(_copy_for_link.end(), gentx->other_transaction_hashes.begin(),
                              gentx->other_transaction_hashes.end());

        auto _merkle_link = coind::data::calculate_merkle_link(_copy_for_link, 0);
        if (_merkle_link != *merkle_link->get())
            throw std::invalid_argument("merkle_link and other_tx_hashes do not match");
    }

    //TODO: wanna for upd protocol version???
    // update_min_protocol_version(counts, self)

    //TODO: Нужно ли это делать в c2pool???
//    self.gentx_size = len(bitcoin_data.tx_id_type.pack(gentx))

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

/*TODO:
coind::data::stream::BlockType_stream
Share::as_block(const shared_ptr<ShareTracker> &_tracker, std::map<uint256, coind::data::tx_type> known_txs)
{
    auto other_txs = _get_other_txs(_tracker, known_txs);
    //TODO:
    return coind::data::stream::BlockType_stream();
}

std::vector<uint256> Share::get_other_tx_hashes(const shared_ptr<ShareTracker> &_tracker)
{
    int32_t parents_needed = 0;
    if (!(*share_info)->transaction_hash_refs.empty())
        parents_needed = max((*share_info)->transaction_hash_refs, [](const auto l, const auto r){
            return true;
        });

    return std::vector<uint256>();
}

std::vector<coind::data::tx_type>
Share::_get_other_txs(const shared_ptr<ShareTracker> &_tracker, std::map<uint256, coind::data::tx_type> known_txs)
{
    other_tx_hashes

    return std::vector<coind::data::tx_type>();
}
*/

nlohmann::json Share::json()
{
    nlohmann::json result{
            {"parent", previous_hash ? previous_hash->GetHex() : ""},
            {"far_parent", (*share_info)->far_share_hash},
//            {"children", tracker->}
            {"type_name", "share"},
            {"local", {
                    // TODO: verified
                    {"time_first_seen", time_seen == 0 ? c2pool::dev::timestamp() : time_seen},
                    {"peer_first_received_from", peer_addr} //TODO: check
            }},
            {"share_data", {
                    {"timestamp", *timestamp},
                    {"target", target},
                    {"max_target", max_target},
                    {"payout_address", coind::data::script2_to_address(new_script, net->parent->ADDRESS_VERSION, -1, net)},
                    {"donation", *donation/65535},
                    {"stale_info", *stale_info},
                    {"nonce", *nonce},
                    {"desired_version", *desired_version},
                    {"absheight", *absheight},
                    {"abswork", *abswork}
            }},
            {"block", {
                    {"hash", hash},
                    {"header", {
                            {"version", header.get()->version},
                            {"previous_block", header.get()->previous_block},
                            {"merkle_root", header.get()->merkle_root},
                            {"timestamp", header.get()->timestamp},
                            {"target", FloatingInteger(header.get()->bits).target()},
                            {"nonce", header.get()->nonce}
                    }},
                    {"gentx", {
                            {"hash", gentx_hash},
                            {"coinbase", HexStr(*coinbase)},
                            {"value", *subsidy * 1e-8},
                            {"last_txout_nonce", last_txout_nonce}
                    }}
            }}

    };

    return result;
}

std::shared_ptr<Share> load_share(PackStream &stream, std::shared_ptr<c2pool::Network> net, const addr_type& peer_addr)
{
    PackedShareData packed_share;
    try
    {
        stream >> packed_share;
    } catch (packstream_exception &ex)
    {
        throw std::invalid_argument((boost::format("Failed unpack PackedShareData in load_share: [%1%]") % ex.what()).str());// << ex.what();
    }

	PackStream _stream(packed_share.contents.value);

	ShareDirector director(std::move(net));
	switch (packed_share.type.value)
	{
		case 17:
//			return director.make_share(packed_share.type.value, peer_addr, _stream);
		case 33:
			return director.make_preSegwitShare(packed_share.type.value, peer_addr, _stream);
        case 34:
        case 35:
            return director.make_segwitMiningShare(packed_share.type.value, peer_addr, _stream);
		default:
			if (packed_share.type.value < 17)
				throw std::runtime_error("sent an obsolete share");
			else
				throw std::runtime_error((boost::format("unkown share type: %1%") % packed_share.type.value).str());
			break;
	}
}

PackedShareData pack_share(const ShareType& share)
{
	// Pack share to t['share_type'] from p2pool
	PackStream contents;
	contents << *share->min_header->stream();
    contents << *share->share_data->stream();
    if (share->segwit_data)
        contents << *share->segwit_data->stream();
	contents << *share->share_info->stream();
	contents << *share->ref_merkle_link->stream();
	contents << pack<IntType(64)>(share->last_txout_nonce);
	contents << *share->hash_link->stream();
	contents << *share->merkle_link->stream();

	// Pack share to PackedShareData
	PackedShareData result(share->VERSION, contents);

	return result;
}