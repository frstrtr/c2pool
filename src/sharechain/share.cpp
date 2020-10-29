#include <share.h>
#include <config.h>
#include <other.h>

#include <memory>

namespace c2pool::shares
{
    bool is_segwit_activated(int version, int segwit_activation_version)
    {
        return (segwit_activation_version > 0) && (version >= segwit_activation_version);
    }

    BaseShare::BaseShare(shared_ptr<c2pool::config::Network> _net, std::tuple<std::string, std::string> _peer_addr, ShareType _contents)
    {
        net = _net;
        peer_addr = _peer_addr;
        contents = _contents;

        min_header = contents.min_header;
        share_info = contents.share_info;
        hash_link = contents.hash_link;
        merkle_link = contents.merkle_link;

        //TODO:
        // # save some memory if we can
        // txrefs = self.share_info['transaction_hash_refs']
        // if txrefs and max(txrefs) < 2**16:
        //     self.share_info['transaction_hash_refs'] = array.array('H', txrefs)
        // elif txrefs and max(txrefs) < 2**32: # in case we see blocks with more than 65536 tx in the future
        //     self.share_info['transaction_hash_refs'] = array.array('L', txrefs)

        bool segwit_activated = is_segwit_activated(VERSION, net->SEGWIT_ACTIVATION_VERSION);

        //TODO:
        // if not (2 <= len(self.share_info['share_data']['coinbase']) <= 100):
        //     raise ValueError('''bad coinbase size! %i bytes''' % (len(self.share_info['share_data']['coinbase']),))

        // if len(self.merkle_link['branch']) > 16 or (segwit_activated and len(self.share_info['segwit_data']['txid_merkle_link']['branch']) > 16):
        //     raise ValueError('merkle branch too long!')

        //TODO: assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])

        share_data = share_info->share_data;
        max_target = share_info->max_bits; //TODO: .target [data.py, 381]
        target = share_info->bits;         //TODO: .target [data.py, 382]
        timestamp = share_info->timestamp;
        previous_hash = share_data->previous_share_hash;
        //TODO: new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash'])
        desired_version = share_data->desired_version;
        absheight = share_info->absheigth;
        abswork = share_info->abswork;

        if (/*TODO:[add NAME in net] (net->NAME == "bitocin") &&*/ absheight > 3927800 && desired_version == 16)
        {
            //TODO: raise ValueError("This is not a hardfork-supporting share!")
        }

        //TODO: check for tx?
        // n = set()
        // for share_count, tx_count in self.iter_transaction_hash_refs():
        //     assert share_count < 110
        //     if share_count == 0:
        //         n.add(tx_count)
        // assert n == set(range(len(self.share_info['new_transaction_hashes'])))

        //TODO: create check_hash_link
        gentx_hash = check_hash_link(
            self.hash_link,
            self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
            self.gentx_before_refhash, );

        //TODO:
        // merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
        // self.header = dict(self.min_header, merkle_root=merkle_root)

        //TODO: self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
        //TODO: self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))

        //TODO: add MAX_TARGET in net
        if (target.Compare(net->MAX_TARGET) > 0)//target > net->MAX_TARGET)
        {
            //TODO: raise p2p.PeerMisbehavingError('share target invalid')
        }

        if (pow_hash.Compare(target) > 0)//pow_hash > target)
        {
            //TODO: raise p2p.PeerMisbehavingError('share PoW invalid')
        }

        new_transaction_hashes = share_info->new_transaction_hashes;

        time_seen = c2pool::time::timestamp();
    }

    std::string BaseShare::SerializeJSON()
    {
        //TODO
    }
    void BaseShare::DeserializeJSON(std::string json)
    {
        //TODO:
    }

} // namespace c2pool::shares