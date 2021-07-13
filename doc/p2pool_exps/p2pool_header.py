#1
self.gentx_hash = check_hash_link(
    self.hash_link,
    self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
    self.gentx_before_refhash,
)
#===
    def check_hash_link(hash_link, data, const_ending=''):
        extra_length = hash_link['length'] % (512//8)
        assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
        extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
        assert len(extra) == extra_length
        return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())

#=======
        @classmethod
        def get_ref_hash(cls, net, share_info, ref_merkle_link):
            return pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(
                identifier=net.IDENTIFIER,
                share_info=share_info,
            ))), ref_merkle_link))

#===========
            # tip_hash = bitcoin_data.hash256 = int256
            #link = ref_merkle_link
            def check_merkle_link(tip_hash, link):
                if link['index'] >= 2**len(link['branch']):
                    raise ValueError('index too large')
                return reduce(lambda c, (i, h): hash256(merkle_record_type.pack(
                    dict(left=h, right=c) if (link['index'] >> i) & 1 else
                    dict(left=c, right=h)
                )), enumerate(link['branch']), tip_hash)











merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
self.header = dict(self.min_header, merkle_root=merkle_root)
self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))