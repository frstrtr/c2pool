struct message_version {
    //= pack.ComposedType([
    //     ('version', pack.IntType(32)),
    pack.IntType(32) version;
    //     ('services', pack.IntType(64)),
    pack.IntType(64) services;
    //     ('addr_to', bitcoin_data.address_type),
    bitcoin_data.address_type addr_to;
    //     ('addr_from', bitcoin_data.address_type),
    bitcoin_data.address_type addr_from;
    //     ('nonce', pack.IntType(64)),
    pack.IntType(64) nonce;
    //     ('sub_version', pack.VarStrType()),
    pack.VarStrType() sub_version;
    //     ('mode', pack.IntType(32)), # always 1 for legacy compatibility
    pack.IntType(32) mode;
    //     ('best_share_hash', pack.PossiblyNoneType(0, pack.IntType(256))),
    pack.PossiblyNoneType(0, pack.IntType(256)) best_share_hash;
    // ])
};

struct message_ping{
    // message_ping = pack.ComposedType([])
};

struct message_addrme{
    //= pack.ComposedType([
    //    ('port', pack.IntType(16)),
    //])
    pack.IntType(16) port;
};

struct message_addrs{
    // = pack.ComposedType([
    //     ('addrs', pack.ListType(pack.ComposedType([
    //         ('timestamp', pack.IntType(64)),
    //         ('address', bitcoin_data.address_type),
    //     ]))),
    // ])
    struct addrs{
        pack.IntType(64) timestamp;
        bitcoin_data.address_type address;
    }
};

struct message_getaddrs{
    //     = pack.ComposedType([
    //     ('count', pack.IntType(32)),
    // ])
    pack.IntType(32) count;
};

struct message_shares{
    //     = pack.ComposedType([
    //     ('shares', pack.ListType(p2pool_data.share_type)),
    // ])
    pack.ListType(p2pool_data.share_type) shares;
};

struct message_sharereq{
    //     = pack.ComposedType([
    //     ('id', pack.IntType(256)),
    pack.IntType(256) id;
    //     ('hashes', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256)) hashes;
    //     ('parents', pack.VarIntType()),
    pack.VarIntType() parents;
    //     ('stops', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256)) stops;
    // ])
};

struct message_sharereply{
    //     = pack.ComposedType([
    //     ('id', pack.IntType(256)),
    pack.IntType(256) id;
    //     ('result', pack.EnumType(pack.VarIntType(), {0: 'good', 1: 'too long', 2: 'unk2', 3: 'unk3', 4: 'unk4', 5: 'unk5', 6: 'unk6'})),
    pack.EnumType(pack.VarIntType(), {0: 'good', 1: 'too long', 2: 'unk2', 3: 'unk3', 4: 'unk4', 5: 'unk5', 6: 'unk6'}) result;
    //     ('shares', pack.ListType(p2pool_data.share_type)),
    pack.ListType(p2pool_data.share_type) shares;
    // ])
};

struct message_bestblock{
    //     = pack.ComposedType([
    //     ('header', bitcoin_data.block_header_type),
    bitcoin_data.block_header_type header;
    // ])
};

struct message_have_tx{
    //     = pack.ComposedType([
    //     ('tx_hashes', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256) tx_hashes;
    // ])
};

struct message_losing_tx{
    //     = pack.ComposedType([
    //     ('tx_hashes', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256) tx_hashes;
    // ])
};

struct message_remember_tx{
    //     = pack.ComposedType([
    //     ('tx_hashes', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256)) tx_hashes;
    //     ('txs', pack.ListType(bitcoin_data.tx_type)),
    pack.ListType(bitcoin_data.tx_type) txs;
    // ])
};

struct message_forget_tx{
    //     = pack.ComposedType([
    //     ('tx_hashes', pack.ListType(pack.IntType(256))),
    pack.ListType(pack.IntType(256)) tx_hashes;
    // ])
}