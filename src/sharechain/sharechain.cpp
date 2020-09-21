//p2pool/data.py

#include <string>
using namespace std;

// #Forrest p2pk BTC address (DGB uses same coin prefixes for private keys as BTC, so the key for BTC equal for DGB address uncompressed!!!)
// #DONATION_SCRIPT = '4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac'.decode('hex')#BTC

/*type?*/ int parseBIP34(/*type?*/ coinbase)
{
    // _, opdata = script.parse(coinbase).next()
    // bignum = pack.IntType(len(opdata)*8).unpack(opdata)
    // if ord(opdata[-1]) & 0x80:
    //     bignum = -bignum
    int bignum = 0;
    return bignum; // tuple
}

class HashLink
{
    //     hash_link_type = pack.ComposedType([
    //     ('state', pack.FixedStrType(32)),
    //     ('extra_data', pack.FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    //     ('length', pack.VarIntType()),
    // ])
public:
    /*type*/ state = 0;     //('state', pack.FixedStrType(32))
    /*type*/ extraData = 0; // pack.FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    /*type*/ length = 0;    // ('length', pack.VarIntType())

    // def prefix_to_hash_link(prefix, const_ending=''):
    //     assert prefix.endswith(const_ending), (prefix, const_ending)
    //     x = sha256.sha256(prefix)
    //     return dict(state=x.state, extra_data=x.buf[:max(0, len(x.buf)-len(const_ending))], length=x.length//8)
    /*type*/ void prefixToHashLink(/*type*/ prefix, /*type*/ constEnding = "")
    {
    }

    // def check_hash_link(hash_link, data, const_ending=''):
    //     extra_length = hash_link['length'] % (512//8)
    //     assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
    //     extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
    //     assert len(extra) == extra_length
    //     return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())
    /*type*/ void checkHashLink(/*type*/ hashLink, /*type*/ data, /*type*/ constEnding = "")
    {
    }

}

class Share
{
public:
    int shareType;        //pack.VarIntType()
    string shareContents; //pack.VarStrType()

    void load_share(/*in parameters block*/ Share share, string net, /*addr*/ peerAddr, /*out parameters block*/ share_versions[share['type']](net, peer_addr, share_versions[share['type']].get_dynamic_types(net)['share_type'].unpack(share['contents']))){

    };

    bool is_segwit_activated(int version, string net)
    {
        //assert not(version is None or net is None)
        // segwit_activation_version = getattr(net, 'SEGWIT_ACTIVATION_VERSION', 0)
        return 0; //version >= segwit_activation_version and segwit_activation_version > 0
    };
};

class SmallBlockHeaderType
{
public:
    int version;       // ('version', pack.VarIntType()),
    int previousBlock; // ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
    int timeStamp;     // ('timestamp', pack.IntType(32)),
    float bits;        // ('bits', bitcoin_data.FloatingIntegerType()),
    long int nonce;    // ('nonce', pack.IntType(32)),
};

class BaseShare
{
public:
    int VERSION = 0;
    int VOTING_VERSION = 0;
    int *SUCCESSOR = nullptr; // None
    SmallBlockHeaderType smallBlockHeader;

    Share *shareInfoType = nullptr; // None
    Share *shareType = nullptr;     // None
    Share *refType = nullptr;       // None

    auto gentxBeforeRefhash; //gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

    int gentxSize = 50000; // conservative estimate, will be overwritten during execution
    int gentxWeight = 200000;
    int *cachedTypes = nullptr; // None

    // @classmethod
    void getDynamicTypes(/*in parameters block*/ /*this?*/ cls, auto net, /*out paarmeters block*/ auto cachedTypes, /*dict*/ t){};

    // @classmethod
    void generateTransaction(/*in parameters block*/
                             /*cls, tracker, share_data, block_target, desired_timestamp, desired_target, ref_merkle_link, desired_other_transaction_hashes_and_fees, net, known_txs=None, last_txout_nonce=0, base_subsidy=None, segwit_data=None*/
                             /*out parameters block*/
                             /*share_info, gentx, other_transaction_hashes, get_share*/){};

    // @classmethod
    void getRefHash(/*this?*/ cls, auto net, auto shareInfo, auto refMerkleLink)
    {
        return 0; //pack.IntType(256).pack(bitcoin_data.check_merkle_link(bitcoin_data.hash256(cls.get_dynamic_types(net)['ref_type'].pack(dict(identifier=net.IDENTIFIER, share_info=share_info,))), ref_merkle_link))
    };

    // class initialization constructor __init__(self...)
public:
    BaseShare(/*this?*/ auto self, /*type?*/ auto net, /*type?*/ auto peer_addr, /*type?*/ auto contents)
    {
        /*type?*/ dynamicTypes = getDynamicTypes(net);    // dynamic_types = self.get_dynamic_types(net)
        /*type?*/ shareInfo = dynamicTypes.shareInfoType; // self.share_info_type = dynamic_types['share_info_type']
        /*type?*/ shareType = dynamicTypes.shareType;     // self.share_type = dynamic_types['share_type']
        /*type?*/ refType = dynamicTypes.refType;         // self.ref_type = dynamic_types['ref_type']

        // self.net = net
        // self.peer_addr = peer_addr
        // self.contents = contents

        /*type?*/ minHeader = contents.minHeader;   // self.min_header = contents['min_header']
        /*type?*/ shareInfo = contents.shareInfo;   // self.share_info = contents['share_info']
        /*type?*/ hashLink = contents.hashLink;     // self.hash_link = contents['hash_link']
        /*type?*/ merkleLink = contents.merkleLink; // self.merkle_link = contents['merkle_link']

        /*type?*/ shareData = shareInfo.shareData;            // self.share_data = self.share_info['share_data']
        /*type?*/ maxTarget = shareInfo.maxBits.target;       // self.max_target = self.share_info['max_bits'].target
        /*type?*/ target = shareInfo.bits.target;             // self.target = self.share_info['bits'].target
        /*type?*/ timestamp = shareInfo.timestamp;            // self.timestamp = self.share_info['timestamp']
        /*type?*/ previousHash = shareData.previousShareHash; // self.previous_hash = self.share_data['previous_share_hash']
        /*type?*/ newScript = /*function*/;                   //self.new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash'])
        /*type?*/ desiredVersion = shareData.desiredVersion;  // self.desired_version = self.share_data['desired_version']
        /*type?*/ absHeight = shareInfo.absHeight;            // self.absheight = self.share_info['absheight']
        /*type?*/ absWork = shareInfo.absWork;                // self.abswork = self.share_info['abswork']

        //  self.gentx_hash = check_hash_link(
        //     self.hash_link,
        //     self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
        //     self.gentx_before_refhash,
        // )
        /*type?*/ gentxHash = chackHashLink(/*type?*/ hashLink, getRefHash(/*type?*/ net, /*type?*/ shareInfo, /*type?*/ contents.refMerkleLink) + /*pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0)*/, /*type?*/ gentxBeforeRefhash);

        // merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)

        // self.header = dict(self.min_header, merkle_root=merkle_root)
        /*type?*/ header = 0;
        // self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
        /*type?*/ powHash = 0;
        // self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))
        /*type?*/ hash = 0;

        // if self.target > net.MAX_TARGET:
        //     from p2pool import p2p
        //     raise p2p.PeerMisbehavingError('share target invalid')

        // if self.pow_hash > self.target:
        //     from p2pool import p2p
        //     raise p2p.PeerMisbehavingError('share PoW invalid')

        // self.new_transaction_hashes = self.share_info['new_transaction_hashes']
        /*type?*/ newTransactionHashes = shareInfo.newTransactionHashes;

        // # XXX eww
        // self.time_seen = time.time()
        /*type?*/ timeSeen = CURRENT_TIME;
    };

    // private:
    /*type?*/ void repr{

    };

    /*type?*/ void as_share{

    };

    /*type?*/ void iterTransactionHashRefs{

    };

    /*type?*/ check(/*type?*/ tracker, /*type?*/ otherTXs = nullptr){

    };

    /*type?*/ getOtherTXHashes(/*type?*/ tracker){

    };

    // private:
    /*type?*/ getOtherTXs(/*type?*/ tracker, /*type?*/ knownTXs){

    };

    /*type?*/ shouldPunishReason(/*type?*/ previousBlock, /*type?*/ bits, /*type?*/ tracker, /*type?*/ knownTXs){

    };

    /*type?*/ asBlock(/*type?*/ tracker, /*type?*/ knownTXs){

    };
}
}
;

class NewShare(BaseShare)
{
    /*type?*/ VERSION = 33;
    /*type?*/ VOTING_VERSION = 33;
    /*type?*/ SUCCESSOR = nullptr;
}

class PreSegwitShare(BaseShare)
{
    /*type?*/ VERSION = 32;
    /*type?*/ VOTING_VERSION = 32;
    /*type?*/ SUCCESSOR = NewShare;
}

class Share(BaseShare)
{
    /*type?*/ VERSION = 17;
    /*type?*/ VOTING_VERSION = 17;
    /*type?*/ SUCCESSOR = NewShare;
}

// share_versions = {s.VERSION:s for s in [NewShare, PreSegwitShare, Share]}

class WeightsSkipList(/*type?*/ forest.TrackerSkipList)
{
public:
    /*type?*/ void getDelta(/*type?*/ element){};
    /*type?*/ void combineDeltas(/*type set?*/ set1(share_count1, weights1, total_weight1, total_donation_weight1), /*type set?*/ set2(share_count2, weights2, total_weight2, total_donation_weight2)){};
    /*type?*/ void initialSolution(/*type?*/ start, /*type tuple?*/ tuple1(max_shares, desired_weight)){};
    /*type?*/ void applyDelta(/*type set?*/ set1(share_count1, weights_list, total_weight1, total_donation_weight1), /*type set?*/ set2(share_count2, weights2, total_weight2, total_donation_weight2), /*type tuple?*/ tuple1(max_shares, desired_weight)){};
    /*type?*/ void judge(/*type set?*/ set1(share_count, weights_list, total_weight, total_donation_weight), /*type tuple?*/ tuple1(max_shares, desired_weight)){};
    /*type?*/ void finalize(/*type set?*/ set1(share_count, weights_list, total_weight, total_donation_weight), /*type set?*/ set1(max_shares, desired_weight)){};
}

class OkayTracker(/*type?*/ forest.Tracker)
{

    // __init__() constructor
public:
    OkayTracker(/*type?*/ net){
        //net
        //verified
        //getCunulativeWeights
    };

    /*type?*/ void attemptVerify(/*type?*/ share){};
    /*type?*/ void think(/*type?*/ blockRelHeightFunc, /*type?*/ previousBlock, /*type?*/ bits, /*type?*/ knownTX){};
    /*type?*/ void score(/*type?*/ shareHash, /*type?*/ blockRelHeightFunc){};
}

/*type?*/ void updateMinProtocolVersion(/*type?*/ counts, /*type?*/ share){};
/*type?*/ void getPoolAttemptsPerSecond(/*type?*/ tracker, /*type?*/ previousShareHash, /*type?*/ dist, bool minWork = false, bool integer = false){};
/*type?*/ void getAverageStaleProp(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind){};
/*type?*/ void getStaleCounts(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind, bool rates = False){};
/*type?*/ void getUserStaleProps(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind){};
/*type?*/ void getExpectedPayouts(/*type?*/ tracker, /*type?*/ bestShareHash, /*type?*/ blockTarget, /*type?*/ subsidy, /*type?*/ net){};
/*type?*/ void getDesiredVersionCounts(/*type?*/ tracker, /*type?*/ bestShareHash, /*type?*/ dist){};
/*type?*/ void getWarnings(/*type?*/ tracker, /*type?*/ bestShare, /*type?*/ net, /*type?*/ bitcoindGetNetworkInfo, /*type?*/ bitcoindWorkValue){};
/*type?*/ void formatHash(/*type?*/ x){};

class Sharestore
{
    //__init__ constructor
public:
    Sharestore(/*type?*/ prefix, /*type?*/ net, /*type?*/ share_cb, /*type?*/ verifiedHashCB)
    {
        // self.dirname = os.path.dirname(os.path.abspath(prefix)) #Путь к папке с файлами данных шар.
        // self.filename = os.path.basename(os.path.abspath(prefix)) #Название файла данных шар ['shares.']
        // self.archive_dirname = os.path.abspath(self.dirname + '/archive') #Путь к папке-архиву с данными шар.
        // self.net = net

        // start = time.time()

        // known = {}
        // filenames, next = self.get_filenames_and_next()
        // for filename in filenames:
        //     share_hashes, verified_hashes = known.setdefault(filename, (set(), set()))
        //     with open(filename, 'rb') as f:
        //         for line in f:
        //             try:
        //                 type_id_str, data_hex = line.strip().split(' ')
        //                 type_id = int(type_id_str)
        //                 if type_id == 0:
        //                     pass
        //                 elif type_id == 1:
        //                     pass
        //                 elif type_id == 2:
        //                     verified_hash = int(data_hex, 16)
        //                     verified_hash_cb(verified_hash)
        //                     verified_hashes.add(verified_hash)
        //                 elif type_id == 5:
        //                     raw_share = share_type.unpack(data_hex.decode('hex'))
        //                     if raw_share['type'] < Share.VERSION:
        //                         continue
        //                     share = load_share(raw_share, self.net, None)
        //                     share_cb(share)
        //                     share_hashes.add(share.hash)
        //                 else:
        //                     raise NotImplementedError("share type %i" % (type_id,))
        //             except Exception:
        //                 log.err(None, "HARMLESS error while reading saved shares, continuing where left off:")
    }

private:
    /*type?*/ void addLine(/*type?*/ line){};

public:
    /*type?*/ void add_share(/*type?*/ share){};
    /*type?*/ void add_verified_hash(/*type?*/ share_hash){};
    /*type?*/ void get_filenames_and_next(){};
    /*type?*/ void forget_share(/*type?*/ share_hash){};
    /*type?*/ void forget_verified_share(/*type?*/ share_hash){};
    /*type?*/ void check_archive_dirname(){};
    /*type?*/ void check_remove(){};
};