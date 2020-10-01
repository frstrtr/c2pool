#include <string>



namespace c2pool::shares
{

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
    };

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

    class NewShare : BaseShare
    {
        /*type?*/ VERSION = 33;
        /*type?*/ VOTING_VERSION = 33;
        /*type?*/ SUCCESSOR = nullptr;
    };

    class PreSegwitShare : BaseShare
    {
        /*type?*/ VERSION = 32;
        /*type?*/ VOTING_VERSION = 32;
        /*type?*/ SUCCESSOR = NewShare;
    };

    class Share : BaseShare
    {
        /*type?*/ VERSION = 17;
        /*type?*/ VOTING_VERSION = 17;
        /*type?*/ SUCCESSOR = NewShare;
    };
} // namespace c2pool::shares