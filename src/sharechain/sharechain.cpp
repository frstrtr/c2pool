// //p2pool/data.py

// #include <string>
// using namespace std;

// // #Forrest p2pk BTC address (DGB uses same coin prefixes for private keys as BTC, so the key for BTC equal for DGB address uncompressed!!!)
// // #DONATION_SCRIPT = '4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac'.decode('hex')#BTC

// /*type?*/ int parseBIP34(/*type?*/ coinbase)
// {
//     // _, opdata = script.parse(coinbase).next()
//     // bignum = pack.IntType(len(opdata)*8).unpack(opdata)
//     // if ord(opdata[-1]) & 0x80:
//     //     bignum = -bignum
//     int bignum = 0;
//     return bignum; // tuple
// }

// class HashLink
// {
//     //     hash_link_type = pack.ComposedType([
//     //     ('state', pack.FixedStrType(32)),
//     //     ('extra_data', pack.FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
//     //     ('length', pack.VarIntType()),
//     // ])
// public:
//     /*type*/ state = 0;     //('state', pack.FixedStrType(32))
//     /*type*/ extraData = 0; // pack.FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
//     /*type*/ length = 0;    // ('length', pack.VarIntType())

//     // def prefix_to_hash_link(prefix, const_ending=''):
//     //     assert prefix.endswith(const_ending), (prefix, const_ending)
//     //     x = sha256.sha256(prefix)
//     //     return dict(state=x.state, extra_data=x.buf[:max(0, len(x.buf)-len(const_ending))], length=x.length//8)
//     /*type*/ void prefixToHashLink(/*type*/ prefix, /*type*/ constEnding = "")
//     {
//     }

//     // def check_hash_link(hash_link, data, const_ending=''):
//     //     extra_length = hash_link['length'] % (512//8)
//     //     assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
//     //     extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
//     //     assert len(extra) == extra_length
//     //     return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())
//     /*type*/ void checkHashLink(/*type*/ hashLink, /*type*/ data, /*type*/ constEnding = "")
//     {
//     }

// }







// // share_versions = {s.VERSION:s for s in [NewShare, PreSegwitShare, Share]}

// class WeightsSkipList(/*type?*/ forest.TrackerSkipList)
// {
// public:
//     /*type?*/ void getDelta(/*type?*/ element){};
//     /*type?*/ void combineDeltas(/*type set?*/ set1(share_count1, weights1, total_weight1, total_donation_weight1), /*type set?*/ set2(share_count2, weights2, total_weight2, total_donation_weight2)){};
//     /*type?*/ void initialSolution(/*type?*/ start, /*type tuple?*/ tuple1(max_shares, desired_weight)){};
//     /*type?*/ void applyDelta(/*type set?*/ set1(share_count1, weights_list, total_weight1, total_donation_weight1), /*type set?*/ set2(share_count2, weights2, total_weight2, total_donation_weight2), /*type tuple?*/ tuple1(max_shares, desired_weight)){};
//     /*type?*/ void judge(/*type set?*/ set1(share_count, weights_list, total_weight, total_donation_weight), /*type tuple?*/ tuple1(max_shares, desired_weight)){};
//     /*type?*/ void finalize(/*type set?*/ set1(share_count, weights_list, total_weight, total_donation_weight), /*type set?*/ set1(max_shares, desired_weight)){};
// }

// class OkayTracker(/*type?*/ forest.Tracker)
// {

//     // __init__() constructor
// public:
//     OkayTracker(/*type?*/ net){
//         //net
//         //verified
//         //getCunulativeWeights
//     };

//     /*type?*/ void attemptVerify(/*type?*/ share){};
//     /*type?*/ void think(/*type?*/ blockRelHeightFunc, /*type?*/ previous_block, /*type?*/ bits, /*type?*/ knownTX){};
//     /*type?*/ void score(/*type?*/ shareHash, /*type?*/ blockRelHeightFunc){};
// }

// /*type?*/ void updateMinProtocolVersion(/*type?*/ counts, /*type?*/ share){};
// /*type?*/ void getPoolAttemptsPerSecond(/*type?*/ tracker, /*type?*/ previousShareHash, /*type?*/ dist, bool minWork = false, bool integer = false){};
// /*type?*/ void getAverageStaleProp(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind){};
// /*type?*/ void getStaleCounts(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind, bool rates = False){};
// /*type?*/ void getUserStaleProps(/*type?*/ tracker, /*type?*/ shareHash, /*type?*/ lookBehind){};
// /*type?*/ void getExpectedPayouts(/*type?*/ tracker, /*type?*/ bestShareHash, /*type?*/ blockTarget, /*type?*/ subsidy, /*type?*/ net){};
// /*type?*/ void getDesiredVersionCounts(/*type?*/ tracker, /*type?*/ bestShareHash, /*type?*/ dist){};
// /*type?*/ void getWarnings(/*type?*/ tracker, /*type?*/ bestShare, /*type?*/ net, /*type?*/ bitcoindGetNetworkInfo, /*type?*/ bitcoindWorkValue){};
// /*type?*/ void formatHash(/*type?*/ x){};

