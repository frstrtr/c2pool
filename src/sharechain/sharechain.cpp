#include <string>
using namespace std;

class Share
{
public:
    int shareType;
    string shareContents;

    void load_share(Share share, string net, addr peerAddr){

    };

    void is_segwit_activated(int version, string net){

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
    int VERSION;
    int VOTING_VERSION;
    int SUCCESSOR;
    SmallBlockHeaderType smallBlockHeader;

    Share *shareInfoType = nullptr;
    Share *shareType = nullptr;
    Share *refType = nullptr;

    //gentx_before_refhash = pack.VarStrType().pack(DONATION_SCRIPT) + pack.IntType(64).pack(0) + pack.VarStrType().pack('\x6a\x28' + pack.IntType(256).pack(0) + pack.IntType(64).pack(0))[:3]

    int gentxSize = 50000; // conservative estimate, will be overwritten during execution
    int gentxWeight = 200000;
    int *cachedTypes = nullptr;
};

class Sharechain
{
};