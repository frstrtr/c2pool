#pragma once
#include "db.h"
#include "uint256.h"

namespace c2pool::shares{
    class BaseShare;
}

using dbshell::Database;


namespace c2pool::shares
{

    //TODO: ARCHIVE ???
    class ShareStore : public Database
    {
    public:
        ShareStore(const std::string /*TODO: boost::filesystem*/ filepath /*, net, share_cb, verifiedHashCB*/);

        void add_share(BaseShare share);
        void forget_share(uint256 share_hash); //TODO: Type for hash

    //----------------

    // public:
    //     /*type?*/ void add_verified_hash(/*type?*/ share_hash){};
    //     /*type?*/ void forget_verified_share(/*type?*/ share_hash){};
    //     /*type?*/ void check_remove(){};
    };
} // namespace c2pool::shares