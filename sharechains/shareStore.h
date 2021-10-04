#pragma once
#include <dbshell/db.h>
#include <btclibs/uint256.h>

#include <memory>
using std::shared_ptr;

namespace c2pool::shares{
    class BaseShare;
}
using c2pool::shares::BaseShare;

using dbshell::Database;


namespace c2pool::shares
{

    //TODO: ARCHIVE ???
    class ShareStore : public Database
    {
    public:
        ShareStore(const std::string /*TODO: boost::filesystem*/ filepath /*, net, share_cb, verifiedHashCB*/);

        void add_share(shared_ptr<BaseShare> share);
        void forget_share(uint256 share_hash);

    //----------------

    // public:
    //     /*type?*/ void add_verified_hash(/*type?*/ share_hash){};
    //     /*type?*/ void forget_verified_share(/*type?*/ share_hash){};
    //     /*type?*/ void check_remove(){};
    };
} // namespace c2pool::shares