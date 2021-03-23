#include "shareStore.h"
#include "share.h"
using c2pool::shares::share::BaseShare;

#include <dbshell/db.h>

#include <memory>
using std::shared_ptr;

namespace c2pool::shares
{

    ShareStore::ShareStore(const std::string /*TODO: boost::filesystem*/ filepath /*, net, share_cb, verifiedHashCB*/) : Database(filepath)
    {
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

    void ShareStore::add_share(shared_ptr<BaseShare> share)
    {
        //TODO: uint256 to String
        if(Exist(share->hash.ToString()))
            return;

        Write(share->hash.ToString(), *share);
    }

    void ShareStore::forget_share(uint256 share_hash){
        //TODO: uint256 to String
        Remove(share_hash.ToString());
    }
} // namespace c2pool::shares