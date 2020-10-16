#ifndef SHARE_STORE_H
#define SHARE_STORE_H


namespace c2pool::shares
{

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
} // namespace c2pool::shares

#endif