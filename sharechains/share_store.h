#pragma once

#include <libdevcore/db.h>
#include "share.h"
#include <libdevcore/filesystem.h>
#include <networks/network.h>

#include <utility>
#include <fstream>
#include <sstream>

class ShareStore
{
private:
    std::shared_ptr<c2pool::Network> net;

	unique_ptr<Database> shares;
	unique_ptr<Database> verified_shares;
public:
    ShareStore() = delete;
//	ShareStore()
//	{
//        auto filepath = c2pool::filesystem::getProjectPath() / "data" / net->net_name;
//
//		shares = std::make_unique<Database>(filepath, "shares");
//		verified_shares = std::make_unique<Database>(filepath, "shares_verified");
//	}

    ShareStore(std::shared_ptr<c2pool::Network> _net) : net(std::move(_net))
    {
        auto filepath = c2pool::filesystem::getProjectPath() / "data" / net->net_name;

        shares = std::make_unique<Database>(filepath, "shares");
        verified_shares = std::make_unique<Database>(filepath, "shares_verified");
    }

public:
	void add_share(ShareType share)
	{
		PackStream packed_share;
		packed_share << *share;

		leveldb::Slice key(reinterpret_cast<const char*>(share->hash.begin()), share->hash.size());
		leveldb::Slice value(reinterpret_cast<const char*>(packed_share.data.data()), packed_share.size());

		shares->Write(key, value);
	}

	void add_verified(ShareType share)
	{
		PackStream packed_share;
		packed_share << *share;

        leveldb::Slice key(reinterpret_cast<const char*>(share->hash.begin()), share->hash.size());
        leveldb::Slice value(reinterpret_cast<const char*>(packed_share.data.data()), packed_share.size());

        shares->Write(key, value);
	}

    // read file from p2pool
    void legacy_init(const boost::filesystem::path &filepath, std::function<void(std::vector<ShareType>, std::vector<uint256>)> init_f)
    {
        std::vector<ShareType> _shares;
        std::vector<uint256> _known_verified;

        auto file = std::fstream(filepath.c_str(), std::ios_base::in);
        if (file.is_open())
        {
            std::string line;
            int i = 0; //REMOVE
            while(getline(file, line))
            {
                std::stringstream ss(line);

                int type_id;
                std::string data_hex;

                ss >> type_id;
                ss >> data_hex;

                switch (type_id)
                {
                    case 0:
                    case 1:
                        break;
                    case 2:
                    {
                        auto verified_hash = uint256S(data_hex);
                        _known_verified.push_back(verified_hash);
                        break;
                    }
                    case 5:
                    {
                        PackStream stream(ParseHex(data_hex));
//                        PackedShareData raw_share;
//                        stream >> raw_share;
//
//                        if (raw_share.type.get() < 17)
//                            continue;

                        auto share = load_share(stream, net, {{}, {}});
                        share->time_seen = 0;
                        _shares.push_back(std::move(share));
                        break;
                    }
                    default:
                        //TODO raise
                        std::cout << "NotImplementedError(ShareType " << type_id << ")." << std::endl;
                        break;
                }



                i++; //REMOVE
//                if (i >= 2601)
                if (i >= 34561)
                    break;
            }


        }
        file.close();

        init_f(_shares, _known_verified);
    }

    //TODO: GET for what?
    //TODO: Test for GET
};

