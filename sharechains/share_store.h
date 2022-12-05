#pragma once

#include <libdevcore/db.h>
#include "share.h"
#include <libdevcore/filesystem.h>

#include <utility>
#include <fstream>
#include <sstream>

class ShareStore
{
private:
    std::string net_name;

	unique_ptr<Database> shares;
	unique_ptr<Database> verified_shares;
public:
	ShareStore()
	{
        auto filepath = c2pool::filesystem::getProjectPath() / "data";

		shares = std::make_unique<Database>(filepath, "shares");
		verified_shares = std::make_unique<Database>(filepath, "shares_verified");
	}

    ShareStore(std::string _net_name) : net_name(std::move(_net_name))
    {
        auto filepath = c2pool::filesystem::getProjectPath() / "data";

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
    void legacy_init(const boost::filesystem::path &filepath)
    {
        auto file = std::fstream(filepath.c_str(), std::ios_base::in);
        if (file.is_open())
        {
            std::string line;
            int i = 0;
            while(getline(file, line))
            {
                std::cout << line << std::endl;
                i++;
                if (i >= 10)
                    break;
            }
        }
        file.close();
    }

    //TODO: GET for what?
    //TODO: Test for GET
};

