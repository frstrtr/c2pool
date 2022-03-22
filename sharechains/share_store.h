#pragma once

#include <libdevcore/db.h>
#include "share.h"
#include <libdevcore/filesystem.h>

class ShareStore
{
private:
	unique_ptr<Database> shares;
	unique_ptr<Database> verified_shares;
public:
	ShareStore()
	{
		shares = std::make_unique<Database>(c2pool::filesystem::getProjectPath(), "shares");
		verified_shares = std::make_unique<Database>(c2pool::filesystem::getProjectPath(), "shares_verified");
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

    //TODO: GET for what?
    //TODO: Test for GET
};

