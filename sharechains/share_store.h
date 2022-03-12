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

		leveldb::Slice key(share->hash, sizeof(share->hash));
		leveldb::Slice value((char*) packed_share.data.data(), packed_share.size());

		shares->write(key, value);
	}

	void add_verified(ShareType share)
	{
		PackStream packed_share;
		packed_share << *share;

		leveldb::Slice key(share->hash, sizeof(share->hash));
		leveldb::Slice value((char*) packed_share.data.data(), packed_share.size());

		verified_shares->write(key, value);
	}

};

