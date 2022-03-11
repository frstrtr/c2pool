#pragma once

#include <libdevcore/db.h>
#include "share.h"
#include <libdevcore/filesystem.h>

class ShareStore
{
public:
	unique_ptr<Database> shares;
	unique_ptr<Database> verified_shares;
public:
	ShareStore()
	{
		shares = std::make_unique<Database>(boost::filesystem::);
	}

public:
	void add_share(std::shared_ptr<Share> share)
	{

	}

};

