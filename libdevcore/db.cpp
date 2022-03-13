#include "db.h"

#include <string>
#include "logger.h"


Database::Database(const boost::filesystem::path &filepath, std::string _name, bool wipe) : name(_name)
{
	options.create_if_missing = true;

	if (wipe)
	{
		leveldb::Status wipe_status = leveldb::DestroyDB(name, options);
	}

	leveldb::Status status = leveldb::DB::Open(options, filepath.string(), &db);

	if (!status.ok())
	{
		//LOG_ERROR << "Unable to open/create datebase with path:  " << filepath
		//          << "; status: " << status.ToString();
		//TODO: close proj
	}
}

Database::~Database()
{
	delete db;
}