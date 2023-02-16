#include "db.h"

#include <string>
#include "logger.h"


Database::Database(const boost::filesystem::path &filepath, const std::string &_name, bool wipe) : name(_name)
{
    options.create_if_missing = true;

	if (wipe)
	{
		leveldb::Status wipe_status = leveldb::DestroyDB((filepath / name).string(), options);
	}

    boost::filesystem::create_directories(filepath);
	leveldb::Status status = leveldb::DB::Open(options, (filepath / name).string(), &db);

	if (!status.ok())
	{
		LOG_ERROR << "Unable to open/create datebase with path:  " << filepath
		          << "; status: " << status.ToString();

		//TODO: close proj
	} else
    {
        LOG_INFO << "DB was opened with path: " << (filepath / name).string();
    }
}

Database::~Database()
{
	delete db;
}