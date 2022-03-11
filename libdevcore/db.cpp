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

//
//bool Database::Write(const std::string &key, DBObject &value, bool sync)
//{
//	DBBatch batch;
//	batch.Write(key, value);
//	return Write(batch, sync);
//}
//
//bool Database::Write(DBBatch &batch, bool sync)
//{
//	leveldb::Status status = db->Write(sync ? syncOptions : writeOptions, &batch.batch);
//
//	if (!status.ok())
//	{
//		//LOG_ERROR << "Failed write data to db:  " << filepath
//		//          << "; status: " << status.ToString();
//		return false;
//	}
//
//	return true;
//}
//
//bool Database::Read(const std::string &key, DBObject &value)
//{
//	leveldb::Slice sliceKey = key;
//	std::string _value;
//
//	leveldb::Status status = db->Get(readOptions, sliceKey, &_value);
//
//	if (!status.ok())
//	{
//		if (status.IsNotFound())
//			return false;
//		//LOG_ERROR << "Failed read data from db:  " << filepath
//		//          << "; status: " << status.ToString();
//		return false;
//	}
//
//	//TODO: try catch deserialize?
//
//	LOG_DEBUG << "Database::Read" << _value;
//
//	value.DeserializeJSON(_value);
//
//	return true;
//}
//
//bool Database::Remove(const std::string &key, bool fSync)
//{
//	//TODO:
//}
//
//bool Database::Exist(const std::string &key)
//{
//	leveldb::Slice sliceKey = key;
//	std::string _value;
//
//	leveldb::Status status = db->Get(readOptions, key, &_value);
//
//	if (!status.ok())
//	{
//		if (status.IsNotFound())
//			return false;
//
//		//LOG_ERROR << "Failed read data from db:  " << filepath
//		//          << "; status: " << status.ToString();
//	}
//
//	return true;
//}
//
//bool Database::IsEmpty()
//{
//	//TODO: create iterator
//}
