#pragma once

#include <string>

#include <leveldb/db.h>
#include <leveldb/slice.h>
#include <boost/filesystem.hpp>

class DBObject;
class DBBatch;

class Database
{
protected:
	leveldb::DB* db;

	leveldb::Options options;
	leveldb::WriteOptions writeOptions;
	leveldb::WriteOptions syncOptions;
	leveldb::ReadOptions iterOptions;
	leveldb::ReadOptions readOptions;

	std::string name;

public:
	Database(const boost::filesystem::path &filepath, std::string _name, bool wipe = false);

	~Database();

	Database(const Database &) = delete;

	Database &operator=(const Database &) = delete;



	//Write value to DB
	bool Write(const std::string &key, DBObject &value, bool sync = false);

	bool Write(DBBatch &batch, bool sync = false);

	//Read value from DB
	bool Read(const std::string &key, DBObject &value);

	//Delete element from DB
	bool Remove(const std::string &key, bool fSync = false); //TODO

	bool Exist(const std::string &key); //TODO
	bool IsEmpty(); //TODO
};