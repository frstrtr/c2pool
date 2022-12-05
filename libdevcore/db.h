#pragma once

#include <iostream>

#include <string>

#include <leveldb/db.h>
#include <leveldb/slice.h>
#include <boost/filesystem.hpp>

class Database
{
protected:
	leveldb::DB *db;

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
	template<typename KEY_T, typename VALUE_T>
	void Write(const KEY_T &key, const VALUE_T &value)
	{
		leveldb::Slice _key(reinterpret_cast<const char *>(&key), sizeof(key));
		leveldb::Slice _value(reinterpret_cast<const char *>(&value), sizeof(value));

		auto Status = db->Put(leveldb::WriteOptions(), _key, _value);
	}

	template<typename KEY_T>
	std::vector<unsigned char> Read(const KEY_T &key)
	{
		leveldb::Slice _key(reinterpret_cast<const char *>(&key), sizeof(key));
		std::string data;

		auto status = db->Get(leveldb::ReadOptions(), _key, &data);
		leveldb::Slice slice_data(data);

		unsigned char *unpacked_data = (unsigned char *) slice_data.data();
		std::vector<unsigned char> result(unpacked_data, unpacked_data + slice_data.size());
		return result;
	}

	template<typename KEY_T>
	void Remove(const KEY_T &key)
	{
		leveldb::Slice _key(reinterpret_cast<const char *>(&key), sizeof(key));
		db->Delete(leveldb::WriteOptions(), _key);
	}

	template<typename KEY_T>
	bool Exist(const KEY_T &key)
	{
		leveldb::Slice _key(reinterpret_cast<const char *>(&key), sizeof(key));
		std::string data;

		auto status = db->Get(leveldb::ReadOptions(), _key, &data);
		return !status.IsNotFound();
	}

	bool IsEmpty()
	{
		//TODO:
        return false;
	}
};