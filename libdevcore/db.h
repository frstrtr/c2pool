#pragma once

#include <iostream>

#include <string>

#include <leveldb/db.h>
#include <leveldb/slice.h>
#include <boost/filesystem.hpp>

#include "logger.h"
#include "stream.h"

class Database
{
protected:
	leveldb::DB *db;

	leveldb::Options options;
//	leveldb::WriteOptions writeOptions;
//	leveldb::WriteOptions syncOptions;
//	leveldb::ReadOptions iterOptions;
//	leveldb::ReadOptions readOptions;

	std::string name;

public:
	Database(const boost::filesystem::path &filepath, const std::string &_name, bool wipe = false);
	~Database();

	Database(const Database &) = delete;

	Database &operator=(const Database &) = delete;

	//Write value to DB
	template<typename KeyStreamType, typename ValueStreamType, typename KEY_T, typename VALUE_T>
	void Write(const KEY_T &key, const VALUE_T &value)
	{
        // Pack key
        auto packed_key = pack_to_stream<KeyStreamType>(key);
        leveldb::Slice k(packed_key.c_str(), packed_key.size());

        // Pack value
        auto packed_value = pack_to_stream<ValueStreamType>(value);
        leveldb::Slice v(packed_value.c_str(), packed_value.size());

		auto status = db->Put(leveldb::WriteOptions(), k, v);
        if (!status.ok())
        {
            LOG_WARNING << "DB::Write: " << status.ToString();
        }
	}

	template<typename KeyStreamType, typename ValueStreamType>
    ValueStreamType Read(const typename KeyStreamType::get_type &key)
	{
        // Pack key
        auto packed_key = pack_to_stream<KeyStreamType>(key);
        leveldb::Slice k(packed_key.c_str(), packed_key.size());

        // Read from db
		std::string data;

		auto status = db->Get(leveldb::ReadOptions(), k, &data);
        if (!status.ok())
        {
            LOG_WARNING << "DB::Read: " << status.ToString();
        }
		leveldb::Slice slice_data(data);

		auto *unpacked_data = (unsigned char *) slice_data.data();
		PackStream result(unpacked_data, slice_data.size());
        ValueStreamType res;
        result >> res;
		return res;
	}

	template<typename KeyStreamType, typename KEY_T>
	void Remove(const KEY_T &key)
	{
        // Pack key
        auto packed_key = pack_to_stream<KeyStreamType>(key);
        leveldb::Slice k(packed_key.c_str(), packed_key.size());

		db->Delete(leveldb::WriteOptions(), k);
	}

	template<typename KeyStreamType, typename KEY_T>
	bool Exist(const KEY_T &key)
	{
        // Pack key
        auto packed_key = pack_to_stream<KeyStreamType>(key);
        leveldb::Slice k(packed_key.c_str(), packed_key.size());

		std::string data;

		auto status = db->Get(leveldb::ReadOptions(), k, &data);
		return !status.IsNotFound();
	}

//	bool IsEmpty()
//	{
//		//TODO:
//        return false;
//	}
};