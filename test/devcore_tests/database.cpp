#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <leveldb/db.h>
#include <vector>
#include <string>
#include <leveldb/write_batch.h>

namespace fs = boost::filesystem;

TEST(Database, boost_database)
{
	leveldb::DB* db;

	leveldb::Options options;
	options.create_if_missing = true;

	std::cout << "Try to open..." << std::endl;
	leveldb::Status status_open = leveldb::DB::Open(options, "testdb", &db);
	std::cout << "Opened, status: " << status_open.ToString() << std::endl;

	int32_t key = 123;
	std::vector<unsigned char> value_data = {0x12, 0xaf, 0x0, 0x21, 0xff};
	std::cout << "ok" << std::endl;

	leveldb::WriteBatch batch;
	leveldb::Slice slice_key((char*)key,  sizeof(key));
	leveldb::Slice slice_value((char*)value_data.data(),  value_data.size());
	std::cout << "Sliced" << std::endl;
	db->Put(leveldb::WriteOptions(), slice_key, slice_value);

	std::cout << "Put: ok!" << std::endl;
	std::string* readed_data;
	db->Get(leveldb::ReadOptions(), slice_key, readed_data);
	leveldb::Slice slice_read(*readed_data);

	unsigned char* readed_unpack_data = (unsigned char*) slice_read.data();
	std::vector<unsigned char> value_data2(readed_unpack_data, readed_unpack_data+5);
	ASSERT_EQ(value_data, value_data2);

}