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
	char *key_packed = reinterpret_cast<char *>(&key);
    int32_t len = sizeof(key) / sizeof(*key_packed);
	std::vector<unsigned char> value = {0x12, 0xaf, 0x0, 0x21, 0xff};
	char* value_data = (char*) value.data();
	std::cout << "ok" << std::endl;

	leveldb::WriteBatch batch;
	leveldb::Slice slice_key(key_packed,  len);
	leveldb::Slice slice_value(value_data,  value.size());
	std::cout << "Sliced" << std::endl;
	db->Put(leveldb::WriteOptions(), slice_key, slice_value);

//	db->Write(leveldb::WriteOptions(),)

	std::string* readed_data = new std::string();
	db->Get(leveldb::ReadOptions(), slice_key, readed_data);
	leveldb::Slice slice_read(*readed_data);

	unsigned char* readed_unpack_data = (unsigned char*) slice_read.data();
	std::cout << "Unpacked!" << std::endl;
	std::vector<unsigned char> value_data2(readed_unpack_data, readed_unpack_data+5);
	ASSERT_EQ(value, value_data2);

	for(auto v : value){
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

	for(auto v : value_data2){
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

}