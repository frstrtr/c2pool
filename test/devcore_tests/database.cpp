#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <leveldb/db.h>
#include <vector>
#include <string>
#include <leveldb/write_batch.h>
#include <libdevcore/db.h>
#include <libdevcore/filesystem.h>

namespace fs = boost::filesystem;

TEST(DatabaseTest, boost_database)
{
	leveldb::DB *db;

	leveldb::Options options;
	options.create_if_missing = true;

	leveldb::Status status_open = leveldb::DB::Open(options, "testdb", &db);
	std::cout << "Opened, status: " << status_open.ToString() << std::endl;

	int32_t key = 123;
	std::vector<unsigned char> value = {0x12, 0xaf, 0x0, 0x21, 0xff};

	leveldb::Slice slice_key(reinterpret_cast<const char *>(&key), sizeof(key));
	leveldb::Slice slice_value(reinterpret_cast<const char *>(value.data()), value.size());
	db->Put(leveldb::WriteOptions(), slice_key, slice_value);

	std::string readed_data;
	db->Get(leveldb::ReadOptions(), slice_key, &readed_data);
	leveldb::Slice slice_read(readed_data);

	unsigned char *readed_unpack_data = (unsigned char *) slice_read.data();
	std::vector<unsigned char> value_data2(readed_unpack_data, readed_unpack_data + 5);
	ASSERT_EQ(value, value_data2);

	for (auto v: value)
	{
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

	for (auto v: value_data2)
	{
		std::cout << (unsigned int) v << " ";
	}
	std::cout << std::endl;

}

TEST(DatabaseTest, db_test)
{
	std::unique_ptr<Database> db = std::make_unique<Database>(c2pool::filesystem::getProjectPath(), "DbTest1");
	db->Write(123, 321);

	auto _value = db->Read(123);
	int* value = reinterpret_cast<int*>(_value.data());

	ASSERT_EQ(321, *value);
	ASSERT_TRUE(db->Exist(123));

	db->Remove(123);
	ASSERT_FALSE(db->Exist(123));
}