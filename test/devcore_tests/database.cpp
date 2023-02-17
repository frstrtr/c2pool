#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <leveldb/db.h>
#include <vector>
#include <string>
#include <leveldb/write_batch.h>
#include <libdevcore/db.h>
#include <libdevcore/filesystem.h>
#include <btclibs/uint256.h>
#include <libdevcore/stream_types.h>

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
	auto db = std::make_unique<Database<StrType, StrType>>(c2pool::filesystem::getProjectPath()/"libdevcore_test", "DbTest1", true);
	std::string k = "2222";
    std::string v = "123";

    db->Write(k, v);

	auto _value = db->Read(k);
	std::string value = _value.get();

	ASSERT_EQ(v, value);

	ASSERT_TRUE(db->Exist(k));

	db->Remove(k);
	ASSERT_FALSE(db->Exist(k));
}
//
//TEST(DatabaseTest, db_test2)
//{
//    std::unique_ptr<Database> db = std::make_unique<Database>(c2pool::filesystem::getProjectPath()/"libdevcore_test", "DbTest2", true);
//    uint256 k = uint256S("4ce");
//    std::string v = "123";
//
//    db->Write<IntType(256), StrType>(k, v);
//
//    auto _value = db->Read<StrType>(k);
//    std::string value(_value.begin(), _value.end());
//
//    ASSERT_EQ(v, value);
//    ASSERT_TRUE(db->Exist(k));
//
//    db->Remove(k);
//    ASSERT_FALSE(db->Exist(v));
//}