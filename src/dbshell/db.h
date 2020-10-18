#include "leveldb/db.h"
#include <string>

namespace dbshell{
    class DBObject;
    class DBBatch;
}

namespace dbshell
{
    //TODO: Objects to bytes serialize;
    //TODO: stream << key/value;
    class Database
    {
    private:
        leveldb::DB *db;

        leveldb::Options options;
        leveldb::WriteOptions writeOptions;
        leveldb::WriteOptions syncOptions;
        leveldb::ReadOptions iterOptions;
        leveldb::ReadOptions readOptions;

    public:
        Database(const std::string /*TODO: boost::filesystem*/ filepath, bool reset = false); //TODO
        ~Database();

        //Write value to DB
        bool Write(const std::string& key, DBObject& value, bool sync = false);
        bool Write(DBBatch& batch, bool sync = false);
        //Read value from DB
        bool Read(const std::string& key, DBObject& value);
        //Delete element from DB
        bool Remove(const std::string& key, bool fSync = false); //TODO

        bool Exist(const std::string& key); //TODO
        bool IsEmpty(); //TODO

        Database(const Database &) = delete;
        Database &operator=(const Database &) = delete;
    };
} // namespace dbshell