#include "db.h"
#include "dbObject.h"
#include "dbBatch.h"
#include <string>
//#include <console>

namespace dbshell
{

    Database::Database(const std::string /*TODO: boost::filesystem*/ filepath, bool reset)
    {
        options.create_if_missing = true;

        leveldb::Status status = leveldb::DB::Open(options, filepath, &db);

        if (!status.ok())
        {
            //LOG_ERROR << "Unable to open/create datebase with path:  " << filepath
            //          << "; status: " << status.ToString();
            //TODO: close proj
        }

        //TODO: wipe db
    }

    Database::~Database()
    {
        delete db;
    }

    bool Database::Write(const std::string &key, DBObject &value, bool sync)
    {
        DBBatch batch;
        batch.Write(key, value);
        return Write(batch, sync);
    }

    bool Database::Write(DBBatch &batch, bool sync)
    {
        leveldb::Status status = db->Write(sync ? syncOptions : writeOptions, &batch.batch);

        if (!status.ok())
        {
            //LOG_ERROR << "Failed write data to db:  " << filepath
            //          << "; status: " << status.ToString();
            return false;
        }

        return true;
    }

    bool Database::Read(const std::string &key, DBObject &value)
    {
        leveldb::Slice sliceKey = key;
        std::string _value;

        leveldb::Status status = db->Get(readOptions, sliceKey, &_value);

        if (!status.ok())
        {
            if (status.IsNotFound())
                return false;
            //LOG_ERROR << "Failed read data from db:  " << filepath
            //          << "; status: " << status.ToString();
            return false;
        }

        //TODO: try catch deserialize?

        value.DeserializeJSON(_value);

        return true;
    }

    bool Database::Remove(const std::string &key, bool fSync)
    {
        //TODO:
    }

    bool Database::Exist(const std::string &key)
    {
        leveldb::Slice sliceKey = key;
        std::string _value;

        leveldb::Status status = db->Get(readOptions, key, &_value);

        if (!status.ok())
        {
            if (status.IsNotFound())
                return false;

            //LOG_ERROR << "Failed read data from db:  " << filepath
            //          << "; status: " << status.ToString();
        }

        return true;
    }

    bool Database::IsEmpty()
    {
        //TODO: create iterator
    }

} // namespace dbshell