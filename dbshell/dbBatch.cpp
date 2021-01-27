#include "leveldb/db.h"
#include "dbBatch.h"
#include "dbObject.h"

namespace dbshell
{
    void DBBatch::Write(const std::string &key, DBObject &value)
    {
        leveldb::Slice sliceKey = key;
        leveldb::Slice sliceValue = value.SerializeJSON();

        batch.Put(sliceKey, sliceValue);
    }

    void DBBatch::Remove(const std::string &key)
    {
        leveldb::Slice sliceKey = key;

        batch.Delete(sliceKey);
    }

    void DBBatch::Clear()
    {
        batch.Clear();
    }
} // namespace dbshell
