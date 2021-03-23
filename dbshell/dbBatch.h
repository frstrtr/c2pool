#pragma once
#include "db.h"

#include <lib/leveldb/include/leveldb/db.h> //TODO
#include <lib/leveldb/include/leveldb/write_batch.h> //TODO:

namespace dbshell{
    class DBObject;
}

namespace dbshell
{
    class DBBatch
    {
        friend dbshell::Database;
    private:
        leveldb::WriteBatch batch;

    public:
        void Write(const std::string& key, DBObject& value);

        void Remove(const std::string& key);

        void Clear();
    };

} // namespace dbshell