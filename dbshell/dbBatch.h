#ifndef DBSHELL_BATCH_H
#define DBSHELL_BATCH_H

#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "db.h"

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

#endif