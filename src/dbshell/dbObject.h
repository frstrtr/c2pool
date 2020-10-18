// interface for any objects which should be put into the database
#include <string>

namespace dbshell
{
    class DBObject
    {
    public:
        virtual std::string SerializeJSON() = 0;
        virtual void DeserializeJSON(std::string json) = 0;
    };
} // namespace dbshell