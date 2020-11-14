#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include <sstream>
#include <univalue.h>

using namespace std;

namespace c2pool::messages
{
    class message;
}

namespace c2pool::python
{
    class Py
    {
    public:
        static bool _ready;
        static void Initialize();

        static void Finalize();
    };
} // namespace c2pool::python

namespace c2pool::python
{
    class other
    {
    public:
        static void debug_log(char *data, unsigned int len);
    };

    class PyPackTypes
    {
    private:
        static auto GetMethodObject(const char *method_name, const char *filename = "packtypes");

        template <typename PyObjectType>
        static char *GetCallFunctionResult(PyObjectType *pyObj);

    public:
        //obj(c++) -> json -> bytes -> unsigned_char*
        template <typename T>
        static char *serialize(char *name_type, T &value);
        //message_<command> -> json -> bytes -> unsigned_char*
        static char *serialize(c2pool::messages::message *msg);

        //unsigned char* -> bytes -> json -> obj(c++)
        static UniValue deserialize(char *name_type, char *value, int length); //length = len(value)
        
        //(def name: deserialize_msg)
        //msg.[unsigned char*] -> bytes -> json -> obj(c++)
        static UniValue deserialize(c2pool::messages::message *msg);

        static int payload_length(c2pool::messages::message *msg);

        //obj(c++) -> json -> bytes -> len(bytes)
        template <typename T>
        static unsigned int packed_size(char *name_type, T &value);

        static unsigned int receive_length(char *length_data);
    };
} // namespace c2pool::python

namespace c2pool::python::for_test
{
    class pymessage
    {
    public:
    };
} // namespace c2pool::python::for_test

#endif //CPOOL_PYSTRUCT_H
