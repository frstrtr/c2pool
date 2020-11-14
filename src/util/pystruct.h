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

namespace c2pool::messages::python
{
    class other
    {
    public:
        static void debug_log(char *data, unsigned int len);
    };

    class pymessage
    {
    public:
        static unsigned int receive_length(char *length_data);

        //called, when get message from p2pool [unpacked]
        static std::stringstream receive(char *command, char *checksum, char *payload, unsigned int length);

        //TODO: prefix
        //called, when send message to p2pool [packed]
        static char *send(char *command, char *payload2);

        static char *send(c2pool::messages::message *msg);

        static int payload_length(char *command, char *payload2);

        static int payload_length(c2pool::messages::message *msg);
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
        //msg.[unsigned char*] -> bytes -> json -> obj(c++)
        static UniValue deserialize(c2pool::messages::message *msg);

        static int payload_length(c2pool::messages::message *msg);

        //obj(c++) -> json -> bytes -> len(bytes)
        template <typename T>
        static unsigned int packed_size(char *name_type, T &value);

        static unsigned int receive_length(char *length_data);

    };
} // namespace c2pool::messages::python

namespace c2pool::messages::python::for_test
{
    class pymessage
    {
    public:
        static char *get_packed_int(int num);

        static char *data_for_test_receive();

        static char *checksum_for_test_receive();

        static unsigned int length_for_test_receive();

        static char *data_for_test_send();

        //called, when send message to p2pool [packed]
        static std::stringstream emulate_protocol_get_data(char *comamnd, char *payload2);

        static void test_get_bytes_from_cpp(char *data, int len);
    };
} // namespace c2pool::messages::python::for_test

#endif //CPOOL_PYSTRUCT_H
