#pragma once

#include <devcore/py_base.h>
#include <string>
#include <univalue.h>
#include <memory>

using namespace std;

namespace c2pool::python
{
    class other
    {
    public:
        static void debug_log(char *data, unsigned int len);
    };

    class PyPackTypes : public c2pool::python::PythonBase
    {
    protected:
        static const char *filepath;

    public:
        static bool is_worked();

        //obj(c++) -> json -> bytes -> unsigned_char*
        // template <typename T>
        // static char *serialize(char *name_type, T &value);
        //message_<command> -> json -> bytes -> unsigned_char*
        static char *encode(UniValue json);

        //unsigned char* -> bytes -> json -> obj(c++)
        // static UniValue deserialize(char *command, char *checksum, char *payload, int unpacked_length); //length = len(value)

        static UniValue decode(char* command, char* checksum, char* payload, int32_t unpacked_len); //length = len(value)

        //(def name: deserialize_msg)
        //msg.[unsigned char*] -> bytes -> json -> obj(c++)
        // static UniValue deserialize(c2pool::messages::message *msg);

        // static int payload_length(shared_ptr<c2pool::libnet::messages::base_message> msg);

        //json -> bytes -> len(bytes)
        static int32_t packed_size(char *name_type, UniValue json_obj);

        static unsigned int receive_length(char *length_data);

        static UniValue generate_error_json(UniValue json);
    };
} // namespace c2pool::python

namespace c2pool::python::for_test
{
    class PyType : public c2pool::python::PythonBase
    {
    protected:
        static const char *filepath;

    public:
        static char *IntType256_test(std::string hex_num);
    };
} // namespace c2pool::python::for_test