#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include <sstream>
using namespace std;

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
    class pymessage
    {
    public:
        static int receive_length(char *length_data);

        //called, when get message from p2pool [unpacked]
        static std::stringstream receive(char *command, char *checksum, char *payload);

        //called, when send message to p2pool [packed]
        static char *send(char *comamnd, char *payload2);
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

        static char *data_for_test_send();

        //called, when send message to p2pool [packed]
        static std::stringstream emulate_protocol_get_data(char *comamnd, char *payload2);
    };
} // namespace c2pool::messages::python::for_test

#endif //CPOOL_PYSTRUCT_H
