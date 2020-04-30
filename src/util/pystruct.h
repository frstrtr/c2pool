#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include <sstream>
using namespace std;

class Py
{
public:
    static bool _ready;
    static void Initialize();

    static void Finalize();
};

namespace c2pool::python::message
{
    class pymessage
    {
    public:
        static stringstream unpack(char *command, char *data);

        static char *pack(char *command, char *vars);

        static char *pack(char *command, stringstream &vars);
    };
} // namespace c2pool::python::message

class pystruct
{
public:
    static stringstream unpack(char *types, char *vars);

    static char *pack(char *types, char *vars);

    static char *pack(char *types, stringstream &vars);
};

#endif //CPOOL_PYSTRUCT_H
