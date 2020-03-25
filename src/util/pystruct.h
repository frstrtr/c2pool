//
// Created by vasil on 09.02.2020.
//

#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include "Python.h"
#include <sstream>
using namespace std;


class Py {
public:
    static bool _ready;
    static void Initialize() {
        if (!_ready) {
            Py_Initialize();
            _ready = true;
        }
    }

    static void Finalize(){
        if (_ready){
            Py_Finalize();
            _ready = false;
        }
    }
};

namespace c2pool::python::message {
    class pymessage {
    public:
        static stringstream unpack(char* command, char* data);

        static char* pack(char* command, char* vars);

        static char* pack(char* command, stringstream &vars);
    };
}

class pystruct{
public:
    static stringstream unpack(char* types, char* vars);

    static char* pack(char* types, char* vars);

    static char* pack(char* types, stringstream &vars);
};


#endif //CPOOL_PYSTRUCT_H
