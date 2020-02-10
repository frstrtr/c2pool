//
// Created by vasil on 09.02.2020.
//

#include <tuple>
#include "pystruct.h"
#include "Python.h"
void pystruct::read() {
    Py_Initialize();
    PyRun_SimpleString("from time import time,ctime\n"
                       "print('Today is', ctime(time()))\n");
    Py_Finalize();
}

void pystruct::pack(std::string, std::tuple vars) {

}

void pystruct::unpack(std::string types, std::tuple<> vars) {

}


#include "pystruct.h"
