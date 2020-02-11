//
// Created by vasil on 09.02.2020.
//

#include <tuple>
#include "pystruct.h"
#include "Python.h"
void pystruct::read() {
    //Py_Initialize();
    PyRun_SimpleString("from time import time,ctime\n"
                       "print('Today is', ctime(time()))\n");
    //Py_Finalize();
}

std::string pystruct::pack(std::string types, std::string vars) {

    char *ret = NULL;

    // Загрузка func.py
    auto pName = PyUnicode_FromString("struc");
    if (!pName) {
        return ret;
    }

    // Загрузить объект модуля
    auto pModule = PyImport_Import(pName);
    if (!pModule) {
        return ret;
    }

    // Словарь объектов содержащихся в модуле
    auto pDict = PyModule_GetDict(pModule);
    if (!pDict) {
        return ret;
    }

    // Загрузка объекта get_value из func.py
    auto pObjct = PyDict_GetItemString(pDict, (const char *) "get_value");
    if (!pObjct) {
        return ret;
    }


    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct)) {
        return ret;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *) "(s)", val);
    if (pVal != NULL) {
        PyObject* pResultRepr = PyObject_Repr(pVal);

        // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
        // Для начала pResultRepr нужно привести к массиву байтов.
        ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

        Py_XDECREF(pResultRepr);
        Py_XDECREF(pVal);
    }

}

void pystruct::unpack(std::string types, std::string vars) {
    //Py_Initialize();
    //PyRun_SimpleString("import struct\n" "print(type(struct.unpack('<i', struct.pack('<i', 1488))))\n");




    //Py_Finalize();
}


#include "pystruct.h"
