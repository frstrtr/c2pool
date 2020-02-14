//
// Created by vasil on 09.02.2020.
//

#include <tuple>
#include "pystruct.h"
#include "Python.h"
#include <filesys.h>
#include<iostream>


using namespace std;


char* pystruct::pack(char* types, char* vars) {

    char *ret = NULL;


    // Загрузка модуля sys
    auto sys = PyImport_ImportModule("sys");
    auto sys_path = PyObject_GetAttrString(sys, "path");
    // Путь до наших исходников Python
    auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
    PyList_Append(sys_path, folder_path);



    // Загрузка struc.py
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

    auto pObjct = PyDict_GetItemString(pDict, (const char *) "pack");
    if (!pObjct) {
        return ret;
    }


    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct)) {
        return ret;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *) "(ss)", types, vars);
    if (pVal != NULL) {
        PyObject* pResultRepr = PyObject_Repr(pVal);

        // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
        // Для начала pResultRepr нужно привести к массиву байтов.
        ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

        Py_XDECREF(pResultRepr);
        Py_XDECREF(pVal);
    }
    return ret;
}

void pystruct::unpack(std::string types, std::string vars) {
    //Py_Initialize();
    //PyRun_SimpleString("import struct\n" "print(type(struct.unpack('<i', struct.pack('<i', 1488))))\n");




    //Py_Finalize();
}


#include "pystruct.h"
