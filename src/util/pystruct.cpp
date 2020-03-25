//
// Created by vasil on 09.02.2020.
//

#include <tuple>
#include "pystruct.h"
#include "Python.h"
#include <filesys.h>
#include <iostream>
#include <sstream>


using namespace std;

bool Py::_ready = false;

char* pystruct::pack(char* types, char* vars) {

    Py::Initialize();

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

char* pystruct::pack(char *types, stringstream& vars) {
    string s;
    string buff;
    while (vars >> buff){
        s += buff;
    }

    char* res = new char[s.length() + 1];
    std::strcpy(res, s.c_str());

    return pystruct::pack(types, res);
}

stringstream pystruct::unpack(char* types, char* vars) {
    Py::Initialize();

    stringstream res;

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
        return res;
    }

    // Загрузить объект модуля
    auto pModule = PyImport_Import(pName);
    if (!pModule) {
        return res;
    }

    // Словарь объектов содержащихся в модуле
    auto pDict = PyModule_GetDict(pModule);
    if (!pDict) {
        return res;
    }

    auto pObjct = PyDict_GetItemString(pDict, (const char *) "unpack");
    if (!pObjct) {
        return res;
    }


    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct)) {
        return res;
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
    ret++; //remove first element ['] in string
    ret[strlen(ret)-1] = 0; //remove last element ['] in string

    res << ret;
    return res;

}
//______________________________messages______________________

stringstream c2pool::python::message::pymessage::unpack(char *command, char *data) {
    Py::Initialize();

    stringstream res;

    char *ret = NULL;


    // Загрузка модуля sys
    auto sys = PyImport_ImportModule("sys");
    auto sys_path = PyObject_GetAttrString(sys, "path");
    // Путь до наших исходников Python
    auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
    PyList_Append(sys_path, folder_path);



    // Загрузка struc.py
    auto pName = PyUnicode_FromString("packtypes");
    if (!pName) {
        return res;
    }

    // Загрузить объект модуля
    auto pModule = PyImport_Import(pName);
    if (!pModule) {
        return res;
    }

    // Словарь объектов содержащихся в модуле
    auto pDict = PyModule_GetDict(pModule);
    if (!pDict) {
        return res;
    }

    auto pObjct = PyDict_GetItemString(pDict, (const char *) "message_unpack");
    if (!pObjct) {
        return res;
    }


    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct)) {
        return res;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *) "(ss)", command, data);
    if (pVal != NULL) {
        PyObject* pResultRepr = PyObject_Repr(pVal);

        // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
        // Для начала pResultRepr нужно привести к массиву байтов.
        ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));
        Py_XDECREF(pResultRepr);
        Py_XDECREF(pVal);
    }
    ret++; //remove first element ['] in string
    ret[strlen(ret)-1] = 0; //remove last element ['] in string

    res << ret;
    return res;
}

char *c2pool::python::message::pymessage::pack(char *command, char *vars) {

    Py::Initialize();

    char *ret = NULL;


    // Загрузка модуля sys
    auto sys = PyImport_ImportModule("sys");
    auto sys_path = PyObject_GetAttrString(sys, "path");
    // Путь до наших исходников Python
    auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
    PyList_Append(sys_path, folder_path);



    // Загрузка struc.py
    auto pName = PyUnicode_FromString("packtypes");
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

    auto pObjct = PyDict_GetItemString(pDict, (const char *) "message_pack");
    if (!pObjct) {
        return ret;
    }


    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct)) {
        return ret;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *) "(ss)", command, vars);
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

char *c2pool::python::message::pymessage::pack(char *command, stringstream &vars) {
    string s;
    string buff;
    while (vars >> buff){
        s += buff;
    }

    char* res = new char[s.length() + 1];
    std::strcpy(res, s.c_str());

    return pystruct::pack(command, res);
}


