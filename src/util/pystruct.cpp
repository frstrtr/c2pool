#include <tuple>
#include "pystruct.h"
#include "Python.h"
#include <filesys.h>
#include <iostream>
#include <sstream>

using namespace std;

namespace c2pool::python
{
    bool Py::_ready = false;

    void Py::Initialize()
    {
        if (!_ready)
        {
            Py_Initialize();
            _ready = true;
        }
    }

    void Py::Finalize()
    {
        if (_ready)
        {
            Py_Finalize();
            _ready = false;
        }
    }
} // namespace c2pool::python

/*
char *pystruct::pack(char *types, char *vars)
{

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
    if (!pName)
    {
        return ret;
    }

    // Загрузить объект модуля
    auto pModule = PyImport_Import(pName);
    if (!pModule)
    {
        return ret;
    }

    // Словарь объектов содержащихся в модуле
    auto pDict = PyModule_GetDict(pModule);
    if (!pDict)
    {
        return ret;
    }

    auto pObjct = PyDict_GetItemString(pDict, (const char *)"pack");
    if (!pObjct)
    {
        return ret;
    }

    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct))
    {
        return ret;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", types, vars);
    if (pVal != NULL)
    {
        PyObject *pResultRepr = PyObject_Repr(pVal);

        // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
        // Для начала pResultRepr нужно привести к массиву байтов.
        ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

        Py_XDECREF(pResultRepr);
        Py_XDECREF(pVal);
    }
    return ret;
}

char *pystruct::pack(char *types, stringstream &vars)
{
    string s;
    string buff;
    while (vars >> buff)
    {
        s += buff;
    }

    char *res = new char[s.length() + 1];
    std::strcpy(res, s.c_str());

    return pystruct::pack(types, res);
}

stringstream pystruct::unpack(char *types, char *vars)
{
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
    if (!pName)
    {
        return res;
    }

    // Загрузить объект модуля
    auto pModule = PyImport_Import(pName);
    if (!pModule)
    {
        return res;
    }

    // Словарь объектов содержащихся в модуле
    auto pDict = PyModule_GetDict(pModule);
    if (!pDict)
    {
        return res;
    }

    auto pObjct = PyDict_GetItemString(pDict, (const char *)"unpack");
    if (!pObjct)
    {
        return res;
    }

    // Проверка pObjct на годность.
    if (!PyCallable_Check(pObjct))
    {
        return res;
    }

    auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", types, vars);
    if (pVal != NULL)
    {
        PyObject *pResultRepr = PyObject_Repr(pVal);

        // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
        // Для начала pResultRepr нужно привести к массиву байтов.
        ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));
        Py_XDECREF(pResultRepr);
        Py_XDECREF(pVal);
    }
    ret++;                    //remove first element ['] in string
    ret[strlen(ret) - 1] = 0; //remove last element ['] in string

    res << ret;
    return res;
} */
//______________________________messages______________________

namespace c2pool::messages::python
{

    int pymessage::receive_length(char *length_data)
    {
        c2pool::python::Py::Initialize();

        int result_method = 0;

        std::stringstream res;

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return result_method;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {
            return result_method;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return result_method;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"receive_length");
        if (!pObjct)
        {
            return result_method;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return result_method;
        }

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(s)", length_data);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }
        ret += 1;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << ret << std::endl; //TODO: DEBUG_PYTHON

        res << ret;
        res >> result_method;

        return result_method;
    }

    std::stringstream pymessage::receive(char *command, char *checksum, char *payload)
    {
        c2pool::python::Py::Initialize();

        stringstream res;

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return res;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {
            return res;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return res;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"receive");
        if (!pObjct)
        {
            return res;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return res;
        }

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(sss)", command, checksum, payload);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }
        ret++;                    //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        res << ret;
        return res;
    }

    char *pymessage::send(char *comamnd, char *payload2)
    {

        c2pool::python::Py::Initialize();

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return ret;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {
            return ret;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return ret;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"send");
        if (!pObjct)
        {
            return ret;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return ret;
        }

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", comamnd, payload2);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        ret += 2;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        return ret;
    }
} // namespace c2pool::messages::python

namespace c2pool::messages::python::for_test
{
    char *pymessage::get_packed_int(int num)
    {
        c2pool::python::Py::Initialize();

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return ret;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {

            return ret;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return ret;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"get_packed_int");
        if (!pObjct)
        {
            return ret;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return ret;
        }
        auto pVal = PyObject_CallFunction(pObjct, (char *)"(i)", num);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        ret += 2;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return ret;
    }

    char *pymessage::data_for_test_receive()
    {
        c2pool::python::Py::Initialize();

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return ret;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {

            return ret;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return ret;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"data_for_test_receive");
        if (!pObjct)
        {
            return ret;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return ret;
        }
        auto pVal = PyObject_CallFunction(pObjct, "");
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        ret += 2;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return ret;
    }

    char *pymessage::checksum_for_test_receive()
    {
        c2pool::python::Py::Initialize();

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return ret;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {

            return ret;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return ret;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"checksum_for_test_receive");
        if (!pObjct)
        {
            return ret;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return ret;
        }
        auto pVal = PyObject_CallFunction(pObjct, "");
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        ret += 2;                 //remove first 2 element [b'] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return ret;
    }

    char *pymessage::data_for_test_send()
    {
        c2pool::python::Py::Initialize();

        char *ret = NULL;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString("packtypes");
        if (!pName)
        {
            return ret;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {

            return ret;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return ret;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"data_for_test_send");
        if (!pObjct)
        {
            return ret;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return ret;
        }
        auto pVal = PyObject_CallFunction(pObjct, "");
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        ret += 2;                 //remove first 2 element [b'] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return ret;
    }
} // namespace c2pool::messages::python::for_test