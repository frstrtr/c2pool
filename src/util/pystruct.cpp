#include <tuple>
#include "pystruct.h"
#include "Python.h"
#include <filesys.h>
#include <iostream>
#include <sstream>
#include "other.h"
#include "messages.h"

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

    unsigned int pymessage::receive_length(char *length_data)
    {
        c2pool::python::Py::Initialize();

        unsigned int result_method = 0;

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

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(y#)", length_data, 4);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "ISO-8859-1", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        //std::cout << "ret: " << ret << std::endl; //TODO: DEBUG_PYTHON

        res << ret;
        res >> result_method;
        //std::cout << "result_method: " << result_method << std::endl; //TODO: DEBUG_PYTHON
        return result_method;
    }

    std::stringstream pymessage::receive(char *command, char *checksum, char *payload, unsigned int length)
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

        //std::cout << "LEN: " << len << std::endl;
        auto pVal = PyObject_CallFunction(pObjct, (char *)"(sy#y#)", command, checksum, 4, payload, length);
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

    char *pymessage::send(char *command, char *payload2)
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

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", command, payload2);
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

        return c2pool::str::from_bytes_to_strChar(ret);
    }

    char *pymessage::send(c2pool::messages::message *msg)
    {
        //std::cout << "SEND_PACK_C_STR: " << msg->command << ", " << msg->pack_c_str() << std::endl;

        return send(msg->command, msg->pack_c_str());
    }

    int pymessage::payload_length(char *command, char *payload2)
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

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"payload_length");
        if (!pObjct)
        {
            return result_method;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return result_method;
        }

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", command, payload2);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "ISO-8859-1", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        res << ret;
        res >> result_method;

        return result_method;
    }

    int pymessage::payload_length(c2pool::messages::message *msg)
    {
        return payload_length(msg->command, msg->pack_c_str());
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

        ret += 1;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return c2pool::str::from_bytes_to_strChar(ret);
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
        //std::cout << "data_for_test_receive(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON

        ret += 1;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        return c2pool::str::from_bytes_to_strChar(ret);
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

        //std::cout << "checksum_for_test_receive(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON

        ret += 1;                 //remove first 2 element [b'] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        return c2pool::str::from_bytes_to_strChar(ret);
    }

    unsigned int pymessage::length_for_test_receive()
    {
        c2pool::python::Py::Initialize();

        unsigned int result_method = 0;

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

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"length_for_test_receive");
        if (!pObjct)
        {
            return result_method;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return result_method;
        }

        auto pVal = PyObject_CallFunction(pObjct, "");
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "ISO-8859-1", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        //std::cout << "ret: " << ret << std::endl; //TODO: DEBUG_PYTHON

        res << ret;
        res >> result_method;

        return result_method;
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

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON

        ret += 1;                 //remove first 2 element [b'] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
        return c2pool::str::from_bytes_to_strChar(ret);
    }

    std::stringstream pymessage::emulate_protocol_get_data(char *command, char *payload2)
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

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"emulate_protocol_get_data");
        if (!pObjct)
        {
            return res;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return res;
        }

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(ss)", command, payload2);
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

    void pymessage::test_get_bytes_from_cpp(char *data, int len)
    {
        std::cout << "DATA: " << data << ", LEN: " << len << std::endl;
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
            return;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {

            return;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return;
        }

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"test_get_bytes_from_cpp");
        if (!pObjct)
        {
            return;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return;
        }
        auto pVal = PyObject_CallFunction(pObjct, (char *)"(y#)", data, len);
        if (pVal != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pVal);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            //ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "ISO-8859-1", "ERROR")));
            Py_XDECREF(pResultRepr);
            Py_XDECREF(pVal);
        }

        //std::cout << "get_packed_int return(without dot): ." << ret << std::endl; //TODO: DEBUG_PYTHON
    }
} // namespace c2pool::messages::python::for_test