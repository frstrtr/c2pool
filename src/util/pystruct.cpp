#include "pystruct.h"
#include "Python.h"
#include "other.h"
#include "messages.h"
#include "univalue.h"
#include "filesys.h"

#include <tuple>
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

namespace c2pool::python
{

    void other::debug_log(char *data, unsigned int len)
    {
        c2pool::python::Py::Initialize();

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

        auto pObjct = PyDict_GetItemString(pDict, (const char *)"debug_log");
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
    }

    //PyPackTypes

    auto PyPackTypes::GetMethodObject(const char *method_name, const char *filename)
    {
        c2pool::python::Py::Initialize();

        PyObject *pObjct = nullptr;

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(FileSystem::getSubDir_c("/src/util"));
        PyList_Append(sys_path, folder_path);

        // Загрузка py файла
        auto pName = PyUnicode_FromString(filename);
        if (!pName)
        {
            return pObjct;
        }

        // Загрузить объект модуля
        auto pModule = PyImport_Import(pName);
        if (!pModule)
        {
            return pObjct;
        }

        // Словарь объектов содержащихся в модуле
        auto pDict = PyModule_GetDict(pModule);
        if (!pDict)
        {
            return pObjct;
        }

        pObjct = PyDict_GetItemString(pDict, method_name);
        if (!pObjct)
        {
            return pObjct;
        }

        // Проверка pObjct на годность.
        if (!PyCallable_Check(pObjct))
        {
            return pObjct;
        }

        return pObjct;
    }

    template <typename PyObjectType>
    char *PyPackTypes::GetCallFunctionResult(PyObjectType *pyObj)
    {
        char *ret = NULL;
        if (pyObj != NULL)
        {
            PyObject *pResultRepr = PyObject_Repr(pyObj);

            // Если полученную строку не скопировать, то после очистки ресурсов Python её не будет.
            // Для начала pResultRepr нужно привести к массиву байтов.
            ret = strdup(PyBytes_AS_STRING(PyUnicode_AsEncodedString(pResultRepr, "utf-8", "ERROR")));

            Py_XDECREF(pResultRepr);
            Py_XDECREF(pyObj);
        }
        ret += 1;                 //remove first element ['] in string
        ret[strlen(ret) - 1] = 0; //remove last element ['] in string

        // std::cout << "ret: " << ret << std::endl; //TODO: DEBUG_PYTHON
        return ret;
    }

    template <typename T>
    char *PyPackTypes::serialize(char *name_type, T &value)
    {
        auto methodObj = GetMethodObject("serialize");
        if (methodObj == nullptr)
        {
            return nullptr; //TODO обработка ситуации, если получено nullptr
        }
        UniValue msg(UniValue::VOBJ);
        msg.pushKV("name_type", name_type);
        UniValue msg_value(UniValue::VOBJ);
        msg_value = value;
        msg.pushKV("value", msg_value);

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", msg.write());

        auto result = GetCallFunctionResult(pVal);

        return c2pool::str::from_bytes_to_strChar(result);
    }

    char *PyPackTypes::serialize(c2pool::messages::message *msg)
    {
        auto methodObj = GetMethodObject("serialize_msg");
        if (methodObj == nullptr)
        {
            return nullptr; //TODO обработка ситуации, если получено nullptr
        }
        UniValue json_msg(UniValue::VOBJ);
        json_msg.pushKV("name_type", (msg->command);
        UniValue msg_value(UniValue::VOBJ);
        msg_value = msg;
        json_msg.pushKV("value", msg_value);

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", json_msg.write());

        auto result = GetCallFunctionResult(pVal);

        if (c2pool::str::compare_str(result, "ERROR", 5)){
            //ERROR
            return "";
        }

        return c2pool::str::from_bytes_to_strChar(result);
    }

    UniValue PyPackTypes::deserialize(char *name_type, char *value, int length)
    {
        UniValue result(UniValue::VOBJ);
        auto methodObj = GetMethodObject("deserialize");
        if (methodObj == nullptr)
        {
            result.setNull();
            return result; //TODO: проверка на Null на выходе функции.
        }
        auto pVal = PyObject_CallFunction(methodObj, (char *)"(sy#)", name_type, value, length);

        auto raw_result = GetCallFunctionResult(pVal);
        result.read(raw_result);

        return result;
    }

    UniValue PyPackTypes::deserialize(c2pool::messages::message *msg)
    {
        UniValue result(UniValue::VOBJ);
        auto methodObj = GetMethodObject("deserialize_msg");
        if (methodObj == nullptr)
        {
            result.setNull();
            return result; //TODO: проверка на Null на выходе функции.
        }
        auto pVal = PyObject_CallFunction(methodObj, (char *)"(sy#y#)", msg->command, msg->checksum, 4, msg->payload, msg->unpacked_length());

        auto raw_result = GetCallFunctionResult(pVal);
        result.read(raw_result);

        return result;
    }

    int PyPackTypes::payload_length(c2pool::messages::message *msg)
    {
        int result = 0;

        auto methodObj = GetMethodObject("payload_length");
        if (methodObj == nullptr)
        {
            return -1; //TODO обработка ситуации, если получено nullptr
        }

        UniValue json_msg(UniValue::VOBJ);
        json_msg.pushKV("name_type", msg->command);
        UniValue msg_value(UniValue::VOBJ);
        msg_value = msg;
        json_msg.pushKV("value", msg_value);

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", json_msg.write());
        auto raw_result = GetCallFunctionResult(pVal);

        stringstream ss;
        ss << raw_result;
        ss >> result;

        return result;
    }

    template <typename T>
    unsigned int PyPackTypes::packed_size(char *name_type, T &value)
    {
        unsigned int result = 0;

        auto methodObj = GetMethodObject("packed_size");
        if (methodObj == nullptr)
        {
            return -1; //TODO обработка ситуации, если получено nullptr
        }
        UniValue msg(UniValue::VOBJ);
        msg.pushKV("name_type", name_type);
        UniValue msg_value(UniValue::VOBJ);
        msg_value = value;
        msg.pushKV("value", msg_value);

        auto pVal = PyObject_CallFunction(pObjct, (char *)"(s)", msg.write());
        auto raw_result = GetCallFunctionResult(pVal);

        stringstream ss;
        ss << raw_result;
        ss >> result;

        return result;
    }

    unsigned int PyPackTypes::receive_length(char *length_data)
    {
        c2pool::python::Py::Initialize();

        unsigned int result = 0;

        auto methodObj = GetMethodObject("receive_length");
        if (methodObj == nullptr)
        {
            return -1; //TODO обработка ситуации, если получено nullptr
        }

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(y#)", length_data, 4);
        auto raw_result = GetCallFunctionResult(pVal);

        stringstream ss;
        ss << raw_result;
        ss >> result;

        return result;
    }

} // namespace c2pool::python

namespace c2pool::python::for_test
{

} // namespace c2pool::python::for_test