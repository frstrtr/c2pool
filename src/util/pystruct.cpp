#include "pystruct.h"
#include "Python.h"
#include "other.h"
#include "messages.h"
#include "univalue.h"
#include <tuple>
#include <iostream>
#include <sstream>
#include <py_base.h>

using namespace std;

namespace c2pool::python
{

    void other::debug_log(char *data, unsigned int len)
    {
        c2pool::python::Py::Initialize();

        // Загрузка модуля sys
        auto sys = PyImport_ImportModule("sys");
        auto sys_path = PyObject_GetAttrString(sys, "path");
        // Путь до наших исходников Python
        auto folder_path = PyUnicode_FromString(c2pool::filesystem::getSubDir_c("/src/util"));
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
        json_msg.pushKV("name_type", msg->command);
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

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", msg.write());
        auto raw_result = GetCallFunctionResult(pVal);

        stringstream ss;
        ss << raw_result;
        ss >> result;

        return result;
    }

    unsigned int PyPackTypes::receive_length(char *length_data)
    {
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