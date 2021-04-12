#include "pystruct.h"
#include <Python.h>
//#include "messages.h"
#include "univalue.h"
#include <tuple>
#include <iostream>
#include <sstream>
#include <devcore/py_base.h>
#include <devcore/str.h>
#include "messages.h"
#include <devcore/logger.h>

using namespace std;

namespace coind::p2p::python
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

    //PyPackCoindTypes

    const char *PyPackCoindTypes::filepath = "/coind/p2p";

    char *PyPackCoindTypes::encode(UniValue json_msg)
    {
        auto methodObj = GetMethodObject("serialize_msg", filepath, "packtypes");
        if (methodObj == nullptr)
        {
            LOG_WARNING << "serialize_msg not founded";
            return nullptr; //TODO обработка ситуации, если получено nullptr
        }
        //auto msg_json_str = "{\"name_type\":\"version\",\"value\":{\"version\":3301,\"services\":0,\"addr_to\":{\"services\":3,\"address\":\"4.5.6.7\",\"port\":8},\"addr_from\":{\"services\":9,\"address\":\"10.11.12.13\",\"port\":14},\"nonce\":6535423,\"sub_version\":\"16\",\"mode\":18,\"best_share_hash\":\"0000000000000000000000000000000000000000000000000000000000000123\"}}";//json_msg.write().c_str();
        string str = json_msg.write();
        const char* msg_json_str = str.c_str();
        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", msg_json_str);
        auto result = GetCallFunctionResult(pVal);
        if (c2pool::dev::compare_str(result, "ERROR", 5))
        {
            LOG_TRACE << result;
            //ERROR
            return "";
        }
        LOG_TRACE << result;
        return c2pool::dev::from_bytes_to_strChar(result);
    }

    UniValue PyPackCoindTypes::decode(shared_ptr<coind::p2p::messages::coind_converter> converter)
    {
        UniValue result(UniValue::VOBJ);
        auto methodObj = GetMethodObject("deserialize_msg", filepath, "packtypes");
        if (methodObj == nullptr)
        {
            result.setNull();
            return result; //TODO: проверка на Null на выходе функции.
        }
        auto pVal = PyObject_CallFunction(methodObj, (char *)"(sy#y#)", converter->command, converter->checksum, 4, converter->payload, converter->get_unpacked_len());

        auto raw_result = GetCallFunctionResult(pVal);
        // LOG_TRACE << "raw_result: " << raw_result;
        result.read(raw_result);
        if(result.exists("error_text")){
            LOG_TRACE << "error text exists";
            return generate_error_json(result);
        }
        //result.read("{"name_type": 0, "value": {"addr_from": {"address": "10.10.10.10", "port": 5024, "services": 0}, "addr_to": {"address": "10.10.10.1", "port": 6736, "services": 0}, "best_share_hash": \"40867716461082619671918594213535070784980289528248303516486975277206795153061\", \"mode\": 1, \"nonce\": 2713422397866666268, \"services\": 0, \"sub_version\": b\"fa6c7cd-dirty-c2pool\", \"version\": 3301}}")
        // LOG_TRACE << "result :" << result.write();
        return result;
    }

    unsigned int PyPackCoindTypes::receive_length(char *length_data)
    {
        unsigned int result = 0;

        //auto methodObj = GetMethodObject("receive_length", "/home/sl33n/c2pool/util", "packtypes");
        auto methodObj = GetMethodObject("receive_length", filepath, "packtypes");
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
    
    UniValue PyPackCoindTypes::generate_error_json(UniValue json){
        auto result = UniValue(UniValue::VOBJ);
        result.pushKV("name_type", 9999);
        result.pushKV("value", json);
        return result;
    }

} // namespace c2pool::python

namespace coind::p2p::python::for_test
{

} // namespace c2pool::python::for_test