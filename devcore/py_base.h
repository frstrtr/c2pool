#pragma once
#include <Python.h>
#include <iostream>
#include "filesystem.h"

namespace c2pool::python
{
    class Py
    {
    public:
        static bool _ready;
        static void Initialize();

        static void Finalize();
    };
} // namespace c2pool::python

namespace c2pool::python
{
    class PythonBase
    {
    protected:
        //ex. filepath: "/src/util"
        static auto GetMethodObject(const char *method_name, const char* filepath, const char *filename)
        {
            Py::Initialize();

            PyObject *pObjct = nullptr;

            // Загрузка модуля sys
            auto sys = PyImport_ImportModule("sys");
            auto sys_path = PyObject_GetAttrString(sys, "path");
            // Путь до наших исходников Python
            auto folder_path = PyUnicode_FromString(c2pool::filesystem::getSubDir_c(filepath));
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
        static char *GetCallFunctionResult(PyObjectType *pyObj)
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
    };
} // namespace c2pool::python