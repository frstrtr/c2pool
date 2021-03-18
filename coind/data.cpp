#include "data.h"
#include <btclibs/uint256.h>
#include <sstream>

namespace coind::data::python
{
    const char *PyBitcoindData::filepath = "/src/util";

    uint256 PyBitcoindData::target_to_average_attempts(uint256 target)
    {
        uint256 result;
        result.SetNull();

        auto methodObj = GetMethodObject("target_to_average_attempts", filepath, "data");
        if (methodObj == nullptr)
        {
            return result; //TODO обработка ситуации, если получено Null
        }

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", target.GetHex());
        auto raw_result = GetCallFunctionResult(pVal);

        result.SetHex(raw_result);
        return result;
    }

    uint256 PyBitcoindData::average_attempts_to_target(uint256 average_attempts)
    {
        uint256 result;
        result.SetNull();

        auto methodObj = GetMethodObject("average_attempts_to_target", filepath, "data");
        if (methodObj == nullptr)
        {
            return result; //TODO обработка ситуации, если получено Null
        }

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", average_attempts.GetHex());
        auto raw_result = GetCallFunctionResult(pVal);

        result.SetHex(raw_result);
        return result;
    }

    double PyBitcoindData::target_to_difficulty(uint256 target)
    {
        double result;
        auto methodObj = GetMethodObject("target_to_difficulty", filepath, "data");
        if (methodObj == nullptr)
        {
            return result; //TODO обработка ситуации, если получено Null
        }

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", target.GetHex());
        auto raw_result = GetCallFunctionResult(pVal);

        std::stringstream ss;
        ss << raw_result;
        ss >> result;
        return result;
    }

    uint256 PyBitcoindData::difficulty_to_target(uint256 difficulty)
    {
        uint256 result;
        result.SetNull();

        auto methodObj = GetMethodObject("difficulty_to_target", filepath, "data");
        if (methodObj == nullptr)
        {
            return result; //TODO обработка ситуации, если получено Null
        }

        auto pVal = PyObject_CallFunction(methodObj, (char *)"(s)", difficulty.GetHex());
        auto raw_result = GetCallFunctionResult(pVal);

        result.SetHex(raw_result);
        return result;
    }
}; // namespace coind::data::python
