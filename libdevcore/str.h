#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

namespace c2pool::dev{
    //STR
    //from [exclude]
    void substr(char *dest, char *source, int from, unsigned int length);

    char *from_bytes_to_strChar(char *source);

    //char и unsigned char будут так же верно сравниваться.
    //true - equaled
    bool compare_str(const void *first_str, const void *second_str, unsigned int length);

    void copy_to_const_c_str(const std::vector<unsigned char> &src, const unsigned char* &dest);

    template<typename T>
    std::string vector_to_string(std::vector<T> arr)
    {
        std::stringstream ss;
        for (auto v : arr)
        {
            ss << v << " ";
        }
        std::string result;
        std::getline(ss, result);

        return result;
    }

    template<typename T>
    std::vector<T> string_to_vector(std::string s)
    {
        std::stringstream ss;
        ss << s;

        std::vector<T> result;
        T value;
        while (ss >> value)
        {
            result.push_back(value);
        }

        return result;
    }
}