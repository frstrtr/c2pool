#pragma once

namespace c2pool::dev{
    //STR
    //from [exclude]
    void substr(char *dest, char *source, int from, unsigned int length);

    char *from_bytes_to_strChar(char *source);

    //char и unsigned char будут так же верно сравниваться.
    //true - equaled
    bool compare_str(const void *first_str, const void *second_str, unsigned int length);
}