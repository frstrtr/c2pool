//
// Created by vasil on 09.02.2020.
//

#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include "Python.h"


class pystruct{
public:
    void unpack(std::string types, std::string vars);

    char* pack(char* types, char* vars);
};


#endif //CPOOL_PYSTRUCT_H
