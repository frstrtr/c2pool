//
// Created by vasil on 09.02.2020.
//

#ifndef CPOOL_PYSTRUCT_H
#define CPOOL_PYSTRUCT_H

#include <string>
#include "Python.h"


class pystruct{
public:

    void read();

    void unpack(std::string types, std::string vars);

    std::string pack(std::string, std::string vars);
};


#endif //CPOOL_PYSTRUCT_H
