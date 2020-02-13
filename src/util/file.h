//
// Created by vasil on 14.02.2020.
//

#ifndef CPOOL_FILE_H
#define CPOOL_FILE_H

#include <iostream>
#include <fstream>
using namespace std;

class file {
private:
    fstream f;
public:
    file(string nameFile);

    string read(int length = -1);

    int write(string text);

    ~file();
};


#endif //CPOOL_FILE_H
