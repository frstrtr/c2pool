//
// Created by vasil on 14.02.2020.
//

#include "file.h"

file::file(string nameFile) {
    f.open(nameFile); //TODO: Open only while read/write?
}

string file::read(int length) {
    string res;
    if (f.is_open()) {
        while (getline (f,res))
        {
            //TODO: output in DEBUG_MODE
        }
        if (length != -1) {
            res = res.substr(0,length);
        }
        return res;
    }
    //TODO:raise
    return "";
}

int file::write(string text) {
    f << text;
}

file::~file() {
    f.close();
}
