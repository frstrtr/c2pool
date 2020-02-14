//
// Created by vasil on 14.02.2020.
//

#include "filesys.h"
#include <cstring>
#include <string>

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

string FileSystem::getProjectDir() {
    return RESOURCES_DIR;
}

const char *FileSystem::getProjectDir_c() {
    return RESOURCES_DIR;
}

string FileSystem::getSubDir(string path) {
    return getProjectDir() + path;
}

const char *FileSystem::getSubDir_c(string path) {
    string str = FileSystem::getSubDir(path);
    char* cstr = new char [str.length()+1];
    std::strcpy (cstr, str.c_str());
    return cstr;
}
