//
// Created by vasil on 14.02.2020.
//

#ifndef CPOOL_FILESYS_H
#define CPOOL_FILESYS_H

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

class FileSystem{
private:
    FileSystem(){

    }
public:
    ///full path to main project folder
    static string getProjectDir();

    static const char* getProjectDir_c();

    ///full subdirection path.
    static string getSubDir(string path);

    static const char* getSubDir_c(string path);
};

#endif //CPOOL_FILESYS_H
