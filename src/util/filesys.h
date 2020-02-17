//
// Created by vasil on 14.02.2020.
//

#ifndef CPOOL_FILESYS_H
#define CPOOL_FILESYS_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
using namespace std;

class BaseFile {
private:

public:
    virtual string read(int length = -1) = 0;

    char* read_c(int length = -1);;

    virtual string getvalue() = 0;

    char* getvalue_c();

    virtual int write(string text) = 0;

    virtual int write(int num) = 0;
};

class File : BaseFile{
private:
    fstream f;
public:
    File(string nameFile = "", string buffer = "");

    ~File();

    string read(int length = -1) override;

    string getvalue() override;

    int write(string text) override;

    int write(int num) override;
};

class MemoryFile : BaseFile{
private:
    stringstream f;
public:

    MemoryFile(string buffer = "");

    ~MemoryFile();

    string read(int length = -1) override;

    string getvalue() override;

    int write(string text) override;

    int write(int num) override;
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
