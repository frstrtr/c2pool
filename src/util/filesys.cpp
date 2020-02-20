#include "filesys.h"
#include <cstring>
#include <string>

char *BaseFile::read_c(int length) {
    string buff = read_str(length);
    char* res = new char[buff.length() + 1];
    std::strcpy(res, buff.c_str());
    return res;
}

char *BaseFile::getvalue_c() {
    string buff = getvalue();
    char* res = new char[buff.length() + 1];
    std::strcpy(res, buff.c_str());
    return res;
}

File::File(string nameFile, string buffer) {
    f.open(nameFile); //TODO: Open only while read/write?
    if (buffer != ""){
        f << buffer;
    }
}

File::~File() {
    f.close();
}

string File::getvalue() {
    string res;
    string buff;
    while (f >> buff){
        res += buff;
    }
    f.seekg(0, ios::beg); //return stream to begin
    return res;
}

string File::read_str(int length) {
    string res;
    string buff;
    if (f.is_open()) {
        while (getline (f,buff))
        {
            res += buff;
            //TODO: output in DEBUG_MODE
        }
        if (length != -1) {
            res = res.substr(0,length);
        }
        f.seekg(0, ios::beg); //return stream to begin
        return res;
    }
    //TODO:raise
    return "";
}

stringstream File::read(int length) {
    stringstream res;
    res << f.rdbuf();
    f.seekg(0, ios::beg); //return stream to begin
    return res;
}

int File::write(string text) {
    f << text;
    return text.length();
}

int File::write(int num) {
    stringstream buff;
    buff << num;
    f << buff.str();
    return buff.str().length();
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

MemoryFile::~MemoryFile() {

}

string MemoryFile::read_str(int length) {
    string res;
    string buff;
    while (getline(f, buff)) {
        res += buff;
        //TODO: output in DEBUG_MODE
    }
    if (length != -1) {
        res = res.substr(0, length);
    }
    f.seekg(0, ios::beg); //return stream to begin
    return res;

    //TODO:raise
    return "";
}

stringstream MemoryFile::read(int length) {
    stringstream res;
    res << f.rdbuf();
    f.seekg(0, ios::beg); //return stream to begin
    return res;
}

string MemoryFile::getvalue() {
    return f.str();
}

int MemoryFile::write(string text) {
    f << text;
    return text.length();
}

int MemoryFile::write(int num) {
    stringstream buff;
    buff << num;
    f << buff.str();
    return buff.str().length();
}

MemoryFile::MemoryFile(string buffer) {
    if (buffer != "") {
        f = stringstream();
        f << buffer;
    }
}

