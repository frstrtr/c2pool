#include "filesys.h"
#include <cstring>
#include <string>

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
    string buff;
    while (f >> buff){
        //TODO: output in DEBUG_MODE
    }
    return buff;
}

string File::read(int length) {
    string res;
    if (f.is_open()) {
        while (getline (f,res))
        {
            //? res += buff;
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

string MemoryFile::read(int length) { //TODO: rework
    string res;

    while (getline(f, res)) {
        //TODO: output in DEBUG_MODE
    }
    if (length != -1) {
        res = res.substr(0, length);
    }
    return res;

    //TODO:raise
    return "";
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
