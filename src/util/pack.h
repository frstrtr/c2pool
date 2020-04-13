#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

#include <iostream>
#include <typeinfo>
#include <sstream>
#include <cmath>
#include <pystruct.h>
#include <filesys.h>
#include <vector>
//todo: remove useless include

enum PackTypes{
    IntType,
    BitcoinDataAddressType, //value = [services; address; port]
    VarStrType,
    PossiblyNoneType,
    ComposedType
};

class ComposedType{
    stringstream fields;

private:
    void Space(){ // проверка и разделение переменных в потоке.
        if (fields.rdbuf()->in_avail() != 0){ //проверка на то, что в fields уже есть какие-то данные.
            fields << ";";
        }
    }

public:
    ComposedType(){
        fields.clear();
    }

    template <typename T>
    ComposedType& add(const T& value){
        Space();
        fields << value;
        return *this;
    }

    template <typename T>
    ComposedType& add(const vector<T> value){
        Space();
        fields << "[";
        for (int i = 0; i < value.size(); i++){
            if (i != 0) {
                fields << ","; //элементы массива разделяются запятой!// s
            }
            fields << value[i];
        }
        fields << "]";
        return *this;
    }

    string read(){//TODO: this is real read, remove other
        string buff;
        fields >> buff;
        string res = buff;
        return res;
    }
};


#endif //CPOOL_PACK_H
