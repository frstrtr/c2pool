#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

#include <iostream>
#include <typeinfo>
#include <sstream>
#include <cmath>
#include <pystruct.h>
#include <filesys.h>
//TODO: remove all auto;
//TODO: add 3 types pack from data.py

template <typename T>
class Type{
public:
    Type(){

    }

    friend bool operator==(const Type& A, const Type& B);
    friend bool operator!=(const Type& A, const Type& B);

    virtual void write(std::stringstream file, T item);
    virtual T read(std::stringstream file);


};

class VarIntType:Type<int>{

    int read(file f) {
        char data = f.read(1);
        int first = (int) data;

        if (first < 0xfd) {
            return first;
        }

        std::string desc;
        int length;
        int minimum;

        switch (first) {
            case 0xfd:
                desc = "<H";
                length = 2;
                minimum = 0xfd;
                break;
            case 0xfe:
                desc = "<I";
                length = 4;
                minimum = pow(2,16);
                break;
            case 0xff:
                desc = "<Q";
                length = 8;
                minimum = pow(2,32);
                break;
            default:
                return 0;
                //raise
        }

        char *data2 = f.read(length);

        auto res = pystruct.unpack(desc, data2); //TODO:???

        if (res < minimum){
            //raise AssertionError('VarInt not canonically packed')
        }

        return res;
    }

    //TODO: NEED RETURN???
    void write(file f, auto item){
        auto pack_value;
        if (item < 0xfd)
            pack_value = pystruct.pack('<B', item);
        else if (item <= 0xffff)
            pack_value = pystruct.pack('<BH', 0xfd, item);
        else if (item <= 0xffffffff)
            pack_value = pystruct.pack('<BI', 0xfe, item);
        else if (item <= 0xffffffffffffffff)
            pack_value = pystruct.pack('<BI', 0xff, item);
        else
            //TODO:RAISE
            return;

        f.write(pack_value); //TODO
    }

};

class VarStrType:Type{
    VarIntType _inner_size;
public:
    auto read(file f){
        auto length = _inner_size.read(file);
        return f.read(length);
    }

    void write(file f, auto item)  override {
        _inner_size.write(file, length(item));
        std::stringstream ss;
        ss << file;

        f.write(item);
    }
};

class EnumType:Type{
    auto inner;
    auto pack_to_unpack;
    auto unpack_to_pack;
public:
    EnumType(auto _inner, auto _pack_to_unpack){
        inner = _inner;
        pack_to_unpack = _pack_to_unpack;
        //TODO: UNPACK!!!
    }

    auto read(auto file){
        auto data = inner.read(file);
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        return pack_to_unpack[data];
    }

    void write(auto file, auto item){
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        inner.write(file, unpack_to_pack[item]);
    }
};

class ListType:Type{
    VarIntType _inner_size;

    auto type;
    auto mul;

public:

    ListType(auto _type, auto _mul = 1){
        type = _type;
        mul = _mul;
    }

    auto read(auto file);

    void write(auto file, auto item){
        //TODO: assert len(item) % self.mul == 0

        _inner_size.write(file, length(item)/mul)

        //TODO: foreach(subitem in item){type.write(file, subitem)}
    }
};

class StructType:Type{
    auto desc;
    auto length;
public:
    StructType(auto _desc){
        desc = _desc;
        //TODO: length = struct.calcsize(desc);
    }

    auto read(file f){
        auto data = f.read(length);
        //TODO: return pystruct.unpack(desc, data)[0]
    }

    void write(file f, auto item){
         f.write(pystruct.pack(self.desc, item)); //TODO
    }
};

class IntType:Type{
    //TODO: CREATE
};

class IPV6AddressType:Type{
public:
    auto read(auto file){
        //TODO
    }

    void write(auto file, auto item){
        //TODO
    }
};

class ComposedType:Type{
    list<auto> fields;
    set<auto> fields_names;
    auto record_type;

public:
    ComposedType(auto _fields){
        fields = _fields; //TODO: list(fields)
        //TODO: field_names initialize
        //TODO: recorc_type = get_record(...)
    }

    auto read(auto file){
        auto item = record_type();
        //TODO: foreach key, type in fileds
        return item;
    }

    void write(auto file, auto item){
        //TODO: assert set(item.keys()) >= self.field_names
        //TODO: foreach
    }
};

class PossiblyNoneType:Type {
    auto none_value;
    auto inner;
public:
    PossiblyNoneType(auto _none_value, auto _inner) {
        none_value = _none_value;
        inner = _inner;
    }

    auto read(auto file) {
        auto value = inner.read(file);
        if (value == none_value) {
            return nullptr;
        } else {
            return value;
        }
    }

    void write(auto file, auto item) {
        if (item == none_value) {
            //TODO: raise ValueError('none_value used')
        }
        inner.write(file, item == nullptr ? none_value : item);
    }
};

class FixedStrType:Type{
    auto length;

    FixedStrType(auto _length){
        length = _length;
    }

    auto read(file f){
        return f.read(length);
    }

    void write(file f, auto item){
        //TODO: if ... raise
        f.write(item);
    }
};




#endif //CPOOL_PACK_H
