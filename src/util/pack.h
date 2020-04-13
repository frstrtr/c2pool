#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

#include <iostream>
#include <typeinfo>
#include <sstream>
#include <cmath>
#include <pystruct.h>
#include <filesys.h>
#include <vector>
//TODO: remove all auto;
//TODO: add 3 types pack from data.py

template <typename T>
class Type{
public:
    Type(){

    }

    friend bool operator==(const Type& A, const Type& B);
    friend bool operator!=(const Type& A, const Type& B);

    virtual void write(MemoryFile &f, T item) = 0;
    virtual T read(MemoryFile &f) = 0;

    T _unpack(BaseFile data, bool ignore_trailing = false){
        T obj = read(data);
        if (!ignore_trailing && remaining(data)){
            //TODO: raise LateEnd();
        }
        return obj;
    }

    char* _pack(T obj){
        auto f = MemoryFile();
        write(f, obj);
        return f.getvalue_c();
    }

    T unpack(auto data, bool ignore_trailing = false){
        //TODO: ???
        //if not type(data) == StringIO.InputType:
        //  data = StringIO.StringIO(data)
        auto obj = _unpack(data, ignore_trailing);
        //TODO: DEBUG!

        return obj;
    }

    char* pack(T obj){
        return _pack(obj);
    }

    int packed_size(T obj){
        int _packed_size = pack(obj).length();
        return _packed_size;
    }

};

class VarIntType: public Type<int> {
public:
    int read(MemoryFile &f) {
        char data = f.read_str()[0];
        int first = (int) data;

        if (first < 0xfd) {
            return first;
        }

        char *desc;
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
                minimum = pow(2, 16);
                break;
            case 0xff:
                desc = "<Q";
                length = 8;
                minimum = pow(2, 32);
                break;
            default:
                return 0;
                //raise
        }

        char *data2 = f.read_c(length);

        int res;
        pystruct::unpack(desc, data2) >> res;
        if (res < minimum) {
            //raise AssertionError('VarInt not canonically packed')
        }
        return res;
    }

    //TODO: NEED RETURN???
    void write(MemoryFile &f, int item) {
        char *pack_value = "";
        stringstream ss;
        if (item < 0xfd) {
            ss << item;
            pack_value = pystruct::pack("<B", ss);
        } else if (item <= 0xffff) {
            ss << 0xfd << ", " << item;
            pack_value = pystruct::pack("<BH", ss);
        } else if (item <= 0xffffffff) {
            ss << 0xfe << ", " << item;
            pack_value = pystruct::pack("<BI", ss);
        } else if (item <= 0xffffffffffffffff) {
            ss << 0xff << ", " << item;
            pack_value = pystruct::pack("<BI", ss);
        } else
            //TODO:RAISE
            return;
        f.write(pack_value); //TODO
    }

};

class VarStrType: public Type<string>{
    VarIntType _inner_size;
public:
    string read(MemoryFile& f){
        auto length = _inner_size.read(f);
        string res;
        f.read(length) >> res;
        return res;
    }

    void write(MemoryFile &f, string item) override {
        _inner_size.write(f, item.length());
        f.write(item);
    }
};

//TODO:? remake
template <typename _type>
class EnumType: public Type<_type>{
    auto inner;
    auto pack_to_unpack;
    auto unpack_to_pack;
public:
    EnumType(auto _inner, auto _pack_to_unpack){
        inner = _inner;
        pack_to_unpack = _pack_to_unpack;
        //TODO: UNPACK!!!
    }

    _type read(MemoryFile& f){
        auto data = inner.read(f);
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        return pack_to_unpack[data];
    }

    void write(MemoryFile &f, string item){
        //TODO: CHECK DATA IN PACK_TO_UNPACK!
        inner.write(f, unpack_to_pack[item]);
    }
};

//TODO: call methods from type
template <typename type>
class ListType: public Type <vector<type>>{
    VarIntType _inner_size;
    int mul = 1;

public:

    ListType(int _mul = 1){
        mul = _mul;
    }

    vector<type> read(MemoryFile& f){
        int length = _inner_size.read(f);
        length *= mul;
        type buff[] = new type[length];
        for (int i = 0; i < length; i++){
            //TODO: self.type.read(file)
        }
        vector<type> res = vector<type>(buff);
    }

    void write(MemoryFile &f, string item){
        //TODO: assert len(item) % self.mul == 0

        _inner_size.write(f, item.length()/mul);

        //TODO: foreach(subitem in item){type.write(file, subitem)}
    }
};

template <typename type>
class StructType: public Type<type>{
    auto desc; //TODO:?
    int length;
public:
    StructType(auto _desc){
        desc = _desc;
        //TODO: length = struct.calcsize(desc);
    }

    auto read(MemoryFile& f){
        auto data = f.read(length);
        string res; //TODO: string?
        res >> pystruct::unpack(desc, data)[0];
        return res;
    }

    void write(MemoryFile &f, string item){
         f.write(pystruct::pack(desc, item));
    }
};


/*class IntType: public Type{
    //TODO: CREATE with memoize
};*/

class IPV6AddressType: public Type{
public:
    auto read(auto file){
        //TODO
    }

    void write(auto file, auto item){
        //TODO
    }
};

enum PackTypes{
    IntType,
    BitcoinDataAddressType, //value = [services; address; port]
    VarStrType,
    PossiblyNoneType,
    ComposedType
};

class ComposedType: public Type<string>{
    //list<auto> fields;
    //set<auto> fields_names;
    //auto record_type;
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

    ComposedType(auto _fields){
        fields = _fields; //TODO: list(fields)
        //TODO: field_names initialize
        //TODO: recorc_type = get_record(...)
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
        string res = "|" + buff + "|";
        return res;
    }
    //___________________________________
    template <typename T>
    ComposedType& add(string field_name, PackTypes packType, const T& value){
        fields << "(" << field_name << "," << packType << "," << value << ")";
        return *this;
    }

    template <typename T>
    ComposedType& add(string field_name, PackTypes packType, string PackAttr, const T& value){
        fields << "(" << field_name << "," << packType << ",[" << PackAttr << "]," << value << ")";
        return *this;
    }

    ComposedType& add(string field_name, ComposedType& value){
        string _v;
        value.fields >> _v;
        fields << "(" << field_name << "," << PackTypes::ComposedType << "," << _v << ")";
        return *this;
    }

    string read(MemoryFile &f){
        //auto item = record_type();
        //TODO: foreach key, type in fileds
        return item;
    }

    void write(MemoryFile &f, string item){
        //TODO: assert set(item.keys()) >= self.field_names
        //TODO: foreach
    }
};

class PossiblyNoneType: public Type {
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

class FixedStrType: public Type{
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
