#include "pack.h"
#include <typeinfo>
#include <iostream>
#include <cstring>
using namespace std;

bool operator==(const Type& A, const Type& B){
    if (typeid(A).name() != typeid(B).name()) return false;
    return (memcmp(&A, &B, sizeof(A)) == 0);
}

bool operator!=(const Type& A, const Type& B) {
    return (!(A == B));
}

auto ListType::read(auto file) {
    auto length = _inner_size.read(file);
    length *= mul;
    //TODO: generate res from type.read(file)

}


