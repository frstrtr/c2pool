#include "pack.h"
#include <iostream>
using namespace std;

Type::Type(int A, int B) {
    a = A;
    b = B;
}

int Type::getB() const {
    return b;
}

int Type::getA() const {
    return a;
}

