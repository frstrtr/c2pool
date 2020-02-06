#ifndef CPOOL_PACK_H
#define CPOOL_PACK_H

class Type{
public:
    int a;
    int b;
    Type(){
        a = 0;
        b = 0;
    }
    Type(int A, int B);

    int getA() const ;
    int getB() const ;

    bool operator==(const Type B) const {
        return ((getA() == B.getA()) && (getB() == B.getB()));
    }
};

#endif //CPOOL_PACK_H
