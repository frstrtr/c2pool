#include <iostream>
#include <sstream>
#include <vector>
using namespace std;

class A;
class B;
class Msg;

class Protocol {
public:
    void handle_A(A* a);

    void handle_B(B* b);

    Msg* HandleFromStr(stringstream& ss);
};

class Msg {
public:
    virtual void unpack(stringstream& ss) = 0;

    virtual void handle(Protocol *proto) = 0;

};

class A : public Msg {
public:
    float a1;
    string a2;

    void unpack(stringstream& ss){
        ss >> a1 >> a2;
    }

    void handle(Protocol* proto){
        proto->handle_A(this);
    }

};

class B : public Msg{
public:

    int b1;

    vector<string> b2;

    void unpack(stringstream& ss){
        ss >> b1;
        string buff;
        while (ss >> buff){
            b2.push_back(buff);
        }
    }

    void handle(Protocol* proto){
        proto->handle_B(this);
    }

};

void Protocol::handle_B(B *b) {
    cout << b->b1 << " ";
    for (auto item : b->b2){
        cout << item << " ";
    }
    cout << endl;
}

void Protocol::handle_A(A *a) {
    cout << a->a1 << " " << a->a2 << endl;
}

Msg *Protocol::HandleFromStr(stringstream &ss) {
    string type;
    ss >> type;
    Msg* res;
    if (type == "A") {
        res = new A();
    }
    if (type == "B") {
        res = new B();
    }
    res->unpack(ss);
    res->handle(this);
    return res;
}


int main(){

    stringstream ss1;
    ss1 << "A" << " " << 0.123 << " " << "STR";

    stringstream ss2;
    ss2 << "B" << " " << 1337 << " " <<  "Str1" << " " << "Str2" << " " << "Str3" << " " << "Str4";


    Protocol* proto = new Protocol();

    proto->HandleFromStr(ss1);
    proto->HandleFromStr(ss2);
    return 0;
}