#include <iostream>

struct Protocol
{
    
};

template <typename HANDSHAKE>
struct BasePoolNode
{
    Protocol* proto;

    Node(int v) 
    {
        
    }
};

struct Protocol1 : Protocol
{

};

struct Protocol2 : Protocol
{

};

template <typename T1, typename T2>
struct Handshake
{
    
};

struct Node : BasePoolNode<Handshake<Protocol1, Protocol2>>
{

};

int main()
{
    Node node;
}