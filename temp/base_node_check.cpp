#include <iostream>
#include <memory>
// struct ILegacy
// {
//     virtual void handle_version() = 0;
// };

// struct IActual
// {
//     virtual void handle_version() = 0;
// };

struct NodeImpl
{
    int m_num;
    Node() {}
    Node(int n) : m_num(n) { std::cout << "hi!" << std::endl; }
};

template <typename Node>
struct NodeProtocol : virtual 
{

}

struct Legacy : virtual NodeImpl
{
    // int l_v;
    // Legacy(int v) : l_v(v) { }

    void handle_version()
    {
        std::cout << "handle legacy version, num = " << m_num << std::endl;
    }
};

struct Actual : virtual NodeImpl
{
    // int a_v;
    // Actual(int v) : a_v(v) { }

    void handle_version()
    {
        std::cout << "handle actual version, num = " << m_num << std::endl;
    }
};

template <typename Base, typename ILegacy, typename IActual>
struct BaseNode : ILegacy, IActual
{
    static_assert(std::is_base_of_v<Base, ILegacy> && std::is_base_of_v<Base, IActual>);
    using base = Base;

    void handle(bool actual)
    {
        if (actual)
        {
            IActual* n = this;
            n->handle_version();
        } else
        {
            ILegacy* n = this;
            n->handle_version();
            std::make_unique
        }    
    }

    BaseNode(int n) : Base(n) { std::cout << "1 " <<  n << std::endl;}
};

namespace pool
{
    // struct Node : BaseNode<::Node, Legacy, Actual>
    // {
    // public:
    //     Node(int n) : base(n) { std::cout << "2 " <<  n << std::endl; }
    // };
    using Node = BaseNode<::Node, Legacy, Actual>;
} // namespace pool

int main(int argc, char *argv[])
{
    pool::Node* node = new pool::Node(100);
    node->handle(false);
}