#include <iostream>
#include <memory>

class NodeImpl
{
protected:
    int m_num;
    int m_num2;

public:
    int m_num3;

public:
    NodeImpl() {}
    NodeImpl(int n, int n2) : m_num(n), m_num2(n2) { std::cout << "hi!" << std::endl; }
};

template <typename Node>
class NodeProtocol : public virtual Node
{
    virtual void handle_message() = 0;
};

class Legacy : public NodeProtocol<NodeImpl>
{
public:
    // int l_v;
    // Legacy(int v) : l_v(v) { }

    void handle_message() override { handle_version(); std::cout << m_num2 << std::endl; }

private:
    void handle_version()
    {
        std::cout << "handle legacy version, num = " << m_num << std::endl;
    }
};

class Actual : protected NodeProtocol<NodeImpl>
{
public:
    // int a_v;
    // Actual(int v) : a_v(v) { }

    void handle_message() override { handle_version(); }

private:
    void handle_version()
    {
        std::cout << "handle actual version, num = " << m_num << std::endl;
    }
};

template <typename Base, typename ILegacy, typename IActual>
class BaseNode : public ILegacy, public IActual
{
public:
    // static_assert(std::is_base_of_v<Base, ILegacy> && std::is_base_of_v<Base, IActual>);
    static_assert(std::is_base_of_v<NodeProtocol<Base>, ILegacy> && std::is_base_of_v<NodeProtocol<Base>, IActual>);

    using base = Base;

    void handle(bool actual)
    {
        if (actual)
        {
            IActual* n = this;
            n->handle_message();
        } else
        {
            ILegacy* n = this;
            n->handle_message();
        }    
    }

    template <typename... Args>
    BaseNode(Args... args) : Base(args...) { }
};

using Node = BaseNode<::NodeImpl, Legacy, Actual>;

int main(int argc, char *argv[])
{
    Node* node = new Node(1010, 10200);
    node->handle(false);
    std::cout << node->m_num3 << std::endl;
    
}