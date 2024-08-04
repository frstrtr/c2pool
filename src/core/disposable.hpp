#pragma once

#include <memory>
#include <vector>
#include <functional>

class Disposables;
class IDisposable
{
public:
    virtual void attach(Disposables& value) = 0;
    virtual void dispose() = 0;
};

class Disposables
{
    std::vector<std::shared_ptr<IDisposable>> m_disposables;

public:
    void attach(std::shared_ptr<IDisposable> value)
    {
        if (value)
            m_disposables.push_back(std::move(value));
    };

    void dispose()
    {
        for (auto& v : m_disposables)
        {
            v->dispose();
        }
        m_disposables.clear();
    }
};

// class BasicDisposable : public IDisposable
// {
//     std::function<void()> m_dispose;

// public:
//     BasicDisposable(std::function<void()>&& dispose_func)
//         : m_dispose(std::move(dispose_func))
//     {

//     }

//     void attach(Disposables& dis) override
//     {
//         dis.attach(std::make_unique<BasicDisposable>(*this));
//     }

//     void dispose() override
//     {
//         _dispose();
//     }
// };