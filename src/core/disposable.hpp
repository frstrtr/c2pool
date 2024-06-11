#pragma once

#include <memory>
#include <vector>

class Disposables;
class IDisposable
{
public:
    virtual void attach(Disposables& value) = 0;
    virtual void dispose() = 0;
};

class Disposables
{
public:
    std::vector<std::unique_ptr<IDisposable>> dis;

    void attach(std::unique_ptr<IDisposable> value)
    {
        dis.push_back(std::move(value));
    };

    void dispose()
    {
        for (auto& v : dis)
        {
            v->dispose();
        }
        dis.clear();
    }
};

class BasicDisposable : public IDisposable
{
    std::function<void()> _dispose;

public:
    BasicDisposable(std::function<void()>&& dispose_func)
        : _dispose(std::move(dispose_func))
    {

    }

    void attach(Disposables& dis) override
    {
        dis.attach(std::make_unique<BasicDisposable>(*this));
    }

    void dispose() override
    {
        _dispose();
    }
};

class EventDisposable : public IDisposable
{
    int _id;
    std::function<void(int)> _dispose;

public:
    EventDisposable(int id, std::function<void(int)>&& dispose_func) 
        : _id(id), _dispose(std::move(dispose_func))
    {
    }

    operator int() const
    {
        return _id;
    }

    void attach(Disposables& dis) override
    {
        dis.attach(std::make_unique<EventDisposable>(*this));
    }

    void dispose() override
    {
        _dispose(_id);
    }
};