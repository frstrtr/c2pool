#pragma once
#include <future>
#include <atomic>
#include <tuple>

#include "network_tree_node.h"

class NetworkTreeNode;

enum NetworkState
{
    offline,
    processing,
    connected
};

enum ReconnectTaskState
{
    cancel,
    ready
};

class ReconnectTask
{
    std::promise<ReconnectTaskState> state;
    std::atomic_bool alive;
public:
    ReconnectTask() : alive(true)
    {
    }

    void ready()
    {
        if (alive)
        {
            state.set_value(ReconnectTaskState::ready);
            alive = false;
        }
    }

    void cancel()
    {
        if (alive)
        {
            state.set_value(ReconnectTaskState::cancel);
            alive = false;
        }
    }

    auto get_future()
    {
        return state.get_future();
    }
};

class ReconnectProcess
{
    std::future<void> process_future;
public:
    std::shared_ptr<ReconnectTask> task;

    ReconnectProcess()
    {
    }

    void start(std::future<void>& fut)
    {
        process_future = std::move(fut);
    }

    std::shared_ptr<ReconnectTask> make_task()
    {
        task = std::make_shared<ReconnectTask>();
        return task;
    }
    
    ReconnectTaskState wait()
    {
        auto fut = task->get_future();
        ReconnectTaskState result = fut.get();
        reset_task();
        return result;
    }

    void reset_task()
    {
        if (task)
            task.reset();
    }

    void cancel()
    {
        if (task)
            task->cancel();
        if (process_future.valid())
            process_future.wait();
    }
};