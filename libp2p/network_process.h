#pragma once
#include <future>
#include <atomic>
#include <tuple>
#include <mutex>

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
    ReconnectTask()
    {
        alive.store(true);
    }

    void ready()
    {
        if (alive.load())
        {
            state.set_value(ReconnectTaskState::ready);
            alive.store(false);
        }
    }

    void cancel()
    {
        if (alive.load())
        {
            state.set_value(ReconnectTaskState::cancel);
            alive.store(false);
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

    std::mutex mutex;
    std::atomic_bool canceled{false};
public:
    std::shared_ptr<ReconnectTask> task;

    ReconnectProcess()
    {
    }

    void start(std::future<void>&& fut)
    {
        process_future = std::move(fut);
    }

    std::shared_ptr<ReconnectTask> make_task()
    {
        std::lock_guard<std::mutex> lock(mutex);
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
        canceled.store(true);
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (task)
                task->cancel();
        }
        if (process_future.valid())
            process_future.wait();
    }

    bool is_canceled()
    {
        return canceled.load();
    }
};