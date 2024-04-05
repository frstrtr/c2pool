#pragma once
#include <iostream>
#include <thread>
#include <future>
#include <mutex>
#include <list>
#include <memory>
#include <cassert>

#include "workflow_task.h"

class WorkflowThread
{
    using finish_handler = std::function<void()>;

private:
    std::future<void> workflow_future;
    std::mutex mutex;

    std::list<std::shared_ptr<WorkflowTask>> tasks;
    std::shared_ptr<WorkflowTask> current_task;
    finish_handler finish;

private:
    void _start()
    {
        std::unique_lock lk(mutex);
        while (!tasks.empty())
        {
            current_task = tasks.front();
            tasks.pop_front();
            
            lk.unlock();
            auto result = current_task->invoke();
            lk.lock();

            current_task.reset();

            switch (result)
            {
            case WorkflowTaskState::ready:
                continue;
            case WorkflowTaskState::cancel:
                break;
            default:
                assert(false);
            }
        }
    }

public:

    WorkflowThread(finish_handler&& finish_)
        : finish(std::move(finish_))
    {
        
    }

    void start()
    {
        std::lock_guard lk(mutex);
        workflow_future = std::async(std::launch::async, &WorkflowThread::_start, this);
    }

    void cancel()
    {
        {
            std::lock_guard lk(mutex);
        
            if (current_task)
                current_task->cancel();
            tasks.clear();
        }
        workflow_future.wait();
    }

    void add_tasks(std::list<std::shared_ptr<WorkflowTask>> new_tasks)
    {
        std::lock_guard<std::mutex> lock(mutex);
        tasks.splice(tasks.end(), new_tasks);
    }
};