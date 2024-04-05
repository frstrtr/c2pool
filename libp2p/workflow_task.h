#pragma once

#include <set>
#include <mutex>
#include <thread>
#include <memory>
#include <numeric>
#include <functional>
#include <condition_variable>

enum WorkflowTaskState
{
    none = 0,
    cancel = -1,
    ready = 1
};

enum TaskType
{
    STOP_TASK,
    RUN_TASK
};

class WorkflowTask : public std::enable_shared_from_this<WorkflowTask>
{
protected:
    std::mutex mutex;
    std::condition_variable cv;

    WorkflowTaskState state {WorkflowTaskState::none};

public:
    const TaskType type;

    WorkflowTask(TaskType type_) 
        : type(type_)
    {
    }

    void ready()
    {
        {
            std::lock_guard lk(mutex);
            if (state != none)
                return;

            state = WorkflowTaskState::ready;
        }
        cv.notify_all();
    }

    void cancel()
    {
        {
            std::lock_guard lk(mutex);
            if (state != none)
                return;

            state = WorkflowTaskState::cancel;
        }
        cv.notify_all();
    }

    virtual WorkflowTaskState invoke() = 0;
};

class RunWorkflowTask : public WorkflowTask
{
    std::function<void(std::shared_ptr<WorkflowTask>)> func;

    RunWorkflowTask(auto&& func_) : WorkflowTask(TaskType::RUN_TASK), func(std::move(func_)) { }

    WorkflowTaskState invoke() override
    {
        std::unique_lock lk(mutex);
        if (state != none)
            return state;

        func(shared_from_this());
        cv.wait(lk, [&]{ return state != WorkflowTaskState::none; });
        // when state updated -- can't be changed.
        return state;
    }
};

class StopWorkflowTask : public WorkflowTask
{
    StopWorkflowTask() : WorkflowTask(TaskType::STOP_TASK) { }

    WorkflowTaskState invoke() override
    {
        std::unique_lock lk(mutex);
        if (state != none)
            return state;

        cv.wait(lk, [&]{ return state != WorkflowTaskState::none; });
        // when state updated -- can't be changed.
        return state;
    }
};

// class WorkflowTask
// {
// protected:
//     std::promise<WorkflowTaskState> state;
//     bool alive;
//     mutable std::mutex mutex;
// public:
//     const TaskType type;

//     WorkflowTask(TaskType type_) : type(type_), alive(true)
//     {
//     }

//     virtual void ready(uint64_t process_id) = 0;

//     void cancel()
//     {
//         std::lock_guard lock(mutex);
//         if (alive)
//         {
//             state.set_value(WorkflowTaskState::cancel);
//             alive = false;
//         }
//     }

//     std::future<WorkflowTaskState> get_future()
//     {
//         std::lock_guard lock(mutex);
//         return state.get_future();
//     }

//     bool is_alive() const
//     {
//         std::lock_guard lock(mutex);
//         return alive;
//     }
// };

// class RunWorkflowTask : public WorkflowTask
// {
// public:
//     RunWorkflowTask() : WorkflowTask(RUN_TASK)
//     {
//     }

//     void ready(uint64_t process_id) override
//     {
//         std::lock_guard lock(mutex);
//         if (!alive)
//             return;
        
//         state.set_value(WorkflowTaskState::ready);
//         alive = false;
//     }
// };

// class StopWorkflowTask : public WorkflowTask
// {
//     std::set<uint64_t> process_ids;

// public:
//     StopWorkflowTask() : WorkflowTask(STOP_TASK)
//     {
//     }

//     void ready(uint64_t process_id) override
//     {
//         std::lock_guard lock(mutex);
//         if (!alive)
//             return;

//         erase_process(process_id);

//         if (process_ids.empty())
//         {
//             state.set_value(WorkflowTaskState::ready);
//             alive = false;
//         }
//     }

//     void add_process(uint64_t id)
//     {
//         std::lock_guard lock(mutex);
//         if (process_ids.contains(id))
//             return;        
        
//         process_ids.insert(id);
//     }

// private:
//     // non-thread safe, use only from ready!
//     void erase_process(uint64_t id)
//     {
//         if(!process_ids.contains(id))
//         {
//             std::cout << "erase_process trying erase invalid id: " << id << std::endl;
//             return;
//         }

//         process_ids.erase(id);
//     }
// };
