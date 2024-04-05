#pragma once

#include <iostream> // remove

#include <atomic>
#include <memory>
#include <functional>
#include <mutex>

class WorkflowNodeProcess
{
    class process_data
    {
    public:
        using finish_handle_type = std::function<void()>;

        const uint64_t id;
        bool alive {true};
        finish_handle_type finish_handle;
        std::mutex& mutex;

        process_data(std::mutex& node_mutex, finish_handle_type handle)
            : id(generate_id()), finish_handle(std::move(handle)), mutex(node_mutex)
        {
            
        }

        ~process_data()
        {
            finish_handle();
        }

    private:
        static uint64_t generate_id()
        {
            static std::atomic_int64_t id_{0};

            return ++id_;
        }
    };
    
private:
    std::shared_ptr<process_data> process;

    WorkflowNodeProcess(std::shared_ptr<process_data> process_)
        : process(std::move(process_))
    {

    }
    
public:
    WorkflowNodeProcess()
    {
    }

    void stop()
    {
        if (process)
        {
            process->alive = false;
        }
    }

    void reset()
    {
        process.reset();
    }

    bool is_alive() const
    {
        return process && process->alive;
    }

    uint64_t get_id() const
    {
        if (!process)
        {
            std::cout << "Process is null when try get_id()!" << std::endl;
        }
        return process->id;
    }

    int count() const
    {
        return process.use_count();
    }

    std::unique_lock<std::mutex> lock() const
    {
        if (process)
            return std::unique_lock(process->mutex);
        else
            return std::unique_lock<std::mutex>();
    }

    void unlock(std::unique_lock<std::mutex>& m) const
    {
        m.unlock();
    }

    operator bool() const
    {
        return is_alive();
    }
    
    static WorkflowNodeProcess make(process_data::finish_handle_type&& finish_handle, std::mutex& mutex)
    {
        return WorkflowNodeProcess(std::make_shared<process_data>(mutex, finish_handle));
    }
};

// macros for fast copy process
#define PROCESS_DUPLICATE __process = get_process()

// macros for start process
#define WORKFLOW_PROCESS()          \
    auto process_locker = __process.lock();  \
    if (!__process) return;

#define WORKFLOW_PROCESS_FINISH() process_locker.unlock();
