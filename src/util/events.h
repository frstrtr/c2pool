#ifndef EVENTS_H
#define EVENTS_H

#include <boost/signals2.hpp>

namespace c2pool::util::events
{
    template <typename... Args>
    class Event
    {
        boost::signals2::signal<void(Args...)> sig;

    public:
        Event() {}

        template <typename _Func, typename... _BoundArgs>
        void subscribe(_Func &&__f, _BoundArgs &&... __args)
        {
            sig.connect(std::bind(__f, __args...));
        }

        void unsubscribe()
        {
            //TODO
        }

        void happened(Args... args) const { sig(args...); }
    };
} // namespace c2pool::util::events

#endif