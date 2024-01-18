#pragma once
#include <map>
#include <set>

#include <libdevcore/logger.h>

enum net_state
{
    disconnected,
    connected
};

class SupervisorElement
{
    net_state state;
public:
    const uint8_t layer;

    SupervisorElement(uint8_t l) : layer(l) {}

    net_state get_state() const
    {
        return state;
    }
    
public:
    virtual void start() = 0;
    virtual void stop() = 0;
    // virtual void restart() = 0;
    virtual void reconnect() = 0;
};

class NetSupervisor
{
protected:
    std::map<uint8_t, std::set<SupervisorElement*>> layers; // Network layers [0; 2^8]
public:
    void add(SupervisorElement* element)
    {
        if (!layers[element->layer].count(element))
            layers[element->layer].insert(element);
        else
            LOG_WARNING << "Element is already in " << element->layer << " layer.";
    }

    void restart(SupervisorElement* element)
    {
        // Stop all supervisor elements upper
        auto layer_it = layers.find(element->layer);
        while (layer_it != layers.end())
        {
            for (auto& el : layer_it->second)
                el->stop();
            layer_it++;
        }

        
    }
};