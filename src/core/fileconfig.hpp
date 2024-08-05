#pragma once

#include <string>
#include <fstream>

#include <core/filesystem.hpp>
#include <core/log.hpp>

namespace core
{

#define PARSE_CONFIG(node, field, type) \
    m_##field = node[#field].as<type>()

#define PARSE_OPTIONAL_CONFIG(node, field, type)  \
    if (node[#field])      \
        PARSE_CONFIG(node, field, type)

class Fileconfig
{
protected:
    std::filesystem::path m_filepath;
    
    virtual std::ofstream& get_default(std::ofstream& file) = 0;
    virtual void load() = 0;
    
    inline void init()
    {
        // check for exist path + make default
        if (!std::filesystem::exists(m_filepath))
        {
            std::filesystem::create_directory(m_filepath.parent_path());
        
            std::ofstream file(m_filepath);
            get_default(file);
            file.close();
            LOG_WARNING << "Config (" << m_filepath << "): not found, created default.";
        }
        load();
    }

public:
    Fileconfig(const std::filesystem::path& filepath) : m_filepath(filepath)
    {
    }
    
    template <typename CONFIG_TYPE, typename... Args>
    static CONFIG_TYPE* load_file(Args... args)
    {
        static_assert(std::is_base_of<Fileconfig, CONFIG_TYPE>(), "CONFIG_TYPE in fileconfig::load_file not based from fileconfig");
        
        Fileconfig* config = new CONFIG_TYPE(args...);
        // load from file
        config->init();
        
        return static_cast<CONFIG_TYPE*>(config);
    }
};
    
} // namespace core
