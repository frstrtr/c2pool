# C2Pool Enhanced - Developer Guide

## Modular Architecture Overview

The C2Pool codebase has been refactored into a modular architecture with clearly separated components. This guide explains how to work with the new structure.

## Component Structure

```
src/c2pool/
├── hashrate/               # Hashrate tracking and statistics
│   ├── tracker.hpp         # HashrateTracker class definition
│   └── tracker.cpp         # Implementation with time-based windows
├── difficulty/             # Automatic difficulty adjustment
│   ├── adjustment_engine.hpp  # DifficultyAdjustmentEngine class
│   └── adjustment_engine.cpp  # VARDIFF implementation
├── storage/                # Persistent storage management
│   ├── sharechain_storage.hpp # SharechainStorage class
│   └── sharechain_storage.cpp # LevelDB-based persistence
├── bridge/                 # Legacy compatibility layer
│   ├── legacy_tracker_bridge.hpp # LegacyShareTrackerBridge class  
│   └── legacy_tracker_bridge.cpp # Bridge to legacy trackers
├── node/                   # Enhanced node implementation
│   ├── enhanced_node.hpp   # EnhancedC2PoolNode class
│   └── enhanced_node.cpp   # Main node orchestration
├── c2pool_refactored.cpp   # New modular main entry point
├── c2pool.cpp              # Original monolithic file (preserved)
└── CMakeLists.txt          # Build configuration
```

## Adding New Features

### 1. Creating a New Component

To add a new component (e.g., `analytics`):

1. **Create directory structure**:
   ```bash
   mkdir src/c2pool/analytics
   ```

2. **Create header file** (`analytics/analytics_engine.hpp`):
   ```cpp
   #pragma once
   #include <memory>
   
   namespace c2pool {
   namespace analytics {
   
   class AnalyticsEngine {
   public:
       AnalyticsEngine();
       void process_data(const Data& data);
       std::string get_report() const;
   private:
       // Implementation details
   };
   
   } // namespace analytics
   } // namespace c2pool
   ```

3. **Create implementation** (`analytics/analytics_engine.cpp`):
   ```cpp
   #include "analytics_engine.hpp"
   #include <core/log.hpp>
   
   namespace c2pool {
   namespace analytics {
   
   AnalyticsEngine::AnalyticsEngine() {
       LOG_INFO << "Analytics engine initialized";
   }
   
   void AnalyticsEngine::process_data(const Data& data) {
       // Process analytics data
   }
   
   } // namespace analytics
   } // namespace c2pool
   ```

4. **Update CMakeLists.txt**:
   ```cmake
   # Analytics Engine Library
   add_library(c2pool_analytics
       analytics/analytics_engine.cpp
   )
   target_include_directories(c2pool_analytics PUBLIC .)
   target_link_libraries(c2pool_analytics 
       core
       nlohmann_json::nlohmann_json
   )
   ```

5. **Integrate with enhanced node** (`node/enhanced_node.hpp`):
   ```cpp
   #include <c2pool/analytics/analytics_engine.hpp>
   
   class EnhancedC2PoolNode {
   private:
       std::unique_ptr<analytics::AnalyticsEngine> m_analytics;
   };
   ```

### 2. Extending Existing Components

#### Adding Methods to HashrateTracker

```cpp
// In hashrate/tracker.hpp
class HashrateTracker {
public:
    // Existing methods...
    
    // New method
    double get_hashrate_variance() const;
    std::vector<double> get_hourly_averages() const;
};

// In hashrate/tracker.cpp
double HashrateTracker::get_hashrate_variance() const {
    // Implementation
}
```

#### Extending DifficultyAdjustmentEngine

```cpp
// In difficulty/adjustment_engine.hpp
class DifficultyAdjustmentEngine {
public:
    // Existing methods...
    
    // New configuration methods
    void set_retarget_window(std::chrono::seconds window);
    void set_max_adjustment_factor(double factor);
};
```

## Testing Components

### Unit Testing

Create tests for individual components:

```cpp
// test/test_hashrate_tracker.cpp
#include <gtest/gtest.h>
#include <c2pool/hashrate/tracker.hpp>

TEST(HashrateTrackerTest, BasicFunctionality) {
    c2pool::hashrate::HashrateTracker tracker;
    
    // Test hashrate calculation
    tracker.record_share("hash1", 1000, std::chrono::system_clock::now());
    double hashrate = tracker.get_current_hashrate();
    
    EXPECT_GT(hashrate, 0.0);
}
```

### Integration Testing

Test component interactions:

```cpp
// test/test_integration.cpp
TEST(IntegrationTest, NodeWithAllComponents) {
    boost::asio::io_context ioc;
    ltc::Config config("ltc");
    
    c2pool::node::EnhancedC2PoolNode node(&ioc, &config);
    
    // Test that all components are initialized
    EXPECT_TRUE(node.is_initialized());
}
```

## Build System Integration

### Adding Dependencies

To add a new external dependency:

1. **Update CMakeLists.txt** (root):
   ```cmake
   find_package(NewLibrary REQUIRED)
   ```

2. **Link in component**:
   ```cmake
   target_link_libraries(c2pool_new_component
       NewLibrary::NewLibrary
       core
   )
   ```

### Creating Component Libraries

Each component should be a separate library:

```cmake
# Component library
add_library(c2pool_component_name
    component/file1.cpp
    component/file2.cpp
)

# Public headers
target_include_directories(c2pool_component_name PUBLIC .)

# Dependencies
target_link_libraries(c2pool_component_name 
    core
    btclibs
    dependency1
    dependency2
)
```

## Configuration Management

### Adding Configuration Options

1. **Extend C2PoolConfig**:
   ```cpp
   // In c2pool_refactored.cpp
   struct C2PoolConfig {
       bool m_testnet = false;
       uint16_t m_port = 9333;
       
       // New options
       bool m_analytics_enabled = true;
       std::string m_analytics_output_dir = "./analytics";
   };
   ```

2. **Add command line parsing**:
   ```cpp
   else if (arg == "--analytics-dir" && i + 1 < argc) {
       config->m_analytics_output_dir = argv[++i];
   }
   ```

## Debugging and Logging

### Adding Logging

Use the centralized logging system:

```cpp
#include <core/log.hpp>

// Different log levels
LOG_DEBUG << "Detailed debugging information";
LOG_INFO << "General information";
LOG_WARNING << "Warning message";
LOG_ERROR << "Error occurred: " << error_details;
```

### Component-specific Logging

Create component-specific log channels:

```cpp
// In component implementation
#define LOG_COMPONENT LOG_INFO << "[ComponentName] "

LOG_COMPONENT << "Component-specific message";
```

## Performance Considerations

### Memory Management

- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Avoid raw pointers except for non-owning references
- Use RAII for resource management

### Threading

- Components should be thread-safe where needed
- Use `boost::asio` for async operations
- Protect shared data with mutexes

### Efficiency

- Pre-allocate containers when size is known
- Use move semantics for large objects
- Consider memory pools for frequent allocations

## Best Practices

### Code Organization

1. **One class per file** (with matching names)
2. **Namespace everything** using `c2pool::component::`
3. **Clear separation** between interface and implementation
4. **Minimal dependencies** between components

### Error Handling

```cpp
// Use exceptions for exceptional cases
if (critical_error) {
    throw std::runtime_error("Critical error occurred");
}

// Use return codes for expected failures
enum class Result { Success, NotFound, InvalidInput };
Result process_data(const Data& data);
```

### Documentation

- Document all public APIs
- Include usage examples
- Explain complex algorithms
- Keep documentation up-to-date

## Example: Complete Component Addition

Here's a complete example of adding a statistics component:

```cpp
// 1. statistics/stats_collector.hpp
#pragma once
#include <string>
#include <map>
#include <mutex>

namespace c2pool {
namespace statistics {

class StatsCollector {
public:
    StatsCollector();
    
    void increment_counter(const std::string& name);
    void set_gauge(const std::string& name, double value);
    std::string get_json_report() const;
    
private:
    mutable std::mutex m_mutex;
    std::map<std::string, uint64_t> m_counters;
    std::map<std::string, double> m_gauges;
};

} // namespace statistics
} // namespace c2pool

// 2. statistics/stats_collector.cpp
#include "stats_collector.hpp"
#include <core/log.hpp>
#include <nlohmann/json.hpp>

namespace c2pool {
namespace statistics {

StatsCollector::StatsCollector() {
    LOG_INFO << "Statistics collector initialized";
}

void StatsCollector::increment_counter(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_counters[name]++;
}

std::string StatsCollector::get_json_report() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    nlohmann::json report;
    report["counters"] = m_counters;
    report["gauges"] = m_gauges;
    
    return report.dump(2);
}

} // namespace statistics
} // namespace c2pool

// 3. Update CMakeLists.txt
add_library(c2pool_statistics
    statistics/stats_collector.cpp
)
target_include_directories(c2pool_statistics PUBLIC .)
target_link_libraries(c2pool_statistics 
    core
    nlohmann_json::nlohmann_json
)

// 4. Integrate in enhanced_node.hpp
#include <c2pool/statistics/stats_collector.hpp>

class EnhancedC2PoolNode {
private:
    std::unique_ptr<statistics::StatsCollector> m_stats;
};
```

This modular approach ensures maintainable, testable, and extensible code.
