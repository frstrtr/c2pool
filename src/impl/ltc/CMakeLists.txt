add_library(pool_ltc 
    messages.hpp 
    protocol.hpp 
    types.hpp 
    transaction.cpp transaction.hpp 
)
target_link_libraries(pool_ltc core pool sharechain)