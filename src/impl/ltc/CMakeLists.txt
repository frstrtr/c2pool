add_library(pool_ltc 
    protocol.hpp 
    types.hpp 
    transaction.cpp transaction.hpp
    share.hpp
)
target_link_libraries(pool_ltc core pool sharechain)