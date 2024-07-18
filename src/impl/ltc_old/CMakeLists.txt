add_library(pool_ltc_old 
    protocol.hpp 
    types.hpp 
    transaction.cpp transaction.hpp
    share.hpp
)
target_link_libraries(pool_ltc_old core pool sharechain)