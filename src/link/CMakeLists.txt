set(LINK_SRCS 
    ${PROJECT_SOURCE_DIR}/link/Link.cpp
    ${PROJECT_SOURCE_DIR}/link/Hardware.cpp
    CACHE INTERNAL "Link srcs")
#add_library(hardware MODULE Hardware.cpp)
#add_library(link SHARED
    #${LINK_SRCS}
    #${NEIGHBOR_SRCS})

##target_link_libraries(hardware util)
#target_link_libraries(link util pthread)

