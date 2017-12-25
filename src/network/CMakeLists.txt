set(NETWORK_SRCS 
    ${PROJECT_SOURCE_DIR}/network/Network.cpp 
    ${PROJECT_SOURCE_DIR}/network/Neighbor.cpp 
    ${PROJECT_SOURCE_DIR}/network/ARP.cpp 
    CACHE INTERNAL "Network srcs")
#set(NEIGHBOR_SRCS Neighbor.cpp ARP.cpp)

add_library(network SHARED
    ${LINK_SRCS}
    ${NETWORK_SRCS}
    ${TRANSPORT_SRCS})

target_link_libraries(network pcap util pthread)
