#set(CMAKE_CXX_FLAGS "-std=c++11 -g")

set(INJECTOR_SRCS 
    injector.cpp)
set(SNIFFEX_SRCS
    sniffex.cpp)
add_executable(injector2 ${INJECTOR_SRCS})
add_executable(sniffex ${SNIFFEX_SRCS})

#message("LINK_SRCS: ${LINK_SRCS}")
#message("NEIGHBOR_SRCS: ${NEIGHBOR_SRCS}")

target_link_libraries(injector2 network)
target_link_libraries(sniffex pcap)
